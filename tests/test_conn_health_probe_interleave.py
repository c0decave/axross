"""The conn_health probe never interleaves with a session's own commands.

``ConnectionManager`` enrolls every session in ``core.conn_health``; its
poll thread sends NOOP every 30 s on the session's ftplib / imaplib /
poplib handle (``_probe_ftp`` / ``_probe_imap`` / ``_probe_pop3``) while
transfer and listing workers use the same handle. FtpSession, ImapSession
and Pop3Session had no lock. Those libraries pair replies with the one
outstanding command and read the socket without any locking of their
own, so a NOOP sent while a RETR / FETCH was in flight could take the
transfer's completion reply as its own (FTP: the probe got "226", the
transfer was left the NOOP's "200"), read part of a message body, or leave
a worker waiting for a reply that was already consumed.

Driven end to end against fake servers on 127.0.0.1. Each records the
order in which commands ARRIVE and holds its answer to the worker's
transfer command until another command arrives (or 1 s passes). A probe
that respects the session's lock never sends anything in that window.
"""

from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.conn_health import HealthManager, HealthRecord  # noqa: E402


class _SeqServer:
    """One connection; a reader thread logs arrivals, the main loop answers
    in order. ``answer(line, server)`` returns the bytes to send."""

    def __init__(self, greeting: bytes, answer, slow: str) -> None:
        self._srv = socket.create_server(("127.0.0.1", 0))
        self.port = self._srv.getsockname()[1]
        self.arrivals: list[str] = []
        self.greeting, self.answer, self.slow = greeting, answer, slow
        self.later = threading.Event()
        self.conn: socket.socket | None = None
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        conn, _ = self._srv.accept()
        self.conn = conn
        queue: list[str] = []
        cond = threading.Condition()

        def reader() -> None:
            for raw in conn.makefile("rb"):
                line = raw.decode().rstrip("\r\n")
                with cond:
                    if any(self.slow in a for a in self.arrivals) and self.slow not in line:
                        self.later.set()
                    self.arrivals.append(line)
                    queue.append(line)
                    cond.notify_all()
            with cond:
                queue.append("")
                cond.notify_all()

        threading.Thread(target=reader, daemon=True).start()
        conn.sendall(self.greeting)
        while True:
            with cond:
                while not queue:
                    cond.wait()
                line = queue.pop(0)
            if not line:
                break
            slow = self.slow in line
            if slow:
                # Hold the reply until something else arrives (a probe
                # that does not wait for the session) or 1 s passes.
                self.later.wait(1.0)
                time.sleep(0.3)
            out = self.answer(line, self)
            if slow:
                with cond:
                    self.arrivals.append(f"{self.slow}-done")
            if out:
                conn.sendall(out)
        conn.close()

    def interleaved(self) -> list[str]:
        """Commands that arrived while the slow command was in flight."""
        start = next(i for i, a in enumerate(self.arrivals) if self.slow in a)
        end = self.arrivals.index(f"{self.slow}-done")
        return self.arrivals[start + 1 : end]


def _probe_while(work, session, protocol: str):
    """Run ``work`` in a thread, probe once it is in flight, join both."""
    result: dict = {}

    def run():
        try:
            result["value"] = work()
        except Exception as exc:  # noqa: BLE001
            result["error"] = exc

    t = threading.Thread(target=run)
    t.start()
    time.sleep(0.2)  # the worker's transfer command is on the wire
    mgr = HealthManager(interval_s=3600)
    record = HealthRecord(profile_key="k", protocol=protocol, label="k")
    mgr._records["k"] = record
    mgr._sessions["k"] = session
    mgr.probe_now("k")
    t.join(10)
    return result, record


# --------------------------------------------------------------------------
# FTP
# --------------------------------------------------------------------------


def _ftp_answer(line: str, srv: _SeqServer) -> bytes:
    verb = line.split(" ", 1)[0]
    if verb in ("USER", "PASS"):
        return b"230 ok\r\n"
    if verb == "TYPE":
        return b"200 type-set\r\n"
    if verb == "PASV":
        srv.data_l = socket.create_server(("127.0.0.1", 0))
        p = srv.data_l.getsockname()[1]
        return f"227 Entering Passive Mode (127,0,0,1,{p >> 8},{p & 255})\r\n".encode()
    if verb == "RETR":
        srv.conn.sendall(b"150 opening\r\n")
        d, _ = srv.data_l.accept()
        d.sendall(b"payload")
        d.close()
        srv.data_l.close()
        return b"226 transfer-complete\r\n"
    if verb == "NOOP":
        return b"200 noop-reply\r\n"
    return b"502 no\r\n"


def _ftp_session(port: int):
    from ftplib import FTP

    from core import ftp_client as FC

    ftp = FTP()
    ftp.connect("127.0.0.1", port, timeout=5)
    ftp.login("u", "p")
    s = FC.FtpSession.__new__(FC.FtpSession)
    s._ftp = ftp
    s._host, s._username, s._has_mlsd = "127.0.0.1", "u", False
    s._verified_at = time.monotonic()
    return s


def test_sad_ftp_probe_does_not_interleave_with_a_transfer():
    srv = _SeqServer(b"220 ready\r\n", _ftp_answer, "RETR")
    s = _ftp_session(srv.port)
    replies: list[tuple[str, str]] = []
    original = s._ftp.voidcmd

    def voidcmd(cmd):
        reply = original(cmd)
        replies.append((cmd, reply))
        return reply

    s._ftp.voidcmd = voidcmd
    result, record = _probe_while(lambda: s.open_read("/f").read(), s, "ftp")
    assert result.get("value") == b"payload", result
    assert srv.interleaved() == [], srv.arrivals
    # If the probe ran at all, it got its own reply, not the transfer's.
    assert all(r == "200 noop-reply" for c, r in replies if c == "NOOP"), replies
    assert not record.stale


def test_happy_idle_ftp_session_is_probed_normally():
    srv = _SeqServer(b"220 ready\r\n", _ftp_answer, "RETR")
    s = _ftp_session(srv.port)
    mgr = HealthManager(interval_s=3600)
    mgr.enroll("k", s, protocol="ftp")
    try:
        record = mgr.probe_now("k")
    finally:
        mgr.stop()
    assert record.healthy, record
    assert srv.arrivals[-1] == "NOOP"


# --------------------------------------------------------------------------
# POP3
# --------------------------------------------------------------------------


def _pop3_answer(line: str, srv: _SeqServer) -> bytes:
    verb = line.split(" ", 1)[0].upper()
    if verb == "RETR":
        return b"+OK message follows\r\nSubject: hi\r\n\r\nbody\r\n.\r\n"
    return b"+OK\r\n"


def test_sad_pop3_probe_does_not_interleave_with_a_retr():
    import poplib

    from core import pop3_client as PC

    srv = _SeqServer(b"+OK ready\r\n", _pop3_answer, "RETR")
    s = PC.Pop3Session.__new__(PC.Pop3Session)
    s._pop = poplib.POP3("127.0.0.1", srv.port, timeout=5)
    s._host, s._username = "127.0.0.1", "u"
    result, record = _probe_while(lambda: s.open_read("/1_x.eml").read(), s, "pop3")
    assert b"body" in result.get("value", b""), result
    assert srv.interleaved() == [], srv.arrivals
    assert not record.stale


# --------------------------------------------------------------------------
# IMAP
# --------------------------------------------------------------------------

_RAW = b"Subject: hi\r\n\r\nbody\r\n"


def _imap_answer(line: str, srv: _SeqServer) -> bytes:
    tag, _, rest = line.partition(" ")
    cmd = rest.split(" ", 1)[0].upper()
    if cmd == "CAPABILITY":
        return f"* CAPABILITY IMAP4rev1\r\n{tag} OK done\r\n".encode()
    if cmd == "LIST":
        return f'* LIST (\\HasNoChildren) "/" "INBOX"\r\n{tag} OK done\r\n'.encode()
    if cmd in ("SELECT", "EXAMINE"):
        return f"* 1 EXISTS\r\n{tag} OK [READ-ONLY] done\r\n".encode()
    if cmd == "UID":
        return (
            f"* 1 FETCH (UID 7 RFC822 {{{len(_RAW)}}}\r\n".encode()
            + _RAW
            + f")\r\n{tag} OK done\r\n".encode()
        )
    return f"{tag} OK done\r\n".encode()


def test_edge_imap_probe_does_not_interleave_with_a_fetch():
    import imaplib

    from core.imap_client import ImapSession

    srv = _SeqServer(b"* OK IMAP4rev1 ready\r\n", _imap_answer, "UID FETCH")
    s = ImapSession.__new__(ImapSession)
    s._imap = imaplib.IMAP4("127.0.0.1", srv.port, timeout=5)
    s._imap.login("u", "p")
    s._host, s._username = "127.0.0.1", "u"
    s._hierarchy_sep = "/"
    s._selected_mailbox = None
    s._selected_readonly = True
    s._mailbox_cache = {"INBOX"}
    result, record = _probe_while(lambda: s.open_read("/INBOX/7.eml").read(), s, "imap")
    assert result.get("value") == _RAW, result
    assert srv.interleaved() == [], srv.arrivals
    assert not record.stale


def test_edge_connected_answers_at_once_while_a_transfer_runs():
    # ConnectionManager asks session.connected (possibly from the GUI
    # thread): it must neither interleave a NOOP nor wait out the transfer.
    srv = _SeqServer(b"220 ready\r\n", _ftp_answer, "RETR")
    s = _ftp_session(srv.port)
    t = threading.Thread(target=lambda: s.open_read("/f").read())
    t.start()
    time.sleep(0.2)
    t0 = time.monotonic()
    assert s.connected is True
    assert time.monotonic() - t0 < 0.5
    t.join(10)
    assert srv.interleaved() == [], srv.arrivals
