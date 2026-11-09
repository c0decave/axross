"""POP3: a dropped connection is reconnected, deletions it loses are said,
and without UIDL a message is found by its fingerprint.

Round 5 (repro_pop3_reconnect.py, repro_pop3_no_uidl_same_subject.py):

* after a network loss every call failed (``-ERR EOF``, then
  BrokenPipeError) for the rest of the session: POP3 never reconnected;
* disconnect() swallowed a failed QUIT - the DELEs sent before it were
  never committed (only QUIT commits them) and nobody was told: the user
  saw the messages deleted, the server kept them;
* on a server without UIDL two messages with the same subject were told
  apart by the subject only: after a renumbering, removing the listed
  "2_Daily report.eml" (MONDAY) deleted TUESDAY's.

Driven against a small stateful POP3 server: per-connection numbering,
DELE committed on QUIT only, UIDL optional, kill() drops every
connection.
"""

from __future__ import annotations

import socket
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import pop3_client as P  # noqa: E402
from core.mail_names import MAX_NAME_BYTES  # noqa: E402


class Pop3d:
    def __init__(self, msgs, uidl=True):
        self.msgs = list(msgs)  # [(uid, subject, body)]
        self.uidl = uidl
        self.conns: list[socket.socket] = []
        self.commands: list[str] = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def close(self):
        self.kill()
        self.sock.close()

    def _accept(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            self.conns.append(c)
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def kill(self):
        for c in self.conns:
            try:
                c.shutdown(socket.SHUT_RDWR)
                c.close()
            except OSError:
                pass
        self.conns.clear()

    @staticmethod
    def raw(m):
        return f"Subject: {m[1]}\r\nMessage-ID: <{m[0]}@x>\r\n\r\n{m[2]}\r\n".encode()

    def _serve(self, c):  # noqa: C901 - one branch per verb
        snap = list(self.msgs)
        deleted: set[int] = set()
        f = c.makefile("rb")
        try:
            c.sendall(b"+OK ready\r\n")
            for line in f:
                cmd = line.decode().strip()
                self.commands.append(cmd)
                verb, _, arg = cmd.partition(" ")
                verb = verb.upper()
                live = [(i + 1, m) for i, m in enumerate(snap) if i + 1 not in deleted]
                if verb in ("USER", "PASS", "NOOP", "RSET"):
                    if verb == "RSET":
                        deleted.clear()
                    c.sendall(b"+OK\r\n")
                elif verb == "LIST" and not arg:
                    c.sendall(b"+OK\r\n" + b"".join(
                        f"{n} {len(self.raw(m))}\r\n".encode() for n, m in live) + b".\r\n")
                elif verb == "LIST":
                    n = int(arg)
                    if 1 <= n <= len(snap) and n not in deleted:
                        c.sendall(f"+OK {n} {len(self.raw(snap[n - 1]))}\r\n".encode())
                    else:
                        c.sendall(b"-ERR no such message\r\n")
                elif verb == "UIDL" and self.uidl:
                    c.sendall(b"+OK\r\n" + b"".join(
                        f"{n} {m[0]}\r\n".encode() for n, m in live) + b".\r\n")
                elif verb in ("TOP", "RETR"):
                    n = int(arg.split()[0])
                    if not (1 <= n <= len(snap)) or n in deleted:
                        c.sendall(b"-ERR no such message\r\n")
                        continue
                    body = self.raw(snap[n - 1])
                    if verb == "TOP":
                        body = body.split(b"\r\n\r\n")[0] + b"\r\n"
                    c.sendall(b"+OK\r\n" + body + b".\r\n")
                elif verb == "DELE":
                    n = int(arg)
                    if not (1 <= n <= len(snap)) or n in deleted:
                        c.sendall(b"-ERR no such message\r\n")
                    else:
                        deleted.add(n)
                        c.sendall(b"+OK\r\n")
                elif verb == "QUIT":
                    gone = {snap[n - 1][0] for n in deleted}
                    self.msgs = [m for m in self.msgs if m[0] not in gone]
                    c.sendall(b"+OK bye\r\n")
                    c.close()
                    return
                else:
                    c.sendall(b"-ERR\r\n")
        except OSError:
            return


@pytest.fixture
def make_server():
    servers: list[Pop3d] = []

    def make(msgs, uidl=True):
        srv = Pop3d(msgs, uidl=uidl)
        servers.append(srv)
        return srv

    yield make
    for srv in servers:
        srv.close()


def _session(srv):
    return P.Pop3Session("127.0.0.1", srv.port, "u", "p", use_ssl=False)


def test_happy_a_dropped_connection_is_reconnected(make_server):
    srv = make_server([("u1", "hello", "a"), ("u2", "salary", "b"), ("u3", "world", "c")])
    s = _session(srv)
    try:
        assert [i.name for i in s.list_dir("/")] == ["1_hello.eml", "2_salary.eml", "3_world.eml"]
        srv.kill()  # network loss
        assert s.open_read("/1_hello.eml").read().startswith(b"Subject: hello")
        srv.kill()
        assert [i.name for i in s.list_dir("/")] == ["1_hello.eml", "2_salary.eml", "3_world.eml"]
        srv.kill()
        assert s.stat("/3_world.eml").size > 0
    finally:
        s.disconnect()


def test_sad_a_failed_quit_after_deletes_says_they_were_not_committed(make_server):
    srv = make_server([("u1", "hello", "a"), ("u2", "spam", "b")])
    s = _session(srv)
    s.list_dir("/")
    s.remove("/2_spam.eml")
    srv.kill()
    with pytest.raises(P.Pop3DeletesLost, match="1 deletion"):
        s.disconnect()
    assert [m[1] for m in srv.msgs] == ["hello", "spam"]  # what the error says
    s.disconnect()  # idempotent afterwards
    # Without deletes pending a failed QUIT has nothing to tell.
    s2 = _session(srv)
    s2.list_dir("/")
    srv.kill()
    s2.disconnect()


def test_sad_a_drop_after_deletes_is_said_and_then_reconnected(make_server):
    srv = make_server([("u1", "hello", "a"), ("u2", "spam", "b")])
    s = _session(srv)
    try:
        s.list_dir("/")
        s.remove("/2_spam.eml")
        srv.kill()
        with pytest.raises(P.Pop3DeletesLost, match="not committed"):
            s.list_dir("/")
        # The next call works on a new connection; the message is back.
        assert [i.name for i in s.list_dir("/")] == ["1_hello.eml", "2_spam.eml"]
    finally:
        s.disconnect()


def test_sad_without_uidl_the_same_subject_deletes_the_listed_message(make_server):
    srv = make_server([("u1", "other", "x"), ("u2", "Daily report", "MONDAY"),
                       ("u3", "Daily report", "TUESDAY")], uidl=False)
    s = _session(srv)
    names = [i.name for i in s.list_dir("/")]
    assert names == ["1_other.eml", "2_Daily report.eml", "3_Daily report.eml"]
    srv.msgs = srv.msgs[1:]  # another client fetched and deleted message 1
    srv.kill()
    s._pop = None  # the next call reconnects: MONDAY is number 1 now
    s.remove("/2_Daily report.eml")
    s.disconnect()
    assert [(m[1], m[2]) for m in srv.msgs] == [("Daily report", "TUESDAY")]


def test_edge_without_uidl_identical_messages_are_not_deleted_after_a_reconnect(make_server):
    twin = ("u2", "Daily report", "same")
    srv = make_server([("u1", "other", "x"), twin, twin], uidl=False)
    s = _session(srv)
    s.list_dir("/")
    srv.kill()
    s._pop = None
    with pytest.raises(OSError, match="cannot tell"):
        s.remove("/2_Daily report.eml")
    s.disconnect()
    assert len(srv.msgs) == 3
    assert not any(c.startswith("DELE") for c in srv.commands)


def test_edge_a_long_subject_is_capped_in_bytes_and_its_old_name_still_works(make_server):
    subject = "請求書" * 40  # 120 characters, 360 bytes
    srv = make_server([("u1", subject, "body")])
    s = _session(srv)
    try:
        (item,) = s.list_dir("/")
        assert len(item.name.encode()) <= MAX_NAME_BYTES
        assert item.name.startswith("1_請求書") and item.name.endswith(".eml")
        assert s.open_read("/" + item.name).read().endswith(b"body\r\n")
        # The name the message had before (120 characters), as a bookmark
        # or a mail dock's seen-state keeps it.
        s._pop.close()
        s._pop = None
        assert s.open_read(f"/1_{subject}.eml").read().endswith(b"body\r\n")
    finally:
        s.disconnect()
