"""IMAP: a hostile server cannot fill the memory any more.

imaplib caps nothing but a single line (1,000,000 bytes): a literal is
read as long as the server announces, and untagged lines are collected
until the tagged one comes. A server that announced a huge literal and
then really sent gigabytes - or sent untagged lines for ever - was read
into memory through list_dir / open_read / the attachment listing.

Every command now has a byte budget, counted in read() and readline():
the open size limit (core/open_limits) for a message FETCH,
``_ANSWER_CAP`` for everything else. Over budget the connection is
dropped (the rest of the answer is still on the wire) and an OSError
naming the size is raised; the next call connects anew.

Driven against a scripted IMAP server on 127.0.0.1 that streams its
answers; each hostile stream stops by itself after 64 MiB, so a broken
budget fails the test instead of hanging it.
"""

from __future__ import annotations

import errno
import io
import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz_testkit import recv_line  # noqa: E402
from mail_fuzz_servers import FakeImapServer  # noqa: E402

from core import imap_client as IC  # noqa: E402
from core import open_limits  # noqa: E402

KIB = 1024
MIB = 1024 * 1024
#: What a hostile stream sends at most before it gives up.
STREAM_STOP = 64 * MIB
CAP = 256 * KIB
BODY_LIMIT = 1 * MIB

MESSAGE = b"Subject: hi\r\n\r\nbody text\r\n"


@pytest.fixture(autouse=True)
def _small_budgets(monkeypatch):
    monkeypatch.setattr(IC, "IMAP_TIMEOUT", 5.0)
    monkeypatch.setattr(IC, "_ANSWER_CAP", CAP)
    monkeypatch.setattr(IC._LiteralInSteps, "_axross_budget", CAP)
    monkeypatch.setattr(open_limits, "max_open_bytes", lambda: BODY_LIMIT)
    monkeypatch.setattr(open_limits, "describe_limit", lambda: "1 MB")


def _endless(head: bytes, unit: bytes, tag: str):
    yield head
    sent = len(head)
    while sent < STREAM_STOP:
        yield unit
        sent += len(unit)
    yield f"{tag} OK done\r\n".encode()


def _body(tag: str, body: bytes = MESSAGE):
    yield b"* 1 FETCH (UID 1 RFC822 {%d}\r\n" % len(body) + body + b")\r\n"
    yield f"{tag} OK done\r\n".encode()


class StreamingImapServer(FakeImapServer):
    """FakeImapServer whose answers to the verbs in ``streams`` come from a
    generator ``(tag) -> chunks`` (the tagged completion included); the
    client hanging up ends the stream."""

    def __init__(self, streams: dict) -> None:
        self.streams = {"BODY": _body, **streams}
        self.sent: dict[str, int] = {}
        super().__init__()

    def _handle(self, conn: socket.socket) -> None:
        conn.sendall(self.greeting)
        while True:
            raw = recv_line(conn)
            if not raw:
                return
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            self.commands.append(line)
            tag, _, rest = line.partition(" ")
            verb, _, arg = rest.partition(" ")
            verb = verb.upper()
            if verb == "UID":
                sub, _, arg = arg.partition(" ")
                verb = sub.upper()
                if verb == "FETCH" and "RFC822)" in arg:
                    verb = "BODY"
            if verb in self.streams:
                for chunk in self.streams[verb](tag):
                    conn.sendall(chunk)  # OSError when the client hung up
                    self.sent[verb] = self.sent.get(verb, 0) + len(chunk)
            else:
                conn.sendall(self.replies.get(verb, b"") + f"{tag} OK done\r\n".encode())
            if verb == "LOGOUT":
                return


def _session(srv) -> IC.ImapSession:
    return IC.ImapSession(srv.host, srv.port, "u", "p", use_ssl=False)


def _commands(srv, verb: str) -> int:
    return sum(1 for c in srv.commands if verb in c.upper())


# --- happy ----------------------------------------------------------------


def test_happy_a_message_under_the_limit_is_read_whole():
    body = MESSAGE + b"x" * (BODY_LIMIT - len(MESSAGE) - 10) + b"\r\n"
    with StreamingImapServer({"BODY": lambda tag: _body(tag, body)}) as srv:
        assert _session(srv).open_read("/INBOX/1_hi.eml").read() == body


def test_happy_answers_under_the_cap_list_as_before():
    with StreamingImapServer({}) as srv:
        s = _session(srv)
        assert [i.name for i in s.list_dir("/INBOX")] == ["1_Hello world.eml"]
        assert {i.name for i in s.list_dir("/")} >= {"INBOX"}


# --- sad: hostile servers ---------------------------------------------------


def test_sad_an_endless_message_literal_is_cut_at_the_open_limit():
    """Announces 4 GB and streams it: refused before a byte of it is read."""
    streams = {"BODY": lambda tag: _endless(b"* 1 FETCH (UID 1 RFC822 {4000000000}\r\n",
                                            b"x" * 65536, tag)}
    with StreamingImapServer(streams) as srv:
        s = _session(srv)
        with pytest.raises(OSError) as info:
            s.open_read("/INBOX/1_hi.eml")
        assert info.value.errno == errno.EFBIG
        assert "larger than 1 MB" in str(info.value) and "Open Size Limit" in str(info.value)
        assert s._imap is None  # dropped: the rest of the literal is still on the wire


def test_sad_an_announced_huge_literal_is_refused_before_reading():
    """{99999999999}: no allocation, no read - the connection is dropped."""
    reader = _reader(b"abc)\r\n")
    with pytest.raises(IC.ImapAnswerTooLarge) as info:
        reader.read(99_999_999_999)
    assert info.value.errno == errno.EFBIG and "larger than 256 KiB" in str(info.value)
    assert reader.state == "LOGOUT" and reader.file.closed


def test_sad_a_literal_that_lies_about_its_size_still_counts():
    """A body announced within the limit but followed by more literals."""
    streams = {"BODY": lambda tag: _endless(
        b"* 1 FETCH (UID 1 RFC822 {100}\r\n" + b"x" * 100 + b"\r\n",
        b"* 1 FETCH (UID 1 BODY[1] {65000}\r\n" + b"y" * 65000 + b")\r\n", tag)}
    with StreamingImapServer(streams) as srv:
        with pytest.raises(OSError, match="larger than 1 MB"):
            _session(srv).open_read("/INBOX/1_hi.eml")
        assert srv.sent["BODY"] < BODY_LIMIT + IC._BODY_SLACK + 8 * MIB


def test_sad_endless_untagged_lines_stop_at_the_cap():
    streams = {"FETCH": lambda tag: _endless(b"", b"* 1 EXISTS\r\n" * 1000, tag)}
    with StreamingImapServer(streams) as srv:
        s = _session(srv)
        with pytest.raises(OSError) as info:
            s.list_dir("/INBOX")
        assert info.value.errno == errno.EFBIG
        assert "UID FETCH" in str(info.value) and "256 KiB" in str(info.value)
        # The client stopped reading long before the stream's own end.
        assert srv.sent["FETCH"] < STREAM_STOP // 2


def test_sad_endless_envelope_literals_stop_at_the_cap():
    """Each subject literal is small; together they are not."""
    unit = (b"* 1 FETCH (UID 1 ENVELOPE (NIL {60000}\r\n" + b"s" * 60000
            + b" NIL NIL NIL NIL NIL NIL NIL NIL))\r\n")
    with StreamingImapServer({"FETCH": lambda tag: _endless(b"", unit, tag)}) as srv:
        with pytest.raises(OSError, match="larger than 256 KiB"):
            _session(srv).list_dir("/INBOX")


def test_sad_an_endless_list_answer_stops_at_the_cap():
    unit = b'* LIST (\\HasNoChildren) "/" "' + b"m" * 200 + b'"\r\n'
    with StreamingImapServer({"LIST": lambda tag: _endless(b"", unit, tag)}) as srv:
        with pytest.raises(OSError, match="answer to LIST"):
            # The login's own LIST (separator detection) is cut already:
            # the connection cannot be used, so connecting fails with it.
            _session(srv).list_dir("/")


# --- edge -------------------------------------------------------------------


def test_edge_after_a_cut_the_next_call_reconnects_and_works():
    big = {"on": True}

    def body(tag):
        if big["on"]:
            big["on"] = False
            return _endless(b"* 1 FETCH (UID 1 RFC822 {4000000000}\r\n", b"x" * 65536, tag)
        return _body(tag)

    with StreamingImapServer({"BODY": body}) as srv:
        s = _session(srv)
        with pytest.raises(OSError):
            s.open_read("/INBOX/1_hi.eml")
        logins = _commands(srv, "LOGIN")
        assert s.open_read("/INBOX/1_hi.eml").read() == MESSAGE
        assert _commands(srv, "LOGIN") == logins + 1


def test_edge_the_body_budget_is_for_one_command_only():
    """The FETCH after a message FETCH has the small cap again."""
    reader = _reader(b"")
    IC._expect_large_answer(reader, 10 * MIB)
    budgets = []
    for _ in range(2):
        try:
            reader._command("NOOP")
        except Exception:  # noqa: BLE001 - no socket behind it; the budget is set first
            pass
        budgets.append(reader._axross_budget)
    assert budgets == [10 * MIB, CAP]


def test_edge_a_line_is_counted_and_cut_at_what_is_left():
    reader = _reader(b"* " + b"a" * (CAP * 2) + b"\r\n")
    with pytest.raises(IC.ImapAnswerTooLarge):
        reader.readline()


def _reader(data: bytes) -> IC._IMAP4:
    imap = IC._IMAP4.__new__(IC._IMAP4)
    imap.file = io.BufferedReader(io.BytesIO(data))
    imap.state = "SELECTED"
    return imap
