"""POP3: a listed message is the message acted on, even after a reconnect,
and a message's bytes are read whole.

Review of 2026-10-17:
- B4: remove() and open_read() used only the number in "<n>_<subject>.eml".
  POP3 numbers messages per connection; after a silent reconnect (the
  size cap dropped the connection) n named ANOTHER message: removing the
  listed "world" deleted "salary-letter". The drop also rolled back the
  DELE sent before it, without a word.
- B20: open_read joined the lines with CRLF and lost the final CRLF, so
  the bytes read were 2 fewer than the size stat reports.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mail_fuzz_servers import FakePop3Server  # noqa: E402

from core import pop3_client as P  # noqa: E402

MAILDROP = {  # connection -> message number -> (uid, subject, size)
    1: {1: ("u-hello", "hello", 100), 2: ("u-world", "world", 200), 3: ("u-big", "big", 900)},
    2: {1: ("u-world", "world", 200), 2: ("u-salary", "salary-letter", 300)},
}


@pytest.fixture
def server(monkeypatch):
    srv = FakePop3Server()
    state = {"conn": 0, "uidl": True}

    def drop(conn):
        return MAILDROP[min(state["conn"], 2)]

    def user(arg):
        state["conn"] += 1
        return b"+OK\r\n"

    def listing(arg):
        msgs = drop(None)
        if arg:
            n = int(arg)
            return b"+OK %d %d\r\n" % (n, msgs[n][2]) if n in msgs else b"-ERR no such message\r\n"
        return b"+OK\r\n" + b"".join(b"%d %d\r\n" % (n, m[2]) for n, m in msgs.items()) + b".\r\n"

    def uidl(arg):
        if not state["uidl"]:
            return b"-ERR not supported\r\n"
        msgs = drop(None)
        if arg:
            n = int(arg)
            return b"+OK %d %s\r\n" % (n, msgs[n][0].encode())
        lines = b"".join(b"%d %s\r\n" % (n, m[0].encode()) for n, m in msgs.items())
        return b"+OK\r\n" + lines + b".\r\n"

    def top(arg):
        n = int(arg.split()[0])
        return b"+OK\r\nSubject: " + drop(None)[n][1].encode() + b"\r\n\r\n.\r\n"

    srv.replies.update({"USER": user, "LIST": listing, "UIDL": uidl, "TOP": top,
                        "RETR": b"+OK\r\nSubject: x\r\n\r\nline one\r\nline two\r\n.\r\n"})
    srv.state = state
    yield srv
    srv.close()


def _session(srv):
    return P.Pop3Session(srv.host, srv.port, "u", "p", use_ssl=False)


def _commands(srv, *verbs):
    return [c for c in srv.commands if c.split()[0] in verbs]


def test_happy_on_the_listings_connection_the_number_is_used(server):
    s = _session(server)
    assert [i.name for i in s.list_dir("/")] == ["1_hello.eml", "2_world.eml", "3_big.eml"]
    s.remove("/2_world.eml")
    s.disconnect()
    assert _commands(server, "DELE", "QUIT") == ["DELE 2", "QUIT"]


def test_sad_after_a_reconnect_the_listed_message_is_found_by_its_uid(server, monkeypatch):
    s = _session(server)
    s.list_dir("/")
    s._pop.close()
    s._pop = None  # the connection is gone; the maildrop renumbers
    s.remove("/2_world.eml")
    assert _commands(server, "DELE") == ["DELE 1"]  # "world" is number 1 now, not "salary-letter"
    with pytest.raises(FileNotFoundError):
        s.remove("/1_hello.eml")  # deleted meanwhile


def test_sad_without_uidl_a_renumbered_message_is_refused(server):
    server.state["uidl"] = False
    s = _session(server)
    s.list_dir("/")
    s._pop.close()
    s._pop = None
    with pytest.raises(OSError, match="list the mailbox again"):
        s.remove("/2_world.eml")  # number 2 is "salary-letter" now
    assert _commands(server, "DELE") == []


def test_edge_a_message_over_the_cap_keeps_the_connection_and_its_deletions(server, monkeypatch):
    monkeypatch.setattr(P, "MAX_MESSAGE_BYTES", 500)
    s = _session(server)
    s.list_dir("/")
    s.remove("/1_hello.eml")
    with pytest.raises(OSError, match="cap"):
        s.open_read("/3_big.eml")
    s.disconnect()
    assert server.state["conn"] == 1  # no reconnect: DELE 1 is committed by QUIT
    assert _commands(server, "DELE", "RETR", "QUIT") == ["DELE 1", "QUIT"]


def test_edge_a_message_is_read_with_its_final_line_end(server):
    s = _session(server)
    s.list_dir("/")
    assert s.open_read("/1_hello.eml").read() == b"Subject: x\r\n\r\nline one\r\nline two\r\n"
