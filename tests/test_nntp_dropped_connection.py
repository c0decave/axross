"""NNTP: a connection nntp_lib closed is no longer reported as connected.

When a multi-line response breaks off (timeout, reset, cap) nntp_lib
closes the socket, because the stream is out of step. NntpSession's
``connected`` only checked ``self._client is not None``, so it still
said True: ConnectionManager._is_connected kept handing out the dead
session, and every later call failed with "Bad file descriptor" until
the user reconnected by hand.

Driven against the scripted NNTP server on 127.0.0.1.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mail_fuzz_servers import FakeNntpServer  # noqa: E402

from core.connection_manager import ConnectionManager  # noqa: E402
from core.nntp_client import NntpSession  # noqa: E402

_ARTICLE = "/comp.lang.python/1_Hello.eml"


@pytest.fixture
def srv():
    server = FakeNntpServer()
    yield server
    server.close()


def _session(srv, timeout: float = 0.5) -> NntpSession:
    s = NntpSession(srv.host, srv.port, use_tls=False)
    s._client._timeout = timeout
    s._client._sock.settimeout(timeout)
    return s


def test_happy_a_working_session_stays_connected(srv):
    s = _session(srv)
    assert s.open_read(_ARTICLE).read().startswith(b"Subject: Hello")
    assert s.connected
    assert ConnectionManager._is_connected(s)


def test_sad_a_response_that_breaks_off_leaves_the_session_disconnected(srv):
    srv.replies["ARTICLE"] = b"220 1 <a@x>\r\nSubject: x\r\n\r\npartial"  # no "." line
    s = _session(srv)
    with pytest.raises(OSError):
        s.open_read(_ARTICLE)
    assert not s.connected
    assert not ConnectionManager._is_connected(s)


def test_sad_an_abandoned_response_that_cannot_be_drained_disconnects(srv):
    srv.replies["OVER"] = b"224 overview\r\n1\tHello\tme\tdate\t<a@x>\t\t5\t1\r\n"  # no "."
    s = _session(srv)
    records = s._client.over(1, 2)
    next(records)
    records.close()  # stops early: the rest must be drained, and cannot be
    assert not s.connected


def test_edge_an_early_stop_that_drains_cleanly_stays_connected(srv):
    s = _session(srv)
    records = s._client.over(1, 2)
    next(records)
    records.close()
    assert s.connected
    assert [i.name for i in s.list_dir("/comp.lang.python")][0] == "1_Hello.eml"


def test_edge_quit_and_close_are_disconnected(srv):
    s = _session(srv)
    s._client.quit()
    assert not s.connected
    s.close()
    assert not s.connected
