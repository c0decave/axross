"""A session the user disconnected stays disconnected.

Measured before (review round 6, repros reconn/repro_{ftp,imap}_reopens_
after_user_close.py): after ``disconnect()`` the next call through the
same FtpSession / ImapSession object - a queued or retried transfer, a
scheduled job, an editor save - logged in again by itself with the stored
password (USER, PASS, ... on the wire), and nothing tracked or closed that
connection. POP3 and Telnet did the same. Now such a call raises
ConnectionError (ENOTCONN, "disconnected"); a connection that was lost
(not closed by the user) is still reconnected.
"""

from __future__ import annotations

import errno
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import imap_memory_server as IMS  # noqa: E402
from ftp_fuzz_server import FakeFtpServer  # noqa: E402

from core import telnet_client as TC  # noqa: E402
from core.ftp_client import FtpSession  # noqa: E402


def _refused(exc_info) -> None:
    assert isinstance(exc_info.value, ConnectionError)
    assert exc_info.value.errno == errno.ENOTCONN
    assert "disconnected" in str(exc_info.value)


# ------------------------------------------------------------------ FTP
def _ftp_server():
    return FakeFtpServer(data={"MLSD": b"type=file;size=3; a.txt\r\n",
                               "RETR": b"abc"})


@pytest.mark.parametrize("call", ["list_dir", "open_read", "stat"])
def test_sad_ftp_after_disconnect_does_not_log_in_again(call):
    with _ftp_server() as srv:
        s = FtpSession(srv.host, srv.port, "u", "p")
        s.disconnect()
        seen = len(srv.commands)
        with pytest.raises(ConnectionError) as exc_info:
            getattr(s, call)("/a.txt" if call != "list_dir" else "/")
        _refused(exc_info)
        assert not [c for c in srv.commands[seen:] if c.startswith(("USER", "PASS"))]
        assert s.connected is False


def test_edge_ftp_close_is_a_disconnect_too():
    with _ftp_server() as srv:
        s = FtpSession(srv.host, srv.port, "u", "p")
        with s:
            assert [i.name for i in s.list_dir("/")] == ["a.txt"]
        with pytest.raises(ConnectionError):
            s.list_dir("/")


def test_happy_ftp_a_lost_connection_is_still_reconnected():
    with _ftp_server() as srv:
        s = FtpSession(srv.host, srv.port, "u", "p")
        try:
            s._ftp.close()  # the network dropped it, the user did not
            s._ftp = None
            assert [i.name for i in s.list_dir("/")] == ["a.txt"]
        finally:
            s.disconnect()


# ----------------------------------------------------------------- IMAP
def test_sad_imap_after_disconnect_does_not_log_in_again(monkeypatch):
    srv = IMS.Server()
    srv.add_box("INBOX")
    srv.add_msg("INBOX", "hello")
    s = IMS.session(monkeypatch, srv)
    assert [i.name for i in s.list_dir("/INBOX")] == ["1_hello.eml"]
    s.disconnect()
    srv.log.clear()
    with pytest.raises(ConnectionError) as exc_info:
        s.list_dir("/INBOX")
    _refused(exc_info)
    assert srv.log == []
    assert s.connected is False


# --------------------------------------------------------------- Telnet
def _telnet_session():
    s = object.__new__(TC.TelnetSession)
    s._connected = True
    s._shell = mock.Mock()
    s._transport = mock.Mock(closed=False)
    s._host, s._port = "127.0.0.1", 23
    s._connect = mock.Mock(name="_connect")
    return s


def test_sad_telnet_after_close_does_not_log_in_again():
    s = _telnet_session()
    s.close()
    with pytest.raises(ConnectionError) as exc_info:
        s._ensure_connected()
    _refused(exc_info)
    with pytest.raises(ConnectionError):
        s._force_reconnect()
    s._connect.assert_not_called()


def test_happy_telnet_a_dropped_link_is_still_reconnected():
    s = _telnet_session()
    s._transport.closed = True  # the link dropped; no close() by the user
    s._ensure_connected()
    s._connect.assert_called_once()
