"""NNTP: a server that closes an idle connection - most Usenet servers do
after a few minutes - and a session used after close().

Before: ``connected`` still said True after the server hung up (the
socket's end showed only at the next command), the next call failed with
"connection closed", and every call after it with "NNTP connection to ...
is closed" - NntpSession never reconnected, unlike IMAP and POP3, and the
connection manager handed the dead session out again. After close() a
listing raised AttributeError ('NoneType' object has no attribute
'list_groups'), no OSError.

Now a read (list, stat, open) that meets the closed connection is run
once more on a new one, logged in again; ``connected`` is False once the
connection is known to be gone; after close() every call is ENOTCONN.
"""

from __future__ import annotations

import errno
import socket
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.connection_manager import ConnectionManager  # noqa: E402
from core.nntp_client import NntpSession  # noqa: E402


class _HangingUpServer:
    """An NNTP server that answers MODE READER and AUTHINFO, then - the
    "idle time-out" - hangs up on the first connection. Later connections
    stay and answer LIST ACTIVE with one group."""

    def __init__(self, login: bool = False) -> None:
        #: The session logs in: the first connection ends after the login.
        self.login = login
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.connections = 0
        self.logins: list[str] = []
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._serve, args=(conn, self.connections),
                             daemon=True).start()

    def _serve(self, conn: socket.socket, number: int) -> None:
        reader = conn.makefile("rb")
        try:
            conn.sendall(b"200 ready\r\n")
            while True:
                line = reader.readline()
                if not line:
                    return
                cmd = line.decode().strip()
                if cmd.upper().startswith("MODE READER"):
                    conn.sendall(b"200 reader\r\n")
                    if number == 1 and not self.login:
                        return  # hangs up once the session is ready
                elif cmd.upper().startswith("AUTHINFO USER"):
                    self.logins.append(cmd.split(" ", 2)[2])
                    conn.sendall(b"381 password\r\n")
                elif cmd.upper().startswith("AUTHINFO PASS"):
                    conn.sendall(b"281 ok\r\n")
                    if number == 1:
                        return  # hangs up once the session is ready
                elif cmd.upper().startswith("LIST"):
                    conn.sendall(b"215 list\r\ncomp.lang.python 10 1 y\r\n.\r\n")
                elif cmd.upper().startswith("QUIT"):
                    conn.sendall(b"205 bye\r\n")
                    return
                else:
                    conn.sendall(b"500 what\r\n")
        finally:
            reader.close()
            conn.close()

    def close(self) -> None:
        self.sock.close()


@pytest.fixture
def server():
    srv = _HangingUpServer()
    yield srv
    srv.close()


@pytest.fixture
def login_server():
    srv = _HangingUpServer(login=True)
    yield srv
    srv.close()


def test_happy_a_listing_after_the_server_hung_up_reconnects(server):
    s = NntpSession("127.0.0.1", server.port, use_tls=False)
    try:
        assert [i.name for i in s.list_dir("/")] == ["comp.lang.python"]
        assert server.connections == 2
        assert s.connected
    finally:
        s.close()


def test_happy_the_reconnect_logs_in_again(login_server):
    s = NntpSession("127.0.0.1", login_server.port, username="reader", password="pw",
                    use_tls=False)
    try:
        assert [i.name for i in s.list_dir("/")] == ["comp.lang.python"]
        assert login_server.logins == ["reader", "reader"]
    finally:
        s.close()


def test_sad_a_dropped_connection_is_not_connected():
    s = NntpSession.__new__(NntpSession)

    class Closed:
        closed = True

    s._nntp = Closed()
    s._host = "news.example"
    assert s.connected is False
    assert ConnectionManager._is_connected(s) is False


def test_sad_after_close_every_call_is_enotconn(server):
    s = NntpSession("127.0.0.1", server.port, use_tls=False)
    s.close()
    for call in (lambda: s.list_dir("/"), lambda: s.stat("/comp.lang.python"),
                 lambda: s.open_read("/comp.lang.python/1_x.eml")):
        with pytest.raises(OSError) as info:
            call()
        assert info.value.errno == errno.ENOTCONN
    assert s.connected is False
