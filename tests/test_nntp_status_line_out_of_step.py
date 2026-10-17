"""NNTP: a status line that could not be read closes the connection.

``_read_status`` let a timeout, an oversized or a malformed status line
escape and kept the socket. The server's reply still arrives, so the
next command read it as its own: after GROUP slow timed out, GROUP fast
returned slow's counts and current_group said "fast" - every article
number after that belonged to the wrong group. Measured 2026-10-17.

A well-formed error reply (411, 480 ...) is framed and keeps the
connection.
"""

from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import nntp_lib  # noqa: E402
from core.nntp_lib import NntpClient, NntpError, NntpResponseError  # noqa: E402

TIMEOUT = 0.3


class _Server:
    """Answers each command line from *script*: a reply, or (delay, reply)."""

    def __init__(self, script: dict):
        self.script = script
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        conn, _ = self.sock.accept()
        try:
            conn.sendall(b"200 ready\r\n")
            for line in conn.makefile("rb"):
                reply = self.script.get(line.strip().decode(), b"500 what\r\n")
                if isinstance(reply, tuple):
                    time.sleep(reply[0])
                    reply = reply[1]
                conn.sendall(reply)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self.sock.close()


@pytest.fixture
def serve():
    servers = []

    def start(script):
        server = _Server(script)
        servers.append(server)
        return NntpClient("127.0.0.1", server.port, timeout=TIMEOUT)

    yield start
    for server in servers:
        server.close()


# -- happy ---------------------------------------------------------------------------------


def test_happy_replies_in_time_keep_the_connection(serve):
    client = serve({"GROUP a": b"211 5 1 5 a\r\n", "GROUP b": b"211 9 1 9 b\r\n"})
    assert client.select_group("a") == (5, 1, 5)
    assert client.select_group("b") == (9, 1, 9)
    assert not client.closed and client.current_group == "b"


# -- sad -----------------------------------------------------------------------------------


def test_sad_a_late_reply_is_never_read_as_the_next_commands(serve):
    client = serve(
        {"GROUP slow": (TIMEOUT * 2, b"211 5 1 5 slow\r\n"), "GROUP fast": b"211 9 1 9 fast\r\n"}
    )
    with pytest.raises(OSError):
        client.select_group("slow")
    assert client.closed
    time.sleep(TIMEOUT * 2)  # the late reply has arrived by now
    with pytest.raises(NntpError, match="is closed"):
        client.select_group("fast")
    assert client.current_group is None


def test_sad_a_malformed_status_line_closes_the_connection(serve):
    client = serve({"GROUP a": b"hello there\r\n211 5 1 5 a\r\n"})
    with pytest.raises(NntpError, match="malformed"):
        client.select_group("a")
    assert client.closed


# -- edge ----------------------------------------------------------------------------------


def test_edge_an_error_reply_is_framed_and_keeps_the_connection(serve):
    client = serve({"GROUP gone": b"411 no such group\r\n", "GROUP a": b"211 5 1 5 a\r\n"})
    with pytest.raises(NntpResponseError):
        client.select_group("gone")
    assert not client.closed
    assert client.select_group("a") == (5, 1, 5)


def test_edge_an_oversized_status_line_closes_the_connection(serve, monkeypatch):
    monkeypatch.setattr(nntp_lib, "MAX_LINE_BYTES", 64)
    client = serve({"GROUP a": b"211 " + b"9" * 200 + b"\r\n"})
    with pytest.raises(NntpError, match="cap"):
        client.select_group("a")
    assert client.closed


def test_edge_a_bad_greeting_closes_the_socket(monkeypatch):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    opened = []
    real = NntpClient._open_socket

    def spy(self):
        opened.append(real(self))
        return opened[-1]

    monkeypatch.setattr(NntpClient, "_open_socket", spy)
    try:
        with pytest.raises(OSError):
            NntpClient("127.0.0.1", srv.getsockname()[1], timeout=TIMEOUT)  # no greeting
        assert opened and opened[0].fileno() == -1
    finally:
        srv.close()
