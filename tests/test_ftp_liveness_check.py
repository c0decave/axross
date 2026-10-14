"""FTP checks the control connection without a NOOP before every command.

Before: ``_ensure_connected`` sent NOOP and waited for its reply before
EVERY operation - one extra round trip per mkdir/stat/delete/rename.
Now a connection verified within the last few seconds is used directly
unless its socket is readable: a server that closed the connection (idle
timeout: "421" then FIN) makes it readable, and then the NOOP + reconnect
path runs exactly as before.
"""

from __future__ import annotations

import socket
import sys
import threading
import unittest
from ftplib import FTP
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import ftp_client as FC  # noqa: E402


class _FakeControl:
    """The server end of a control connection: answers NOOP and MKD."""

    def __init__(self) -> None:
        self.client_sock, self._srv = socket.socketpair()
        self.commands: list[str] = []
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        f = self._srv.makefile("rb")
        for raw in f:
            line = raw.decode().strip()
            self.commands.append(line.split(" ", 1)[0])
            if line == "NOOP":
                self._srv.sendall(b"200 ok\r\n")
            elif line.startswith("MKD "):
                self._srv.sendall(b'257 "' + line[4:].encode() + b'" created\r\n')
            else:
                self._srv.sendall(b"502 no\r\n")

    def server_closes(self) -> None:
        self._srv.sendall(b"421 Timeout\r\n")
        self._srv.shutdown(socket.SHUT_RDWR)
        self._srv.close()

    def ftp(self) -> FTP:
        ftp = FTP()
        ftp.sock = self.client_sock
        ftp.file = self.client_sock.makefile("r", encoding=ftp.encoding)
        return ftp

    def noops(self) -> int:
        return self.commands.count("NOOP")


def _session(ftp: FTP) -> FC.FtpSession:
    s = FC.FtpSession.__new__(FC.FtpSession)
    s._ftp = ftp
    s._host, s._username = "h", "u"
    return s


class LivenessTest(unittest.TestCase):
    def setUp(self) -> None:
        self.ctl = _FakeControl()
        self.addCleanup(self.ctl.client_sock.close)

    def test_happy_a_burst_of_commands_sends_one_noop(self) -> None:
        s = _session(self.ctl.ftp())
        for i in range(20):
            s.mkdir(f"/d{i}")
        self.assertEqual(self.ctl.commands.count("MKD"), 20)
        self.assertEqual(self.ctl.noops(), 1)

    def test_sad_a_server_side_close_still_reconnects(self) -> None:
        s = _session(self.ctl.ftp())
        s.mkdir("/a")
        self.ctl.server_closes()
        fresh = _FakeControl()
        self.addCleanup(fresh.client_sock.close)

        def reconnect():
            s._ftp = fresh.ftp()

        with mock.patch.object(FC.FtpSession, "_connect", side_effect=reconnect) as conn:
            s.mkdir("/b")
        conn.assert_called_once()
        self.assertEqual(fresh.commands, ["MKD"])

    def test_edge_after_the_window_the_noop_comes_back(self) -> None:
        s = _session(self.ctl.ftp())
        clock = [1000.0]
        with mock.patch.object(FC.time, "monotonic", side_effect=lambda: clock[0]):
            s.mkdir("/a")
            clock[0] += FC.LIVENESS_WINDOW - 0.5
            s.mkdir("/b")
            self.assertEqual(self.ctl.noops(), 1)
            clock[0] += 1.0
            s.mkdir("/c")
        self.assertEqual(self.ctl.noops(), 2)

    def test_edge_connected_property_still_asks_the_server(self) -> None:
        s = _session(self.ctl.ftp())
        self.assertTrue(s.connected)
        self.assertTrue(s.connected)
        self.assertEqual(self.ctl.noops(), 2)

    def test_edge_no_real_socket_falls_back_to_noop(self) -> None:
        ftp = mock.Mock()
        ftp.sock = mock.Mock()
        s = _session(ftp)
        s._ensure_connected()
        s._ensure_connected()
        self.assertEqual(ftp.voidcmd.call_count, 2)


if __name__ == "__main__":
    unittest.main()
