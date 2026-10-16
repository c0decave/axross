"""POP3 stat() reads the size from the single-line ``LIST n`` reply.

``poplib.POP3.list(n)`` returns ONE response line (``b"+OK 2 120"``),
not the ``(resp, lines, octets)`` triple of a bare ``LIST``. stat()
unpacked it as a triple: every call raised ValueError, so ``exists()``
(which only catches OSError) raised too, for every message.

Driven end to end against an in-process POP3 server on 127.0.0.1.
"""

from __future__ import annotations

import socket
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.pop3_client import Pop3Session  # noqa: E402

_MESSAGES = {1: b"Subject: one\r\n\r\nbody one\r\n", 2: b"Subject: hello\r\n\r\n" + b"x" * 90}


class _FakePop3:
    def __init__(self) -> None:
        self._srv = socket.create_server(("127.0.0.1", 0))
        self.port = self._srv.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            threading.Thread(target=self._session, args=(conn,), daemon=True).start()

    def _session(self, conn: socket.socket) -> None:
        conn.sendall(b"+OK ready\r\n")
        for raw in conn.makefile("rb"):
            cmd, *args = raw.decode().split()
            cmd = cmd.upper()
            if cmd in ("USER", "PASS", "NOOP"):
                conn.sendall(b"+OK\r\n")
            elif cmd == "LIST" and args:
                n = int(args[0])
                if n in _MESSAGES:
                    conn.sendall(f"+OK {n} {len(_MESSAGES[n])}\r\n".encode())
                else:
                    conn.sendall(b"-ERR no such message\r\n")
            elif cmd == "QUIT":
                conn.sendall(b"+OK bye\r\n")
                break
            else:
                conn.sendall(b"-ERR unsupported\r\n")
        conn.close()

    def stop(self) -> None:
        self._srv.close()


class Pop3StatTest(unittest.TestCase):
    def setUp(self) -> None:
        self.srv = _FakePop3()
        self.addCleanup(self.srv.stop)
        self.s = Pop3Session("127.0.0.1", self.srv.port, "u", "p", use_ssl=False)
        self.addCleanup(self.s.close)

    def test_happy_stat_reports_the_message_size(self) -> None:
        item = self.s.stat("/2_hello.eml")
        self.assertEqual(item.size, len(_MESSAGES[2]))
        self.assertFalse(item.is_dir)
        self.assertEqual(self.s.stat("/1_one.eml").size, len(_MESSAGES[1]))

    def test_sad_missing_message_is_an_oserror_and_not_existing(self) -> None:
        with self.assertRaises(OSError):
            self.s.stat("/9_gone.eml")
        self.assertFalse(self.s.exists("/9_gone.eml"))

    def test_edge_exists_answers_for_present_and_malformed_paths(self) -> None:
        self.assertTrue(self.s.exists("/1_one.eml"))
        self.assertFalse(self.s.exists("/not-a-message.txt"))
        self.assertTrue(self.s.exists("/"))


if __name__ == "__main__":
    unittest.main()
