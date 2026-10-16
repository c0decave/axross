"""NNTP ARTICLE / HEAD / BODY return the article's bytes unchanged.

Each line was decoded as UTF-8 with ``errors="replace"`` and encoded
again, so every byte that is not valid UTF-8 became U+FFFD (EF BF BD):
yEnc binary posts (the bulk of binary Usenet), Latin-1 / KOI8 text and
8-bit attachments came back corrupted, and a file saved from the
article differed from the one posted.

Driven end to end against an in-process NNTP server on 127.0.0.1.
"""

from __future__ import annotations

import socket
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.nntp_lib import NntpClient  # noqa: E402

# A yEnc-style body line: arbitrary high bytes, and NUL-free (yEnc escapes NUL).
_BINARY_LINE = bytes(range(0x80, 0x100)) + b"\xff\xfe=y"
_LATIN1 = "Grüße aus Köln".encode("latin-1")


class _FakeNntp:
    def __init__(self, replies: dict[str, bytes]) -> None:
        self.replies = replies
        self._srv = socket.create_server(("127.0.0.1", 0))
        self.port = self._srv.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                c, _ = self._srv.accept()
            except OSError:
                return
            threading.Thread(target=self._session, args=(c,), daemon=True).start()

    def _session(self, c: socket.socket) -> None:
        c.sendall(b"200 ready\r\n")
        for raw in c.makefile("rb"):
            verb = raw.decode("ascii", "replace").split()[0].upper()
            c.sendall(self.replies.get(verb, b"500 what\r\n"))
            if verb == "QUIT":
                break
        c.close()

    def stop(self) -> None:
        self._srv.close()


class NntpBinaryArticleTest(unittest.TestCase):
    def _client(self, replies: dict[str, bytes]) -> NntpClient:
        srv = _FakeNntp(replies)
        self.addCleanup(srv.stop)
        client = NntpClient(host="127.0.0.1", port=srv.port)
        self.addCleanup(client._sock.close)
        return client

    def test_happy_ascii_article_with_dot_stuffing(self) -> None:
        c = self._client({"ARTICLE": b"220 1 <a@x>\r\nSubject: hi\r\n\r\n..dot\r\nbody\r\n.\r\n"})
        self.assertEqual(c.article(1), b"Subject: hi\r\n\r\n.dot\r\nbody\r\n")

    def test_sad_binary_and_latin1_bytes_survive(self) -> None:
        c = self._client(
            {
                "ARTICLE": b"220 1 <a@x>\r\nSubject: bin\r\n\r\n" + _BINARY_LINE + b"\r\n.\r\n",
                "BODY": b"222 1 <a@x>\r\n" + _LATIN1 + b"\r\n.\r\n",
                "HEAD": b"221 1 <a@x>\r\nSubject: " + _LATIN1 + b"\r\n.\r\n",
            }
        )
        self.assertEqual(c.article(1), b"Subject: bin\r\n\r\n" + _BINARY_LINE + b"\r\n")
        self.assertEqual(c.body(1), _LATIN1 + b"\r\n")
        self.assertEqual(c.head(1), b"Subject: " + _LATIN1 + b"\r\n")

    def test_edge_dot_stuffed_binary_line(self) -> None:
        c = self._client({"BODY": b"222 1 <a@x>\r\n.." + b"\xe9\xff" + b"\r\n.\r\n"})
        self.assertEqual(c.body(1), b".\xe9\xff\r\n")


if __name__ == "__main__":
    unittest.main()
