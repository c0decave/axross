"""Gopher recursive_fetch names leaves the way list_dir does.

It used to build each child path from the raw display string and fetch
every non-menu entry: info lines (type ``i``) were requested from the
server as files, two entries sharing a display string landed on one key
(the second body overwrote the first), and the returned paths differed
from the names ``list_dir`` shows, so they did not resolve back through
``open_read``.

Driven end to end against an in-process Gopher server on 127.0.0.1.
"""

from __future__ import annotations

import socket
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.gopher_client import GopherSession  # noqa: E402


class _GopherServer:
    def __init__(self, responses: dict[str, bytes]) -> None:
        self.responses = responses
        self.selectors: list[str] = []
        self._srv = socket.create_server(("127.0.0.1", 0))
        self._srv.settimeout(0.2)
        self.port = self._srv.getsockname()[1]
        self._stop = threading.Event()
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                c, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                sel = b""
                while not sel.endswith(b"\r\n"):
                    chunk = c.recv(64)
                    if not chunk:
                        break
                    sel += chunk
                selector = sel.decode().rstrip("\r\n")
                self.selectors.append(selector)
                c.sendall(self.responses.get(selector, b"3not found\tfake\t(NULL)\t0\r\n.\r\n"))
            finally:
                c.close()

    def stop(self) -> None:
        self._stop.set()
        self._srv.close()


class RecursiveFetchNamingTest(unittest.TestCase):
    def _session(self, responses: dict[str, bytes]) -> tuple[GopherSession, _GopherServer]:
        srv = _GopherServer(responses)
        self.addCleanup(srv.stop)
        return GopherSession(host="127.0.0.1", port=srv.port), srv

    def test_happy_info_lines_are_not_fetched_as_files(self) -> None:
        root = (
            b"iWelcome to the hole\tfake\t(NULL)\t0\r\n"
            b"i\tfake\t(NULL)\t0\r\n"
            b"0notes.txt\t/notes.txt\texample\t70\r\n"
            b".\r\n"
        )
        s, srv = self._session({"": root, "/notes.txt": b"n"})
        srv.selectors.clear()
        out = s.recursive_fetch("/")
        self.assertEqual(out, {"/notes.txt": b"n"})
        self.assertNotIn("fake", srv.selectors)

    def test_sad_duplicate_display_names_keep_both_bodies(self) -> None:
        root = (
            b"0report\t/r1\texample\t70\r\n"
            b"0report\t/r2\texample\t70\r\n"
            b".\r\n"
        )
        s, _ = self._session({"": root, "/r1": b"first", "/r2": b"second"})
        out = s.recursive_fetch("/")
        self.assertEqual(out, {"/report.txt": b"first", "/report-1.txt": b"second"})
        self.assertEqual(sorted(i.name for i in s.list_dir("/")), ["report-1.txt", "report.txt"])

    def test_edge_keys_resolve_through_open_read(self) -> None:
        root = (
            b"0a/b\t/deep/x\texample\t70\r\n"
            b"1My Menu\t/m\texample\t70\r\n"
            b".\r\n"
        )
        sub = b"0leaf\t/m/leaf\texample\t70\r\n.\r\n"
        s, _ = self._session({"": root, "/m": sub, "/deep/x": b"X", "/m/leaf": b"L"})
        out = s.recursive_fetch("/")
        self.assertEqual(out, {"/a_b.txt": b"X", "/My Menu/leaf.txt": b"L"})
        for path, body in out.items():
            with s.open_read(path) as fh:
                self.assertEqual(fh.read(), body)


if __name__ == "__main__":
    unittest.main()
