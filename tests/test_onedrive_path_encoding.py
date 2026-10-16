"""OneDrive puts drive paths into Graph URLs percent-encoded.

Two defects, both on the URL a path turns into:

* The path went into ``root:/<path>`` raw. ``#`` ends the URL (requests
  drops the fragment), ``?`` starts a query string and ``%20`` is
  decoded by the server: ``open_read("/notes#2.txt")`` downloaded
  ``/notes`` instead.
* ``checksum``, ``copy``, ``share`` and ``permissions_list`` called
  ``self._escape_path``, which does not exist - an AttributeError (not
  the OSError of the contract) or an OSError-wrapped failure, every time.

Driven end to end through ``requests`` against a local HTTP server that
stands in for graph.microsoft.com.
"""

from __future__ import annotations

import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import requests  # noqa: E402

from core import onedrive_client as OD  # noqa: E402


class _FakeGraph:
    def __init__(self) -> None:
        self.requests: list[tuple[str, str]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # noqa: D401 - silence
                pass

            def _answer(self, status: int, body: bytes, ctype: str) -> None:
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                outer.requests.append((self.command, self.path))
                if self.command == "GET" and self.path.endswith(":/content"):
                    self._answer(200, b"BYTES", "application/octet-stream")
                    return
                item = {
                    "id": "ID1",
                    "name": "x",
                    "size": 5,
                    "file": {"hashes": {"sha256Hash": "AB" * 32}},
                }
                self._answer(200, json.dumps(item).encode(), "application/json")

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _handle

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self._srv.server_address[1]}/v1.0"

    def stop(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()

    def paths(self) -> list[str]:
        return [p for _, p in self.requests]


class OneDrivePathEncodingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.graph = _FakeGraph()
        self.addCleanup(self.graph.stop)
        patcher = mock.patch.object(OD, "GRAPH_BASE", self.graph.base)
        patcher.start()
        self.addCleanup(patcher.stop)
        s = OD.OneDriveSession.__new__(OD.OneDriveSession)
        s._drive_type = "personal"
        s._site_id = ""
        s._access_token = "token"
        s._http = requests.Session()
        self.addCleanup(s._http.close)
        s._ensure_token = lambda: None
        self.s = s

    def test_happy_plain_names_are_unchanged(self) -> None:
        self.s.open_read("/docs/report.txt").read()
        self.s.stat("/docs/report.txt")
        self.assertEqual(
            self.graph.paths(),
            [
                "/v1.0/me/drive/root:/docs/report.txt:/content",
                "/v1.0/me/drive/root:/docs/report.txt",
            ],
        )

    def test_sad_hash_question_and_percent_reach_the_server_intact(self) -> None:
        self.s.open_read("/notes#2.txt").read()
        self.s.list_dir("/what?")
        self.s.stat("/a%20b.txt")
        with self.s.open_write("/up load#1.bin") as fh:
            fh.write(b"x")
        self.assertEqual(
            self.graph.paths(),
            [
                "/v1.0/me/drive/root:/notes%232.txt:/content",
                "/v1.0/me/drive/root:/what%3F:/children",
                "/v1.0/me/drive/root:/a%2520b.txt",
                "/v1.0/me/drive/root:/up%20load%231.bin:/content",
            ],
        )

    def test_sad_verbs_that_used_the_missing_helper_work(self) -> None:
        self.assertEqual(self.s.checksum("/d/f#1"), "sha256:" + "ab" * 32)
        self.s.copy("/d/f#1", "/e?/g")
        self.s.permissions_list("/d/f#1")
        self.assertEqual(
            self.graph.requests,
            [
                ("GET", "/v1.0/me/drive/root:/d/f%231"),
                ("POST", "/v1.0/me/drive/root:/d/f%231:/copy"),
                ("GET", "/v1.0/me/drive/root:/d/f%231:/permissions"),
            ],
        )

    def test_edge_root_and_unicode(self) -> None:
        self.s.list_dir("/")
        self.s.stat("/Ünïcødé ✓.txt")
        self.assertEqual(
            self.graph.paths(),
            [
                "/v1.0/me/drive/root/children",
                "/v1.0/me/drive/root:/%C3%9Cn%C3%AFc%C3%B8d%C3%A9%20%E2%9C%93.txt",
            ],
        )


if __name__ == "__main__":
    unittest.main()
