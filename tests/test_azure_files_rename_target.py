"""Azure Files rename sends the destination as a path inside the share.

``rename_file`` / ``rename_directory`` take ``new_name`` relative to the
share (the SDK builds the target client from ``self.share_name`` plus
``new_name``). axross passed ``"<share>/<dst>"``, so renaming ``/a.txt``
to ``/b.txt`` on share ``data`` targeted ``data/data/b.txt``: the rename
failed (parent not found) or, with a folder named like the share, moved
the item into that folder.

Driven through the real azure-storage-file-share SDK against a local
HTTP server that records the rename requests.
"""

from __future__ import annotations

import sys
import threading
import unittest
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    from azure.storage.fileshare import ShareServiceClient

    from core.azure_client import AzureFilesSession

    SDK = True
except ImportError:  # pragma: no cover - optional extra
    SDK = False

_ACCOUNT = "devstoreaccount1"
_KEY = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="


class _FakeFileService:
    def __init__(self, directories: set[str]) -> None:
        self.directories = directories  # share-relative paths
        self.renames: list[tuple[str, str]] = []  # (target path, source header)
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _reply(self, status: int) -> None:
                self.send_response(status)
                self.send_header("ETag", '"0x1"')
                self.send_header("Last-Modified", formatdate(usegmt=True))
                self.send_header("x-ms-request-id", "r")
                self.send_header("x-ms-version", self.headers.get("x-ms-version", ""))
                if status == 404:
                    self.send_header("x-ms-error-code", "ResourceNotFound")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                parts = urlsplit(self.path)
                rel = parts.path.split("/", 3)[3] if parts.path.count("/") >= 3 else ""
                if "comp=rename" in parts.query:
                    src = self.headers.get("x-ms-file-rename-source", "")
                    outer.renames.append((rel, urlsplit(src).path))
                    self._reply(200)
                elif "restype=directory" in parts.query:
                    self._reply(200 if rel in outer.directories else 404)
                else:
                    self._reply(200)

            do_GET = do_HEAD = do_PUT = _handle

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        self.endpoint = f"http://127.0.0.1:{self._srv.server_address[1]}/{_ACCOUNT}"

    def stop(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()


@unittest.skipUnless(SDK, "azure-storage-file-share not installed")
class AzureFilesRenameTargetTest(unittest.TestCase):
    def _session(self, directories: set[str]) -> tuple["AzureFilesSession", _FakeFileService]:
        svc = _FakeFileService(directories)
        self.addCleanup(svc.stop)
        conn = (
            f"DefaultEndpointsProtocol=http;AccountName={_ACCOUNT};AccountKey={_KEY};"
            f"FileEndpoint={svc.endpoint};"
        )
        s = AzureFilesSession.__new__(AzureFilesSession)
        s._share_name = "data"
        s._service = ShareServiceClient.from_connection_string(conn)
        s._share = s._service.get_share_client("data")
        self.addCleanup(s._service.close)
        return s, svc

    def test_happy_file_rename_in_the_share_root(self) -> None:
        s, svc = self._session(set())
        s.rename("/a.txt", "/b.txt")
        self.assertEqual(svc.renames, [("b.txt", f"/{_ACCOUNT}/data/a.txt")])

    def test_sad_nested_file_rename_keeps_the_share_out_of_the_target(self) -> None:
        s, svc = self._session({"docs"})
        s.rename("/docs/a.txt", "/docs/old/a.txt")
        self.assertEqual(svc.renames[0][0], "docs/old/a.txt")

    def test_edge_directory_rename(self) -> None:
        s, svc = self._session({"src dir"})
        s.rename("/src dir", "/dst dir")
        self.assertEqual(svc.renames[0][0], "dst%20dir")


if __name__ == "__main__":
    unittest.main()
