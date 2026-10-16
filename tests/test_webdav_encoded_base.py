"""WebDAV strips a percent-encoded base path from PROPFIND hrefs.

A Nextcloud URL for a user with a space in the name ends in
``/remote.php/dav/files/John%20Doe``. The client kept that prefix
percent-encoded but compared it with the DECODED href, so the prefix
was never stripped: the listing of ``/`` contained the collection itself
(named "John Doe"), and stat / is_dir / exists of every path failed
with "PROPFIND returned no entry".

Driven end to end through requests against a local PROPFIND server.
"""

from __future__ import annotations

import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, unquote

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    import defusedxml  # noqa: F401
    import requests  # noqa: F401

    from core.webdav_client import WebDavSession

    DEPS = True
except ImportError:  # pragma: no cover - optional extra
    DEPS = False

# Server-side tree below the user's root: path -> is_dir
_TREE = {"": True, "notes.txt": False, "Sub Dir": True, "Sub Dir/a.txt": False}


def _entry(href: str, is_dir: bool, name: str) -> str:
    rtype = "<d:collection/>" if is_dir else ""
    size = "" if is_dir else "<d:getcontentlength>5</d:getcontentlength>"
    return (
        f"<d:response><d:href>{href}</d:href><d:propstat><d:prop>"
        f"<d:displayname>{name}</d:displayname><d:resourcetype>{rtype}</d:resourcetype>"
        f"{size}</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
    )


class _Dav:
    def __init__(self, root: str) -> None:
        self.root = root  # encoded, e.g. /remote.php/dav/files/John%20Doe
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_PROPFIND(self):  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                raw = self.path
                if not unquote(raw).startswith(unquote(outer.root)):
                    self.send_response(404)
                    self.end_headers()
                    return
                rel = unquote(raw)[len(unquote(outer.root)) :].strip("/")
                if rel not in _TREE:
                    self.send_response(404)
                    self.end_headers()
                    return
                entries = [(rel, _TREE[rel])]
                if self.headers.get("Depth") == "1" and _TREE[rel]:
                    prefix = rel + "/" if rel else ""
                    entries += [
                        (p, d)
                        for p, d in _TREE.items()
                        if p.startswith(prefix) and p and "/" not in p[len(prefix) :]
                    ]
                body = '<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">'
                for p, d in entries:
                    href = outer.root + "/" + quote(p) + ("/" if d and p else "")
                    name = p.rsplit("/", 1)[-1] if p else unquote(outer.root).rsplit("/", 1)[-1]
                    body += _entry(href, d, name)
                body += "</d:multistatus>"
                data = body.encode()
                self.send_response(207)
                self.send_header("Content-Type", "application/xml; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self._srv.server_address[1]}{root}"

    def stop(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()


@unittest.skipUnless(DEPS, "requests + defusedxml needed")
class WebDavEncodedBaseTest(unittest.TestCase):
    def _session(self, root: str) -> "WebDavSession":
        dav = _Dav(root)
        self.addCleanup(dav.stop)
        s = WebDavSession(dav.url)
        self.addCleanup(s.close)
        return s

    def test_happy_plain_base_path(self) -> None:
        s = self._session("/dav/files/alice")
        self.assertEqual(sorted(i.name for i in s.list_dir("/")), ["Sub Dir", "notes.txt"])
        self.assertEqual(s.stat("/notes.txt").size, 5)

    def test_sad_encoded_base_path_lists_only_children(self) -> None:
        s = self._session("/remote.php/dav/files/John%20Doe")
        self.assertEqual(sorted(i.name for i in s.list_dir("/")), ["Sub Dir", "notes.txt"])
        self.assertEqual(s.stat("/notes.txt").size, 5)
        self.assertTrue(s.exists("/notes.txt"))

    def test_edge_nested_and_root_on_encoded_base(self) -> None:
        s = self._session("/remote.php/dav/files/J%C3%BCrgen%20M")
        self.assertTrue(s.is_dir("/Sub Dir"))
        self.assertTrue(s.is_dir("/"))
        self.assertEqual([i.name for i in s.list_dir("/Sub Dir")], ["a.txt"])


if __name__ == "__main__":
    unittest.main()
