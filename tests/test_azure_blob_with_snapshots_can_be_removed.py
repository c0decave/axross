"""Azure Blob: a blob that has snapshots can be removed and renamed.

Protocol review (round 1): Delete Blob went without
``x-ms-delete-snapshots``; Azure refuses that for a blob with snapshots
(409 SnapshotsPresent) - and this backend's own snapshot_create() makes
them. remove() then said "File exists" (the 409 fell through to EEXIST),
a rename stopped after its copy and left a duplicate. Deleting a blob
now deletes its snapshots with it, as the portal's "delete blob and its
snapshots" does; SnapshotsPresent, should it still come, is EBUSY.
"""

from __future__ import annotations

import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

pytest.importorskip("azure.storage.blob")

from fake_azure_storage import ACCOUNT, KEY  # noqa: E402

LIST = ('<?xml version="1.0" encoding="utf-8"?><EnumerationResults ServiceEndpoint="x" '
        'ContainerName="c"><Blobs></Blobs><NextMarker /></EnumerationResults>').encode()
REFUSED = (b'<?xml version="1.0" encoding="utf-8"?><Error><Code>SnapshotsPresent</Code>'
           b'<Message>This operation is not permitted because the blob has snapshots.</Message>'
           b'</Error>')


@pytest.fixture
def server():
    seen: list = []

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def send(self, status, body=b"", hdrs=None):
            self.send_response(status)
            for k, v in (hdrs or {}).items():
                self.send_header(k, v)
            if "Content-Length" not in (hdrs or {}):
                self.send_header("Content-Length", str(len(body)))
            self.send_header("x-ms-version", "2021-06-08")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def handle_any(self):
            u = urlsplit(self.path)
            q = parse_qs(u.query)
            n = int(self.headers.get("Content-Length") or 0)
            if n:
                self.rfile.read(n)
            seen.append((self.command, u.path, self.headers.get("x-ms-delete-snapshots")))
            if q.get("restype") == ["container"] and q.get("comp") == ["list"]:
                return self.send(200, LIST, {"Content-Type": "application/xml"})
            if q.get("restype") == ["container"]:
                return self.send(200, b"", {"ETag": '"0x1"',
                                            "Last-Modified": "Mon, 02 Jan 2024 00:00:00 GMT"})
            if self.command == "HEAD":
                return self.send(200, b"", {"ETag": '"0x1"',
                                            "Last-Modified": "Mon, 02 Jan 2024 00:00:00 GMT",
                                            "x-ms-blob-type": "BlockBlob", "Content-Length": "3"})
            if self.command == "DELETE":
                if self.headers.get("x-ms-delete-snapshots"):
                    return self.send(202)
                return self.send(409, REFUSED, {"Content-Type": "application/xml",
                                                "x-ms-error-code": "SnapshotsPresent"})
            self.send(400)

        do_GET = do_HEAD = do_DELETE = do_PUT = handle_any

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv, seen
    srv.shutdown()
    srv.server_close()


def test_sad_a_blob_with_snapshots_is_removed(server):
    from core.azure_client import AzureBlobSession

    srv, seen = server
    cs = (f"DefaultEndpointsProtocol=http;AccountName={ACCOUNT};AccountKey={KEY};"
          f"BlobEndpoint=http://127.0.0.1:{srv.server_address[1]}/{ACCOUNT};")
    s = AzureBlobSession(connection_string=cs, container="c")
    s.remove("/f.txt")
    deletes = [r for r in seen if r[0] == "DELETE"]
    assert deletes and all(r[2] == "include" for r in deletes)


def test_edge_snapshots_present_is_ebusy():
    import errno

    from core import azure_client as AC

    class _Exc(Exception):
        error_code = "SnapshotsPresent"
        status_code = 409

    err = AC._azure_error(_Exc("has snapshots"), "Cannot remove /f")
    assert err.errno == errno.EBUSY
