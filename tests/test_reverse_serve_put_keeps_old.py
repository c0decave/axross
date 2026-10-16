"""A failed reverse-server PUT leaves the old object; a failed commit is no 2xx.

Measured before, on both the S3 and the WebDAV flavour:

* A PUT whose body stopped short (client gone, timeout) got its 400, and
  then the handler's ``finally`` called ``handle.close()`` -- committing
  the partial body over the existing object. On LocalFS the truncating
  ``open(..., "wb")`` had already destroyed it before the first byte
  arrived. The client was told the PUT failed; the file was gone anyway.
* A backend whose commit failed at ``close()`` (every buffered writer:
  FTP STOR, S3 upload, a RamFS over its quota) had that error logged at
  debug level and the client got 200/201 for data that was never stored.
"""

from __future__ import annotations

import os
import shutil
import socket
import stat
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import reverse_serve  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402


class _QuotaRamFs(RamFsSession):
    """Accepts the bytes, refuses them at commit -- like a buffered
    upload whose STOR/PUT is rejected when the writer closes."""

    refuse_commit = False

    def _commit_write(self, path, data):
        if self.refuse_commit:
            raise OSError("simulated quota exceeded at commit")
        super()._commit_write(path, data)


class _Base:
    flavour = ""
    ok_status = 0

    def start(self, backend, root: str) -> None:
        serve = reverse_serve.serve_s3 if self.flavour == "s3" else reverse_serve.serve_webdav
        self.srv = serve(backend, bind="127.0.0.1", port=0, root_path=root)
        self.addCleanup(self.srv.shutdown)

    def url_path(self, name: str) -> str:
        return f"/bucket/{name}" if self.flavour == "s3" else f"/bucket/{name}"

    def put(self, name: str, body: bytes) -> int:
        req = urllib.request.Request(
            f"{self.srv.base_url}{self.url_path(name)}",
            data=body,
            method="PUT",
            headers={"Content-Length": str(len(body))},
        )
        try:
            with urllib.request.urlopen(req) as r:
                return r.status
        except urllib.error.HTTPError as exc:
            return exc.code

    def short_put(self, name: str, announced: int, sent: bytes) -> int:
        with socket.create_connection(("127.0.0.1", self.srv.port), timeout=5.0) as s:
            s.sendall(
                f"PUT {self.url_path(name)} HTTP/1.1\r\n".encode()
                + b"Host: 127.0.0.1\r\n"
                + f"Content-Length: {announced}\r\n".encode()
                + b"Connection: close\r\n\r\n"
                + sent
            )
            s.shutdown(socket.SHUT_WR)
            data = s.recv(4096)
        return int(data.split(b" ", 2)[1])


class _LocalCases(_Base):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / "bucket").mkdir()
        self.obj = self.tmp / "bucket" / "obj.bin"
        self.obj.write_bytes(b"old content")
        self.start(LocalFS(), str(self.tmp))

    def test_happy_a_complete_put_replaces_the_object(self) -> None:
        self.assertEqual(self.put("obj.bin", b"brand new"), self.ok_status)
        self.assertEqual(self.obj.read_bytes(), b"brand new")

    def test_sad_a_short_body_keeps_the_old_object(self) -> None:
        self.assertEqual(self.short_put("obj.bin", 100, b"partial"), 400)
        self.assertEqual(self.obj.read_bytes(), b"old content")
        self.assertEqual(sorted(p.name for p in self.obj.parent.iterdir()), ["obj.bin"])

    def test_edge_a_short_body_for_a_new_key_leaves_nothing(self) -> None:
        self.assertEqual(self.short_put("fresh.bin", 100, b"partial"), 400)
        self.assertEqual(sorted(p.name for p in self.obj.parent.iterdir()), ["obj.bin"])

    def test_edge_an_overwrite_keeps_the_permission_bits(self) -> None:
        os.chmod(self.obj, 0o640)
        self.assertEqual(self.put("obj.bin", b"brand new"), self.ok_status)
        self.assertEqual(stat.S_IMODE(self.obj.stat().st_mode), 0o640)

    def test_edge_an_empty_put_stores_an_empty_object(self) -> None:
        self.assertEqual(self.put("obj.bin", b""), self.ok_status)
        self.assertEqual(self.obj.read_bytes(), b"")


class _BufferedCases(_Base):
    def setUp(self) -> None:
        self.backend = _QuotaRamFs()
        self.backend.mkdir("/bucket")
        with self.backend.open_write("/bucket/obj.bin") as fh:
            fh.write(b"old content")
        self.start(self.backend, "/")

    def read_obj(self) -> bytes:
        with self.backend.open_read("/bucket/obj.bin") as fh:
            return fh.read()

    def test_happy_a_complete_put_replaces_the_object(self) -> None:
        self.assertEqual(self.put("obj.bin", b"brand new"), self.ok_status)
        self.assertEqual(self.read_obj(), b"brand new")

    def test_sad_a_short_body_keeps_the_old_object(self) -> None:
        self.assertEqual(self.short_put("obj.bin", 100, b"partial"), 400)
        self.assertEqual(self.read_obj(), b"old content")

    def test_sad_a_refused_commit_is_not_reported_as_success(self) -> None:
        self.backend.refuse_commit = True
        status = self.put("obj.bin", b"brand new")
        self.assertGreaterEqual(status, 500)
        self.backend.refuse_commit = False
        self.assertEqual(self.read_obj(), b"old content")


class S3LocalTest(_LocalCases, unittest.TestCase):
    flavour, ok_status = "s3", 200


class DavLocalTest(_LocalCases, unittest.TestCase):
    flavour, ok_status = "dav", 201


class S3BufferedTest(_BufferedCases, unittest.TestCase):
    flavour, ok_status = "s3", 200


class DavBufferedTest(_BufferedCases, unittest.TestCase):
    flavour, ok_status = "dav", 201


if __name__ == "__main__":
    unittest.main()
