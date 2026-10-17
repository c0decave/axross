"""An append treats an object as missing because the server said so, not its name.

``read_existing_for_append`` decides whether a failed download means
"absent, start empty" or "present but unreadable, refuse". It looked for
"404", "not found", "no such" in the error TEXT -- which carries the
path. On a write-only S3 role (PutObject allowed, GetObject and
HeadObject 403 -- the usual upload-only policy) an append to
``site/404.html`` or ``logs/http-404.log`` read "Cannot read
/site/404.html: ... (AccessDenied)", found "404" in the name, started
from an empty buffer and uploaded only the new bytes over the object.

Driven through S3Session.open_write(append=True) with a fake boto3
client that answers like S3 does for such a role.
"""

from __future__ import annotations

import io
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from botocore.exceptions import ClientError  # noqa: E402

from core import s3_client as SC  # noqa: E402
from core.append_helpers import read_existing_for_append  # noqa: E402


class _FakeS3:
    def __init__(self, objects: dict[str, bytes], *, readable: bool) -> None:
        self.objects = objects
        self.readable = readable
        self.uploads: list[tuple[str, bytes]] = []

    def get_object(self, Bucket, Key):  # noqa: N803 - boto3 names
        if not self.readable:
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}}, "GetObject"
            )
        if Key not in self.objects:
            raise ClientError({"Error": {"Code": "NoSuchKey", "Message": "missing"}}, "GetObject")
        return {"Body": io.BytesIO(self.objects[Key])}

    def head_object(self, Bucket, Key):  # noqa: N803
        if not self.readable:
            raise ClientError({"Error": {"Code": "403", "Message": "Forbidden"}}, "HeadObject")
        if Key not in self.objects:
            raise ClientError({"Error": {"Code": "404", "Message": "Not Found"}}, "HeadObject")
        return {"ContentLength": len(self.objects[Key])}

    def list_objects_v2(self, **kw):
        return {"KeyCount": 0}

    def upload_fileobj(self, fileobj, Bucket, Key):  # noqa: N803
        data = fileobj.read()
        self.uploads.append((Key, data))
        self.objects[Key] = data


def _session(fake: _FakeS3) -> SC.S3Session:
    s = SC.S3Session.__new__(SC.S3Session)
    s._s3 = fake
    s._bucket = "b"
    s._anonymous = False
    return s


class AppendNotFoundIgnoresPathTest(unittest.TestCase):
    def append(self, fake: _FakeS3, path: str, data: bytes) -> None:
        with _session(fake).open_write(path, append=True) as fh:
            fh.write(data)

    def test_happy_append_keeps_the_old_bytes(self) -> None:
        fake = _FakeS3({"logs/http-404.log": b"old;"}, readable=True)
        self.append(fake, "/logs/http-404.log", b"new")
        self.assertEqual(fake.objects["logs/http-404.log"], b"old;new")

    def test_sad_an_unreadable_object_named_404_is_not_overwritten(self) -> None:
        fake = _FakeS3({"site/404.html": b"precious"}, readable=False)
        with self.assertRaises(OSError):
            self.append(fake, "/site/404.html", b"new")
        self.assertEqual(fake.uploads, [])
        self.assertEqual(fake.objects["site/404.html"], b"precious")

    def test_sad_a_name_saying_not_found_does_not_count_either(self) -> None:
        fake = _FakeS3({"docs/no such file.txt": b"precious"}, readable=False)
        with self.assertRaises(OSError):
            self.append(fake, "/docs/no such file.txt", b"new")
        self.assertEqual(fake.uploads, [])

    def test_edge_a_missing_object_still_starts_empty(self) -> None:
        fake = _FakeS3({}, readable=True)
        self.append(fake, "/site/404.html", b"new")
        self.assertEqual(fake.objects["site/404.html"], b"new")

    def test_edge_file_not_found_error_counts_as_missing(self) -> None:
        def open_read(path):
            raise FileNotFoundError(2, "No such file", path)

        def stat(path):
            raise FileNotFoundError(2, "No such file", path)

        got = read_existing_for_append(
            open_read=open_read, stat=stat, path="/x", cap=10, label="t", logger=SC.log
        )
        self.assertEqual(got, b"")


if __name__ == "__main__":
    unittest.main()
