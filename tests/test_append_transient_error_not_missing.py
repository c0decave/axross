"""A transient server error is not "the object is missing".

Found in review (round 1, core): ``_looks_not_found`` matched "404" and
"no such" anywhere in the error text. A busy server whose message carries
a request id such as ``7c1e4049-...`` (or a DNS failure saying "No such
host is known") read as "absent", the append started from an empty
buffer and uploaded only the new bytes over the object.

"404" now counts only as a status of its own, "no such" only for a file,
key, object, path, blob or directory, and a message that names a
transient condition (busy, throttled, timed out, a host that cannot be
resolved, 429/5xx) never counts as not found. FileNotFoundError and
ENOENT still do.

Driven end to end through S3Session.open_write(append=True).
"""

from __future__ import annotations

import errno
import io
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

botocore = pytest.importorskip("botocore.exceptions")
ClientError = botocore.ClientError

from core import s3_client as SC  # noqa: E402
from core.append_helpers import _looks_not_found  # noqa: E402

BUSY_ID = "RequestId:7c1e4049-201e-0042-6b3f-1d9a5a000000"


class _FakeS3:
    def __init__(self, objects: dict[str, bytes], *, error: tuple[str, str] | None) -> None:
        self.objects = objects
        self.error = error
        self.uploads: list[tuple[str, bytes]] = []

    def _maybe_fail(self, op: str) -> None:
        if self.error is not None:
            code, message = self.error
            raise ClientError({"Error": {"Code": code, "Message": message}}, op)

    def get_object(self, Bucket, Key):  # noqa: N803 - boto3 names
        self._maybe_fail("GetObject")
        if Key not in self.objects:
            raise ClientError({"Error": {"Code": "NoSuchKey", "Message": "missing"}}, "GetObject")
        return {"Body": io.BytesIO(self.objects[Key])}

    def head_object(self, Bucket, Key):  # noqa: N803
        self._maybe_fail("HeadObject")
        if Key not in self.objects:
            raise ClientError({"Error": {"Code": "404", "Message": "Not Found"}}, "HeadObject")
        return {"ContentLength": len(self.objects[Key])}

    def list_objects_v2(self, **kw):
        return {"KeyCount": 0}

    def upload_fileobj(self, fileobj, Bucket, Key):  # noqa: N803
        data = fileobj.read()
        self.uploads.append((Key, data))
        self.objects[Key] = data


def _append(fake: _FakeS3, path: str, data: bytes) -> None:
    s = SC.S3Session.__new__(SC.S3Session)
    s._s3 = fake
    s._bucket = "b"
    s._anonymous = False
    with s.open_write(path, append=True) as fh:
        fh.write(data)


# --------------------------------------------------------------------------
# End to end
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("code", "message"),
    [
        ("SlowDown", f"Please reduce your request rate. {BUSY_ID}"),
        ("ServiceUnavailable", f"Server busy (503 ServerBusy) {BUSY_ID}"),
        ("InternalError", "We encountered an internal error. Please try again. id 404a"),
    ],
)
def test_sad_transient_error_never_truncates_the_object(code, message):
    fake = _FakeS3({"logs/app.log": b"precious;"}, error=(code, message))
    with pytest.raises(OSError):
        _append(fake, "/logs/app.log", b"new")
    assert fake.uploads == []
    assert fake.objects["logs/app.log"] == b"precious;"


def test_happy_append_to_a_missing_object_starts_empty():
    fake = _FakeS3({}, error=None)
    _append(fake, "/logs/new.log", b"new")
    assert fake.objects["logs/new.log"] == b"new"


def test_happy_append_keeps_the_old_bytes():
    fake = _FakeS3({"logs/app.log": b"old;"}, error=None)
    _append(fake, "/logs/app.log", b"new")
    assert fake.objects["logs/app.log"] == b"old;new"


# --------------------------------------------------------------------------
# The classifier
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "Not found: /x",
        "An error occurred (404) when calling the HeadObject operation: Not Found",
        "HTTP 404",
        "status=404",
        "An error occurred (NoSuchKey) when calling the GetObject operation",
        "No such file or directory",
        "no such object",
        "RESOURCE_NOT_FOUND",
    ],
)
def test_happy_real_not_found_messages_still_count(text):
    assert _looks_not_found(OSError(text), "/x")


@pytest.mark.parametrize(
    "text",
    [
        f"Server busy (503 ServerBusy)\n{BUSY_ID}",
        "request id 4049f, please retry",
        "No such host is known",
        "getaddrinfo failed: host not found",
        "Read timed out. (read timeout=60) 404-token",
        "429 Too Many Requests: not found in cache",
        "Temporary failure in name resolution",
        "Connection reset by peer (no such object yet?)",
    ],
)
def test_sad_transient_or_unrelated_messages_do_not_count(text):
    assert not _looks_not_found(OSError(text), "/x")


def test_edge_enoent_counts_whatever_the_text():
    assert _looks_not_found(OSError(errno.ENOENT, "Server busy (503)"), "/x")
    assert _looks_not_found(FileNotFoundError("timed out"), "/x")


def test_edge_the_path_is_still_ignored():
    assert not _looks_not_found(OSError("Cannot read /site/404.html: Access Denied"),
                                "/site/404.html")
