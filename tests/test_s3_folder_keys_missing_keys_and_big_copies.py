"""S3: trailing-slash destinations, missing keys and copies above 5 GiB.

* A destination ending in "/" became the folder-marker key ``x/``: the
  data vanished from the listing (shown as a folder) and a later
  ``mkdir("/x")`` replaced it with an empty marker. ``rename``,
  ``open_write`` and ``copy`` now refuse such a file destination with
  IsADirectoryError, as Azure Blob's ``_file_key`` does.
* ``stat("/nothing/")`` answered ``is_dir=True`` for any name: a
  trailing-slash key is a folder only when the prefix exists.
* ``remove()`` of a missing key reported success (DeleteObject answers
  204 for it) and ``stat()`` of one was a plain OSError: both are
  FileNotFoundError now, as on LocalFS.
* CopyObject is capped at 5 GiB, so moving or copying a bigger object
  failed: above the cap the copy is a multipart upload of
  UploadPartCopy byte ranges.
"""

from __future__ import annotations

import pytest

from tests.test_object_store_file_beside_a_same_named_folder import _s3

botocore_exceptions = pytest.importorskip("botocore.exceptions")


def _writable(keys):
    sess, store = _s3(keys)

    def put_object(Bucket, Key, Body):
        store[Key] = Body.read() if hasattr(Body, "read") else Body

    sess._s3.put_object = put_object
    return sess, store


class _BigS3:
    """Records the copy calls for an object HEAD reports as *size* bytes."""

    def __init__(self, size, *, fail_part=None):
        self.size = size
        self.fail_part = fail_part
        self.calls = []

    def head_object(self, Bucket, Key):
        if Key != "big.iso":
            raise botocore_exceptions.ClientError({"Error": {"Code": "404"}}, "HeadObject")
        return {"ContentLength": self.size, "ContentType": "application/x-iso9660-image"}

    def copy_object(self, **kw):
        self.calls.append(("copy_object", kw))
        if self.size > 5 * 1024**3:
            raise botocore_exceptions.ClientError(
                {"Error": {"Code": "InvalidRequest", "Message": "too large"}}, "CopyObject"
            )

    def create_multipart_upload(self, **kw):
        self.calls.append(("create", kw))
        return {"UploadId": "u1"}

    def upload_part_copy(self, **kw):
        self.calls.append(("part", kw))
        if kw["PartNumber"] == self.fail_part:
            raise botocore_exceptions.ClientError({"Error": {"Code": "500"}}, "UploadPartCopy")
        return {"CopyPartResult": {"ETag": f'"e{kw["PartNumber"]}"'}}

    def complete_multipart_upload(self, **kw):
        self.calls.append(("complete", kw))

    def abort_multipart_upload(self, **kw):
        self.calls.append(("abort", kw))


def _big(size, **kw):
    sess, _ = _s3([])
    sess._s3 = _BigS3(size, **kw)
    return sess, sess._s3


# -- happy -------------------------------------------------------------------


def test_happy_stat_of_an_existing_prefix_with_a_slash_is_a_folder():
    sess, _ = _s3(["docs/a.txt"])
    assert sess.stat("/docs/").is_dir


def test_happy_a_copy_above_5_gib_is_a_multipart_part_copy():
    size = 6 * 1024**3 + 7
    sess, fake = _big(size)
    sess.copy("/big.iso", "/copy.iso")
    kinds = [c[0] for c in fake.calls]
    assert "copy_object" not in kinds
    assert kinds[0] == "create" and kinds[-1] == "complete"
    assert fake.calls[0][1]["ContentType"] == "application/x-iso9660-image"
    ranges = [c[1]["CopySourceRange"] for c in fake.calls if c[0] == "part"]
    assert ranges[0].startswith("bytes=0-")
    assert ranges[-1].endswith(f"-{size - 1}")
    parts = fake.calls[-1][1]["MultipartUpload"]["Parts"]
    assert [p["PartNumber"] for p in parts] == list(range(1, len(ranges) + 1))


def test_happy_a_small_copy_is_still_one_copy_object():
    sess, store = _s3(["a.txt"])
    sess.copy("/a.txt", "/b.txt")
    assert store["b.txt"] == store["a.txt"]


# -- sad ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "op",
    [
        lambda s: s.rename("/report.txt", "/archive/"),
        lambda s: s.copy("/report.txt", "/archive/"),
        lambda s: s.open_write("/archive/"),
    ],
    ids=["rename", "copy", "open_write"],
)
def test_sad_a_file_destination_ending_in_a_slash_is_refused(op):
    sess, store = _writable(["report.txt"])
    with pytest.raises(IsADirectoryError):
        op(sess)
    assert store == {"report.txt": b"data-report.txt"}


def test_sad_stat_of_a_missing_prefix_with_a_slash_is_not_found():
    sess, _ = _s3(["a.txt"])
    with pytest.raises(FileNotFoundError):
        sess.stat("/nothing/")


def test_sad_remove_of_a_missing_key_is_not_found():
    sess, store = _s3(["a.txt"])
    with pytest.raises(FileNotFoundError):
        sess.remove("/typo.txt")
    assert sorted(store) == ["a.txt"]


def test_sad_stat_of_a_missing_key_is_not_found():
    sess, _ = _s3(["a.txt"])
    with pytest.raises(FileNotFoundError):
        sess.stat("/typo.txt")


def test_sad_a_failed_part_aborts_the_multipart_copy():
    sess, fake = _big(6 * 1024**3, fail_part=2)
    with pytest.raises(OSError):
        sess.copy("/big.iso", "/copy.iso")
    kinds = [c[0] for c in fake.calls]
    assert kinds[-1] == "abort" and "complete" not in kinds


# -- edge --------------------------------------------------------------------


def test_edge_rename_onto_itself_keeps_the_object():
    sess, store = _s3(["a.txt"])
    sess.rename("/a.txt", "/a.txt")
    assert store == {"a.txt": b"data-a.txt"}


def test_edge_copy_of_a_missing_source_is_not_found():
    sess, _ = _s3(["a.txt"])
    with pytest.raises(FileNotFoundError):
        sess.copy("/typo.txt", "/b.txt")
