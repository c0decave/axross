"""S3 folders on a store whose ListObjectsV2 answer has no KeyCount.

KeyCount is optional in S3-compatible stores (older Ceph RGW, some
gateways). S3Session.is_dir / stat read ``resp.get("KeyCount", 0)``, so
on such a store every folder (a prefix) was absent: is_dir False, exists
False, and remove(recursive=True) of a folder said "not found" while its
objects stayed. Contents / CommonPrefixes decide when KeyCount is missing.
"""

from __future__ import annotations

import pytest

pytest.importorskip("botocore")

from core.s3_client import S3Session  # noqa: E402
from tests.test_backend_conformance import _S3Store  # noqa: E402


@pytest.fixture(params=["with", "without"])
def s3(request):
    store = _S3Store()
    if request.param == "without":
        orig = store.list_objects_v2

        def no_keycount(**kw):
            resp = dict(orig(**kw))
            resp.pop("KeyCount", None)
            return resp

        store.list_objects_v2 = no_keycount
    s = S3Session.__new__(S3Session)
    s._s3, s._bucket, s._anonymous = store, "b", False
    store._put("photos/a.jpg", b"x")
    store._put("photos/2024/b.jpg", b"y")
    return s, store


def test_sad_a_prefix_is_a_folder_without_keycount(s3):
    s, _store = s3
    assert s.is_dir("/photos") is True
    assert s.exists("/photos") is True
    assert s.stat("/photos").is_dir is True
    assert s.is_dir("/photos/2024") is True


def test_sad_recursive_remove_of_the_folder_removes_its_objects(s3):
    s, store = s3
    s.remove("/photos", recursive=True)
    assert store.objects == {}


def test_edge_a_missing_prefix_is_still_no_folder(s3):
    s, _store = s3
    assert s.is_dir("/videos") is False
    with pytest.raises(FileNotFoundError):
        s.stat("/videos")


def test_sad_open_read_of_a_missing_key_is_file_not_found(s3):
    s, _store = s3
    with pytest.raises(FileNotFoundError):
        s.open_read("/photos/nope.jpg")
    with pytest.raises(IsADirectoryError):
        s.open_read("/photos")
