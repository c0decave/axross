"""S3 ``list_versions`` follows ``IsTruncated`` instead of stopping at page one.

``ListObjectVersions`` returns at most 1 000 entries per call
(``MaxKeys``). ``list_versions`` made one call and returned what it got,
so an object with more than 1 000 versions silently lost its oldest ones
from the version browser — the very versions a restore usually wants.

Siblings that share the key as a prefix (``a.txt.bak``) were already
filtered out by key; S3 lists keys in order, so once a page reaches a key
past the target no further page can hold one of its versions, and the
loop stops there instead of paging through every sibling.

Driven through a real boto3 client with botocore's Stubber, which checks
every request against the S3 service model.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

boto3 = pytest.importorskip("boto3")
from botocore.stub import Stubber  # noqa: E402

from core import s3_client as S3  # noqa: E402

WHEN = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _v(key: str, n: int, latest: bool = False) -> dict:
    return {
        "Key": key,
        "VersionId": f"v{n:05d}",
        "IsLatest": latest,
        "LastModified": WHEN,
        "Size": n,
        "ETag": '"x"',
        "StorageClass": "STANDARD",
    }


def _session():
    client = boto3.client(
        "s3",
        region_name="us-east-1",
        aws_access_key_id="k",
        aws_secret_access_key="s",
    )
    s = object.__new__(S3.S3Session)
    s._s3 = client
    s._bucket = "b"
    return s, Stubber(client)


def _page(versions, *, next_key=None, next_vid=None) -> dict:
    resp = {"Versions": versions, "IsTruncated": next_key is not None}
    if next_key is not None:
        resp["NextKeyMarker"] = next_key
        resp["NextVersionIdMarker"] = next_vid
    return resp


def test_happy_more_than_one_page_of_versions_is_listed_completely():
    s, stub = _session()
    first = [_v("a.txt", i, latest=(i == 0)) for i in range(1000)]
    second = [_v("a.txt", i) for i in range(1000, 1500)]
    stub.add_response(
        "list_object_versions",
        _page(first, next_key="a.txt", next_vid="v00999"),
        {"Bucket": "b", "Prefix": "a.txt"},
    )
    stub.add_response(
        "list_object_versions",
        _page(second),
        {"Bucket": "b", "Prefix": "a.txt", "KeyMarker": "a.txt", "VersionIdMarker": "v00999"},
    )
    with stub:
        versions = s.list_versions("/a.txt")
    stub.assert_no_pending_responses()
    assert len(versions) == 1500
    assert [v.is_current for v in versions].count(True) == 1
    assert versions[-1].version_id == "v01499"


def test_sad_sibling_keys_are_not_counted_and_end_the_paging():
    s, stub = _session()
    page1 = [_v("a.txt", 1, latest=True), _v("a.txt", 2), _v("a.txt.bak", 3, latest=True)]
    stub.add_response(
        "list_object_versions",
        # Truncated, but the page already reached a key past "a.txt":
        # asking for the next page would only list more siblings.
        _page(page1, next_key="a.txt.bak", next_vid="v00003"),
        {"Bucket": "b", "Prefix": "a.txt"},
    )
    with stub:
        versions = s.list_versions("/a.txt")
    stub.assert_no_pending_responses()
    assert [v.version_id for v in versions] == ["v00001", "v00002"]


def test_sad_truncated_page_without_a_marker_raises_instead_of_looping():
    s, stub = _session()
    resp = _page([_v("a.txt", 1)])
    resp["IsTruncated"] = True
    stub.add_response("list_object_versions", resp, {"Bucket": "b", "Prefix": "a.txt"})
    with stub, pytest.raises(OSError):
        s.list_versions("/a.txt")


def test_edge_unversioned_bucket_returns_no_versions():
    s, stub = _session()
    stub.add_response(
        "list_object_versions", {"IsTruncated": False}, {"Bucket": "b", "Prefix": "a.txt"}
    )
    with stub:
        assert s.list_versions("/a.txt") == []


def test_edge_client_error_is_an_oserror():
    s, stub = _session()
    stub.add_client_error("list_object_versions", service_error_code="AccessDenied")
    with stub, pytest.raises(OSError):
        s.list_versions("/a.txt")


def test_edge_a_repeated_marker_raises_instead_of_looping():
    s, stub = _session()
    page = _page([_v("a.txt", 1)], next_key="a.txt", next_vid="v00001")
    stub.add_response("list_object_versions", page, {"Bucket": "b", "Prefix": "a.txt"})
    stub.add_response(
        "list_object_versions",
        page,
        {"Bucket": "b", "Prefix": "a.txt", "KeyMarker": "a.txt", "VersionIdMarker": "v00001"},
    )
    with stub, pytest.raises(OSError):
        s.list_versions("/a.txt")
