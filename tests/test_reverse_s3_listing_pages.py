"""Reverse-S3 lists in S3 order, pages, groups by delimiter, takes folders.

Measured with boto3 against the loopback server: ListObjects ignored
``marker`` / ``start-after`` / ``continuation-token`` (every page was
page one again, the v2 paginator looped over the same 1000 keys),
returned keys in walk order instead of sorted, ignored ``delimiter``
(no CommonPrefixes; nested keys came back as top-level objects), and a
folder-marker PUT of ``dir/`` (AWS console "Create folder", rclone
directory markers) lost its slash and stored an empty FILE ``dir``, so
the next PUT ``dir/a.txt`` failed.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import urllib.error
import urllib.request

import pytest

from core import reverse_serve
from core.local_fs import LocalFS
from core.ram_fs import RamFsSession

boto3 = pytest.importorskip("boto3")
from botocore.config import Config  # noqa: E402

_N = 1203


def _client(srv):
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
        os.environ.pop(k, None)
    return boto3.client(
        "s3",
        endpoint_url=srv.base_url,
        aws_access_key_id="x",
        aws_secret_access_key="y",
        region_name="us-east-1",
        config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}),
    )


@pytest.fixture(scope="module")
def big():
    ram = RamFsSession()
    ram.mkdir("/bkt")
    ram.mkdir("/bkt/dir")
    ram.mkdir("/bkt/dir/deeper")
    for i in range(_N):
        with ram.open_write(f"/bkt/k{i:04d}") as fh:
            fh.write(b"x")
    for rel in ("dir/nested.txt", "dir/deeper/z.txt", "a.txt"):
        with ram.open_write(f"/bkt/{rel}") as fh:
            fh.write(b"n")
    srv = reverse_serve.serve_s3(ram, bind="127.0.0.1", port=0, auth_token=None)
    try:
        yield _client(srv)
    finally:
        srv.shutdown()


_ALL = sorted([f"k{i:04d}" for i in range(_N)] + ["dir/nested.txt", "dir/deeper/z.txt", "a.txt"])


# -- happy -------------------------------------------------------------------


@pytest.mark.parametrize("op", ["list_objects_v2", "list_objects"])
def test_happy_paginator_returns_every_key_once_in_order(big, op):
    seen = []
    for page in big.get_paginator(op).paginate(Bucket="bkt", PaginationConfig={"PageSize": 500}):
        seen += [o["Key"] for o in page.get("Contents", [])]
    assert seen == _ALL


def test_happy_delimiter_groups_folders_into_common_prefixes(big):
    d = big.list_objects_v2(Bucket="bkt", Delimiter="/", MaxKeys=5000)
    assert [p["Prefix"] for p in d.get("CommonPrefixes", [])] == ["dir/"]
    keys = [o["Key"] for o in d["Contents"]]
    assert "dir/nested.txt" not in keys and "a.txt" in keys
    assert d["KeyCount"] == len(keys) + 1
    inner = big.list_objects_v2(Bucket="bkt", Prefix="dir/", Delimiter="/")
    assert [o["Key"] for o in inner["Contents"]] == ["dir/nested.txt"]
    assert [p["Prefix"] for p in inner["CommonPrefixes"]] == ["dir/deeper/"]


def test_happy_folder_marker_put_makes_a_folder():
    root = tempfile.mkdtemp(prefix="s3root-")
    try:
        os.makedirs(os.path.join(root, "bkt"))
        srv = reverse_serve.serve_s3(
            LocalFS(), bind="127.0.0.1", port=0, root_path=root, auth_token=None
        )
        try:
            s3 = _client(srv)
            s3.put_object(Bucket="bkt", Key="dir/", Body=b"")
            assert os.path.isdir(os.path.join(root, "bkt", "dir"))
            s3.put_object(Bucket="bkt", Key="dir/a.txt", Body=b"hello")
            with open(os.path.join(root, "bkt", "dir", "a.txt"), "rb") as fh:
                assert fh.read() == b"hello"
            # A second marker PUT on the existing folder is fine too.
            s3.put_object(Bucket="bkt", Key="dir/", Body=b"")
        finally:
            srv.shutdown()
    finally:
        shutil.rmtree(root)


# -- sad ---------------------------------------------------------------------


def test_sad_v1_marker_and_v2_start_after_skip_what_was_seen(big):
    p1 = big.list_objects(Bucket="bkt", MaxKeys=3)
    assert [o["Key"] for o in p1["Contents"]] == _ALL[:3]
    assert p1["IsTruncated"] is True
    p2 = big.list_objects(Bucket="bkt", Marker=p1["Contents"][-1]["Key"], MaxKeys=3)
    assert [o["Key"] for o in p2["Contents"]] == _ALL[3:6]
    v2 = big.list_objects_v2(Bucket="bkt", StartAfter=_ALL[-2])
    assert [o["Key"] for o in v2["Contents"]] == _ALL[-1:]
    assert v2["IsTruncated"] is False


def test_sad_folder_marker_with_a_body_is_refused():
    ram = RamFsSession()
    ram.mkdir("/bkt")
    srv = reverse_serve.serve_s3(ram, bind="127.0.0.1", port=0, auth_token=None)
    try:
        req = urllib.request.Request(
            f"{srv.base_url}/bkt/dir/", data=b"data", method="PUT",
            headers={"Content-Length": "4"},
        )
        with pytest.raises(urllib.error.HTTPError) as info:
            urllib.request.urlopen(req)
        assert info.value.code == 400
        assert not ram.exists("/bkt/dir")
    finally:
        srv.shutdown()


# -- edge --------------------------------------------------------------------


def test_edge_continuation_token_and_common_prefix_marker(big):
    p1 = big.list_objects_v2(Bucket="bkt", Delimiter="/", MaxKeys=2)
    assert [o["Key"] for o in p1["Contents"]] == ["a.txt"]
    assert [p["Prefix"] for p in p1["CommonPrefixes"]] == ["dir/"]
    p2 = big.list_objects_v2(
        Bucket="bkt", Delimiter="/", MaxKeys=2, ContinuationToken=p1["NextContinuationToken"]
    )
    assert "CommonPrefixes" not in p2
    assert [o["Key"] for o in p2["Contents"]] == ["k0000", "k0001"]
    assert p2["ContinuationToken"] == p1["NextContinuationToken"]
    # v1 with a delimiter names the common prefix as the next marker.
    v1 = big.list_objects(Bucket="bkt", Delimiter="/", MaxKeys=2)
    assert v1["NextMarker"] == "dir/"
    v1b = big.list_objects(Bucket="bkt", Delimiter="/", MaxKeys=2, Marker="dir/")
    assert [o["Key"] for o in v1b["Contents"]] == ["k0000", "k0001"]


def test_edge_bad_continuation_token_is_400(big):
    with pytest.raises(Exception) as info:
        big.list_objects_v2(Bucket="bkt", ContinuationToken="!!not-a-token!!")
    assert "InvalidArgument" in str(info.value)
