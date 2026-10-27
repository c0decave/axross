"""Reverse serve: a stat or a listing that FAILS is never "not found" or
"empty".

0.14.90 / 0.14.99 made DELETE answer an error instead of 404/204 when the
backend refused it ("a client takes 404 for gone"). The read side kept
the same mistake (core/reverse_serve.py):

* WebDAV HEAD, GET and PROPFIND and S3 HEAD bucket, GET and HEAD object
  answered 404 / NoSuchKey / NoSuchBucket for EVERY OSError of stat() - a
  timeout or a refused permission included.
* PROPFIND with Depth 1 answered 207 with the folder and no children when
  list_dir() failed: an unreadable folder looked empty.
* The S3 listing (_walk_keys) skipped every folder whose list_dir() failed
  and answered IsTruncated=false: the keys below it were simply missing.
  A failing bucket root gave an empty, complete listing.

``rclone sync``, ``aws s3 sync --delete`` or a davfs2 cache take a 404, an
empty folder or a complete listing without a key as "the object is gone"
and delete their copy. Only a path that is really not there is 404 now
(a backend's FileNotFoundError, or exists() answering False for a backend
such as RamFS whose stat raises a plain OSError); a refusal is 403, any
other failure 500.
"""

from __future__ import annotations

import sys
import urllib.error
import urllib.request
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import reverse_serve  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402

TOKEN = "t0ken-for-unknown-is-not-gone"


class _Flaky(RamFsSession):
    """RamFS whose stat / list_dir of chosen paths fail like a remote that
    timed out or refused - the entries are there all the time."""

    def __init__(self):
        super().__init__(f"flaky-{id(self)}")
        self.stat_errors: dict[str, OSError] = {}
        self.list_errors: dict[str, OSError] = {}

    def stat(self, path):
        if path in self.stat_errors:
            raise self.stat_errors[path]
        return super().stat(path)

    def list_dir(self, path):
        if path in self.list_errors:
            raise self.list_errors[path]
        return super().list_dir(path)


def _write(b, path, data=b"x"):
    with b.open_write(path) as fh:
        fh.write(data)


@pytest.fixture
def backend():
    b = _Flaky()
    b.mkdir("/served")
    b.mkdir("/served/bkt")
    b.mkdir("/served/bkt/docs")
    b.mkdir("/served/bkt/sub")
    _write(b, "/served/bkt/docs/a.txt", b"alpha")
    _write(b, "/served/bkt/sub/b.txt", b"beta")
    _write(b, "/served/bkt/top.txt", b"top")
    yield b
    b.disconnect()


def _serve(backend, flavour):
    fn = reverse_serve.serve_webdav if flavour == "webdav" else reverse_serve.serve_s3
    return fn(backend, bind="127.0.0.1", port=0, root_path="/served", auth_token=TOKEN)


@pytest.fixture
def dav(backend):
    srv = _serve(backend, "webdav")
    yield srv
    srv.shutdown()


@pytest.fixture
def s3(backend):
    srv = _serve(backend, "s3")
    yield srv
    srv.shutdown()


def http(srv, method, path, headers=None):
    headers = dict(headers or {})
    headers.setdefault("Authorization", f"Bearer {TOKEN}")
    req = urllib.request.Request(srv.base_url + path, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _keys(body: bytes) -> list[str]:
    root = ET.fromstring(body)
    return sorted(e.text for e in root.iter() if e.tag.endswith("Key"))


# ------------------------------------------------------------------ happy / missing

def test_happy_a_missing_path_is_still_404_on_both_flavours(dav, s3):
    """RamFS raises a plain OSError for a missing path: exists() decides."""
    for method in ("GET", "HEAD", "PROPFIND"):
        assert http(dav, method, "/bkt/nope.txt")[0] == 404, method
    assert http(s3, "GET", "/bkt/nope.txt")[0] == 404
    assert http(s3, "HEAD", "/bkt/nope.txt")[0] == 404
    assert http(s3, "HEAD", "/nobucket")[0] == 404
    assert http(s3, "GET", "/nobucket?list-type=2")[0] == 404


def test_happy_a_complete_s3_listing_still_lists_every_key(s3):
    status, body = http(s3, "GET", "/bkt?list-type=2")
    assert status == 200
    assert _keys(body) == ["docs/a.txt", "sub/b.txt", "top.txt"]


# ------------------------------------------------------------------ sad: WebDAV

@pytest.mark.parametrize("method", ["GET", "HEAD", "PROPFIND"])
def test_sad_dav_a_stat_that_times_out_is_no_404(dav, backend, method):
    backend.stat_errors["/served/bkt/top.txt"] = TimeoutError("timed out")
    status, _ = http(dav, method, "/bkt/top.txt")
    assert status == 500, status


def test_sad_dav_a_refused_stat_is_403(dav, backend):
    backend.stat_errors["/served/bkt/top.txt"] = PermissionError("refused")
    assert http(dav, "GET", "/bkt/top.txt")[0] == 403


def test_sad_dav_propfind_of_an_unlistable_folder_is_no_empty_folder(dav, backend):
    backend.list_errors["/served/bkt/docs"] = TimeoutError("timed out")
    status, body = http(dav, "PROPFIND", "/bkt/docs", headers={"Depth": "1"})
    assert status == 500, (status, body[:200])


def test_sad_dav_propfind_of_a_folder_it_may_not_list_is_403(dav, backend):
    backend.list_errors["/served/bkt/docs"] = PermissionError("refused")
    assert http(dav, "PROPFIND", "/bkt/docs", headers={"Depth": "1"})[0] == 403


# ------------------------------------------------------------------ sad: S3

def test_sad_s3_get_and_head_object_with_a_failing_stat_are_no_nosuchkey(s3, backend):
    backend.stat_errors["/served/bkt/top.txt"] = TimeoutError("timed out")
    assert http(s3, "GET", "/bkt/top.txt")[0] == 500
    assert http(s3, "HEAD", "/bkt/top.txt")[0] == 500
    backend.stat_errors["/served/bkt/top.txt"] = PermissionError("refused")
    assert http(s3, "GET", "/bkt/top.txt")[0] == 403


def test_sad_s3_head_bucket_with_a_failing_stat_is_no_nosuchbucket(s3, backend):
    backend.stat_errors["/served/bkt"] = TimeoutError("timed out")
    assert http(s3, "HEAD", "/bkt")[0] == 500


def test_sad_s3_listing_with_an_unlistable_subfolder_is_an_error(s3, backend):
    backend.list_errors["/served/bkt/sub"] = TimeoutError("timed out")
    status, body = http(s3, "GET", "/bkt?list-type=2")
    assert status == 500, (status, body[:300])
    assert b"sub/b.txt" not in body


def test_sad_s3_listing_of_an_unlistable_bucket_is_no_empty_bucket(s3, backend):
    backend.list_errors["/served/bkt"] = PermissionError("refused")
    status, body = http(s3, "GET", "/bkt?list-type=2")
    assert status == 403, (status, body[:300])


# ------------------------------------------------------------------ edge

def test_edge_a_folder_that_vanished_during_the_s3_walk_is_skipped(s3, backend):
    """Listed by its parent, gone when the walk reaches it: it is gone,
    the rest of the listing is complete."""
    backend.list_errors["/served/bkt/sub"] = FileNotFoundError("gone")
    status, body = http(s3, "GET", "/bkt?list-type=2")
    assert status == 200
    assert _keys(body) == ["docs/a.txt", "top.txt"]


def test_edge_a_file_not_found_from_stat_is_404_without_asking_again(dav, backend):
    backend.stat_errors["/served/bkt/top.txt"] = FileNotFoundError("gone")
    assert http(dav, "GET", "/bkt/top.txt")[0] == 404
