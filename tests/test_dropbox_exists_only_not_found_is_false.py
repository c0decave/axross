"""Dropbox exists() and is_dir() say False only for "not found".

Both read every ApiError as "no". The SDK raises ApiError for each route
error answer (HTTP 403 / 404 / 409), and files/get_metadata answers with
more than path/not_found: restricted_content, locked, malformed_path,
other. server_side_copy(overwrite=False) and the transfer worker's
no-clobber check take False from exists() as the go-ahead to write, so a
path Dropbox only refused to describe was treated as absent. Only
path/not_found (and path/not_folder: a file where a folder of the path
should be) means False now; every other route error is an OSError.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

dropbox = pytest.importorskip("dropbox")

from requests_fuzz_adapter import mount  # noqa: E402

from core.dropbox_client import DropboxSession  # noqa: E402

FILE = {
    ".tag": "file",
    "name": "a.txt",
    "id": "id:a",
    "client_modified": "2024-01-02T03:04:05Z",
    "server_modified": "2024-01-02T03:04:05Z",
    "rev": "0123456789abcdef",
    "size": 5,
}
FOLDER = {".tag": "folder", "name": "dir", "id": "id:d"}


def _session(responder) -> DropboxSession:
    sess = requests.Session()
    mount(sess, responder)
    s = DropboxSession.__new__(DropboxSession)
    s._dbx = dropbox.Dropbox(
        oauth2_access_token="t",
        session=sess,
        max_retries_on_error=0,
        max_retries_on_rate_limit=0,
    )
    s._proxies = {}
    return s


def _answer(status, obj):
    body = json.dumps(obj).encode()
    return lambda request: (status, {"Content-Type": "application/json"}, body)


def _lookup_error(tag: str, status: int = 409):
    return _answer(
        status,
        {"error_summary": f"path/{tag}/", "error": {".tag": "path", "path": {".tag": tag}}},
    )


def _store(request):
    path = json.loads(request.body)["path"]
    if path == "/a.txt":
        return 200, {"Content-Type": "application/json"}, json.dumps(FILE).encode()
    if path == "/dir":
        return 200, {"Content-Type": "application/json"}, json.dumps(FOLDER).encode()
    return _lookup_error("not_found")(request)


def test_happy_present_and_absent():
    s = _session(_store)
    assert s.exists("/a.txt") is True
    assert s.exists("/dir") is True
    assert s.is_dir("/dir") is True
    assert s.is_dir("/a.txt") is False
    assert s.exists("/missing") is False
    assert s.is_dir("/missing") is False


@pytest.mark.parametrize(
    "responder",
    [
        _lookup_error("restricted_content"),
        _lookup_error("locked"),
        _lookup_error("malformed_path"),
        _lookup_error("a_tag_this_sdk_does_not_know"),
        _lookup_error("restricted_content", status=403),
    ],
    ids=["restricted", "locked", "malformed", "other", "403"],
)
def test_sad_a_refused_lookup_is_an_oserror_not_absent(responder):
    s = _session(responder)
    with pytest.raises(OSError, match="a.txt"):
        s.exists("/a.txt")
    with pytest.raises(OSError, match="a.txt"):
        s.is_dir("/a.txt")


def test_sad_no_clobber_copy_keeps_a_locked_target():
    from core.server_ops import server_side_copy

    copied = []

    def api(request):
        if request.url.endswith("/files/copy_v2"):
            copied.append(json.loads(request.body))
            return 200, {"Content-Type": "application/json"}, b"{}"
        return _lookup_error("locked")(request)

    s = _session(api)
    with pytest.raises(OSError):
        server_side_copy(s, "/a.txt", "/b.txt", overwrite=False)
    assert copied == []


def test_edge_not_folder_on_the_way_means_absent():
    """A file where the path needs a folder: nothing is at that path."""
    s = _session(_lookup_error("not_folder"))
    assert s.exists("/a.txt/b") is False
    assert s.is_dir("/a.txt/b") is False


def test_edge_root_needs_no_request():
    def boom(request):
        raise AssertionError("no request for the root")

    s = _session(boom)
    assert s.exists("/") is True
    assert s.is_dir("/") is True
