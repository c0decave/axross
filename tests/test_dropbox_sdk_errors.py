"""Dropbox SDK failures other than ApiError are OSError.

DropboxSession caught only ApiError around SDK calls. A 500 / 503
(InternalServerError), 429 (RateLimitError), 400 (BadInputError), an
answer stone could not validate (ValidationError), a garbage body
(JSONDecodeError, UnicodeDecodeError, TypeError, RecursionError) and
the SDK's own ``assert`` on an error answer's content type all escaped
list_dir / stat / open_read / is_dir / exists to callers that handle
OSError. A ``has_more`` answer that repeats its cursor kept list_dir
paging forever. Found by tests/test_fuzz_dropbox.py.
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


def _json(status, obj, content_type="application/json"):
    body = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
    return lambda request: (status, {"Content-Type": content_type}, body)


def test_happy_listing():
    s = _session(_json(200, {"entries": [FILE], "cursor": "c", "has_more": False}))
    assert [(i.name, i.size) for i in s.list_dir("/")] == [("a.txt", 5)]


@pytest.mark.parametrize("status", [400, 429, 500, 503])
def test_sad_error_status_is_an_oserror(status):
    s = _session(_json(status, {"error_summary": "x", "error": {".tag": "other"}}))
    for op in (lambda: s.list_dir("/"), lambda: s.stat("/a.txt"), lambda: s.open_read("/a")):
        with pytest.raises(OSError):
            op()


@pytest.mark.parametrize(
    "body",
    [b"<html>", b"[" * 100000, b'{"entries": [1], "cursor": "c", "has_more": false}', b"\xff"],
    ids=["html", "deep", "junk-entry", "invalid-utf8"],
)
def test_sad_garbage_answer_is_an_oserror(body):
    s = _session(_json(200, body))
    with pytest.raises(OSError):
        s.list_dir("/")


def test_edge_unknown_answer_is_not_a_no():
    s = _session(_json(503, {"error_summary": "x"}))
    with pytest.raises(OSError):
        s.is_dir("/a")
    with pytest.raises(OSError):
        s.exists("/a")


def test_edge_not_found_still_reads_as_no():
    error = {
        "error_summary": "path/not_found/",
        "error": {".tag": "path", "path": {".tag": "not_found"}},
    }
    s = _session(_json(409, error))
    assert s.exists("/a") is False
    assert s.is_dir("/a") is False


def test_edge_repeating_cursor_fails_instead_of_paging_forever():
    s = _session(_json(200, {"entries": [FILE], "cursor": "same", "has_more": True}))
    with pytest.raises(OSError, match="cursor"):
        s.list_dir("/")


def test_edge_error_answer_without_content_type():
    s = _session(lambda request: (401, {}, b"no"))
    with pytest.raises(OSError):
        s.stat("/a.txt")
