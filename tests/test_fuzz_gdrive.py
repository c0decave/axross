"""Fuzz: the Google Drive backend against a hostile Drive API endpoint.

The real ``googleapiclient`` service (static discovery document, no
network) runs on a fake ``http`` object that answers every call: mutated
JSON, JSON of the wrong shape, fields of the wrong type (Drive sends
sizes as strings), absurd sizes and dates, traversal names, error
statuses with garbage bodies, a page token that loops. Every call returns
sane data or raises OSError.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("googleapiclient")
import httplib2  # noqa: E402
from fuzz_testkit import check_contract, iterations, mutants  # noqa: E402
from googleapiclient.discovery import build  # noqa: E402

from core.gdrive_client import GDriveSession  # noqa: E402

FOLDER_MIME = "application/vnd.google-apps.folder"
FILE = {
    "id": "F1",
    "name": "a.txt",
    "mimeType": "text/plain",
    "size": "5",
    "modifiedTime": "2024-01-02T03:04:05.000Z",
}
FOLDER = {"id": "D1", "name": "sub", "mimeType": FOLDER_MIME}
LISTING = {"files": [FILE, FOLDER]}
REVISIONS = {"revisions": [{"id": "r1", "modifiedTime": "2024-01-02T03:04:05Z", "size": "5"}]}


class FakeHttp:
    """The ``http`` object googleapiclient calls ``request()`` on."""

    def __init__(self) -> None:
        self.listing: object = LISTING
        self.meta: object = FILE
        self.revisions: object = REVISIONS
        self.content = b"hello"
        self.status = 200

    def _json(self, obj) -> bytes:
        return obj if isinstance(obj, bytes) else json.dumps(obj).encode()

    def request(self, uri, method="GET", body=None, headers=None, **_kwargs):
        if "alt=media" in uri:
            body_out = self.content
            hdrs = {"content-length": str(len(body_out))}
        elif "/revisions" in uri:
            body_out, hdrs = self._json(self.revisions), {}
        elif "/files?" in uri or uri.endswith("/files"):
            body_out, hdrs = self._json(self.listing), {}
        else:
            body_out, hdrs = self._json(self.meta), {}
        resp = httplib2.Response(
            {"status": str(self.status), "content-type": "application/json", **hdrs}
        )
        return resp, body_out


@pytest.fixture
def gdrive():
    http = FakeHttp()
    s = GDriveSession.__new__(GDriveSession)
    s._service = build("drive", "v3", http=http, static_discovery=True)
    s._path_cache = {"/": "root"}
    yield http, s


def _ops(s):
    def fresh(fn):
        def run():
            s._path_cache = {"/": "root"}
            return fn()

        return run

    return {
        "list_dir": fresh(lambda: s.list_dir("/")),
        "list_sub": fresh(lambda: s.list_dir("/sub")),
        "stat": fresh(lambda: s.stat("/a.txt")),
        "is_dir": fresh(lambda: s.is_dir("/sub")),
        "exists": fresh(lambda: s.exists("/a.txt")),
        "open_read": fresh(lambda: s.open_read("/a.txt").read()),
        "mkdir": fresh(lambda: s.mkdir("/new")),
        "list_versions": fresh(lambda: s.list_versions("/a.txt")),
        "disk_usage": fresh(lambda: s.disk_usage("/")),
        "checksum": fresh(lambda: s.checksum("/a.txt")),
        "share": fresh(lambda: s.share("/a.txt")),
        "permissions_list": fresh(lambda: s.permissions_list("/a.txt")),
    }


def _all_ops(s, ctx):
    for name, op in _ops(s).items():
        result = check_contract(op, (OSError,), timeout=10.0, context=f"{ctx} {name}")
        if name in ("list_dir", "list_sub", "stat"):
            for item in result if isinstance(result, list) else [result]:
                if hasattr(item, "name"):
                    assert isinstance(item.name, str) and item.name
                    assert isinstance(item.size, int) and item.size >= 0


def test_happy_listing(gdrive):
    _http, s = gdrive
    assert sorted((i.name, i.is_dir, i.size) for i in s.list_dir("/")) == [
        ("a.txt", False, 5),
        ("sub", True, 0),
    ]
    assert s.open_read("/a.txt").read() == b"hello"


HOSTILE = {
    "list-top": [FILE],
    "null": None,
    "files-null": {"files": None},
    "files-object": {"files": {"a": 1}},
    "entry-junk": {"files": [1, "x", None, {}]},
    "name-types": {"files": [{**FILE, "name": 5}, {**FILE, "name": None}]},
    "id-types": {"files": [{**FILE, "id": 5}, {**FILE, "id": None}]},
    "size-junk": {"files": [{**FILE, "size": "abc"}, {**FILE, "size": "-1"}, {**FILE, "size": []}]},
    "size-huge": {"files": [{**FILE, "size": "9" * 5000}]},
    "date-types": {"files": [{**FILE, "modifiedTime": 5}, {**FILE, "modifiedTime": "nope"}]},
    "traversal": {"files": [{**FILE, "name": "../../x"}, {**FILE, "name": "a/b"}]},
    "token-type": {"files": [FILE], "nextPageToken": 5},
    "deep": b"[" * 100000 + b"]" * 100000,
    "not-json": b"<html>",
    "invalid-utf8": b'{"files": [{"name": "\xff"}]}',
    "empty": b"",
}


@pytest.mark.parametrize("body", list(HOSTILE.values()), ids=list(HOSTILE))
def test_sad_hostile_answers(gdrive, body):
    http, s = gdrive
    http.listing = http.meta = http.revisions = body
    _all_ops(s, repr(body)[:60])


def test_sad_mutated_answers(gdrive):
    http, s = gdrive
    corpus = [json.dumps(LISTING).encode(), json.dumps(FILE).encode()]
    for n, body in enumerate(mutants(corpus, seed=0x4744, per_entry=iterations(60))):
        http.listing = http.meta = http.revisions = body
        _all_ops(s, f"mutant {n}")


@pytest.mark.parametrize("status", [400, 401, 403, 404, 429, 500, 503])
def test_sad_error_statuses(gdrive, status):
    http, s = gdrive
    http.status = status
    http.listing = http.meta = http.revisions = b"\xff<garbage>"
    _all_ops(s, f"status {status}")


def test_edge_page_token_that_loops(gdrive):
    http, s = gdrive
    http.listing = {"files": [FILE], "nextPageToken": "same"}
    result = check_contract(lambda: s.list_dir("/"), (OSError,), timeout=10.0)
    assert isinstance(result, OSError)
