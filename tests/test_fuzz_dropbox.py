"""Fuzz: the Dropbox backend against a hostile Dropbox API endpoint.

The real ``dropbox`` SDK runs on a ``requests`` session whose transport is
a scripted adapter: mutated JSON, JSON of the wrong shape, every error
status the SDK maps to its own exception classes (400 / 401 / 409 / 429 /
500 / 503), garbage bodies, transport failures, and a ``has_more`` cursor
that never ends. Every call returns sane data or raises OSError.
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

from fuzz_testkit import check_contract, iterations, mutants  # noqa: E402
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
    "path_lower": "/a.txt",
    "path_display": "/a.txt",
    "content_hash": "0" * 64,
}
FOLDER = {
    ".tag": "folder",
    "name": "sub",
    "id": "id:s",
    "path_lower": "/sub",
    "path_display": "/sub",
}
LISTING = {"entries": [FILE, FOLDER], "cursor": "c1", "has_more": False}
REVISIONS = {"is_deleted": False, "entries": [FILE]}
USAGE = {"used": 10, "allocation": {".tag": "individual", "allocated": 100}}


class _Api:
    def __init__(self) -> None:
        self.answers: dict[str, object] = {
            "list_folder": LISTING,
            "list_folder/continue": LISTING,
            "get_metadata": FILE,
            "list_revisions": REVISIONS,
            "get_space_usage": USAGE,
        }
        self.override: object = None
        self.status = 200
        self.raise_exc: Exception | None = None

    def __call__(self, request):
        if self.raise_exc is not None:
            raise self.raise_exc
        url = request.url
        if url.endswith("/files/download"):
            if self.status != 200:
                return self.status, {}, b"\xff garbage"
            md = self.override if self.override is not None else FILE
            arg = md if isinstance(md, bytes) else json.dumps(md).encode()
            return 200, {"Dropbox-API-Result": arg.decode("latin-1")}, b"hello"
        route = url.split("/2/", 1)[1].split("/", 1)[1]
        body = self.override if self.override is not None else self.answers.get(route, {})
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        return self.status, {"Content-Type": "application/json"}, raw


@pytest.fixture
def dbx():
    api = _Api()
    sess = requests.Session()
    mount(sess, api)
    s = DropboxSession.__new__(DropboxSession)
    s._dbx = dropbox.Dropbox(
        oauth2_access_token="t", session=sess, max_retries_on_error=0, max_retries_on_rate_limit=0
    )
    s._proxies = {}
    yield api, s


def _ops(s):
    return {
        "list_dir": lambda: s.list_dir("/"),
        "stat": lambda: s.stat("/a.txt"),
        "is_dir": lambda: s.is_dir("/sub"),
        "exists": lambda: s.exists("/a.txt"),
        "open_read": lambda: s.open_read("/a.txt").read(),
        "mkdir": lambda: s.mkdir("/new"),
        "remove": lambda: s.remove("/a.txt"),
        "rename": lambda: s.rename("/a.txt", "/b.txt"),
        "list_versions": lambda: s.list_versions("/a.txt"),
        "disk_usage": lambda: s.disk_usage("/"),
    }


def _all_ops(s, ctx):
    for name, op in _ops(s).items():
        result = check_contract(op, (OSError,), timeout=10.0, context=f"{ctx} {name}")
        if name in ("list_dir", "stat"):
            items = result if isinstance(result, list) else [result]
            for item in items:
                if hasattr(item, "name"):
                    assert isinstance(item.name, str) and isinstance(item.size, int)


def test_happy_listing(dbx):
    _api, s = dbx
    assert sorted((i.name, i.is_dir) for i in s.list_dir("/")) == [("a.txt", False), ("sub", True)]
    assert s.stat("/a.txt").size == 5
    assert s.open_read("/a.txt").read() == b"hello"


@pytest.mark.parametrize("status", [400, 401, 403, 409, 429, 500, 503, 599])
def test_sad_error_statuses(dbx, status):
    api, s = dbx
    api.status = status
    api.override = b'{"error_summary": "x", "error": {".tag": "other"}}'
    _all_ops(s, f"status {status}")


HOSTILE = {
    "list-top": [FILE],
    "null": None,
    "entries-null": {"entries": None, "cursor": "c", "has_more": False},
    "entry-junk": {"entries": [1, "x", {".tag": "nope"}], "cursor": "c", "has_more": False},
    "size-types": {"entries": [{**FILE, "size": "5"}], "cursor": "c", "has_more": False},
    "negative-size": {"entries": [{**FILE, "size": -1}], "cursor": "c", "has_more": False},
    "date-junk": {
        "entries": [{**FILE, "server_modified": "nope"}],
        "cursor": "c",
        "has_more": False,
    },
    "traversal": {"entries": [{**FILE, "name": "../../x"}], "cursor": "c", "has_more": False},
    "deep": b"[" * 100000 + b"]" * 100000,
    "bigint": b'{"entries": [], "cursor": "c", "has_more": false, "x": ' + b"9" * 5000 + b"}",
    "not-json": b"<html>",
    "invalid-utf8": b'{"entries": [{"name": "\xff"}]}',
    "empty": b"",
}


@pytest.mark.parametrize("body", list(HOSTILE.values()), ids=list(HOSTILE))
def test_sad_hostile_answers(dbx, body):
    api, s = dbx
    api.override = body
    _all_ops(s, repr(body)[:60])


def test_sad_mutated_answers(dbx):
    api, s = dbx
    corpus = [json.dumps(LISTING).encode(), json.dumps(FILE).encode()]
    for n, body in enumerate(mutants(corpus, seed=0x4442, per_entry=iterations(80))):
        api.override = body
        _all_ops(s, f"mutant {n}")


@pytest.mark.parametrize(
    "exc",
    [requests.ConnectionError("reset"), requests.ReadTimeout("slow")],
    ids=["reset", "timeout"],
)
def test_sad_transport_failures(dbx, exc):
    api, s = dbx
    api.raise_exc = exc
    _all_ops(s, type(exc).__name__)


def test_edge_cursor_that_never_ends(dbx):
    api, s = dbx
    api.answers["list_folder"] = {**LISTING, "has_more": True}
    api.answers["list_folder/continue"] = {**LISTING, "has_more": True}
    result = check_contract(lambda: s.list_dir("/"), (OSError,), timeout=10.0)
    assert isinstance(result, OSError)
