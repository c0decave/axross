"""Fuzz: the OneDrive backend against a hostile Microsoft Graph endpoint.

A scripted ``requests`` adapter answers every Graph call: mutated JSON,
JSON of the wrong shape (a list, ``value: null``, entries that are not
objects, fields of the wrong type), absurd sizes and dates, traversal
names, error statuses with garbage bodies, a pagination link that loops,
dropped connections. Every call returns sane data or raises OSError.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest import mock

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz_testkit import check_contract, iterations, mutants  # noqa: E402
from requests_fuzz_adapter import mount  # noqa: E402

from core.onedrive_client import OneDriveSession  # noqa: E402

ITEM = {
    "id": "ID1",
    "name": "a.txt",
    "size": 5,
    "lastModifiedDateTime": "2024-01-15T10:30:00Z",
    "file": {"mimeType": "text/plain"},
}
FOLDER = {"id": "ID2", "name": "sub", "size": 0, "folder": {"childCount": 1}}
LISTING = {"value": [ITEM, FOLDER]}


class _Graph:
    def __init__(self) -> None:
        self.item: object = ITEM
        self.listing: object = LISTING
        self.content = b"hello"
        self.status = 200
        self.raise_exc: Exception | None = None

    @staticmethod
    def _body(obj) -> bytes:
        return obj if isinstance(obj, bytes) else json.dumps(obj).encode()

    def __call__(self, request):
        if self.raise_exc is not None:
            raise self.raise_exc
        url = request.url
        if url.endswith(":/content"):
            body = self.content
        elif any(
            k in url for k in ("children", "page=", "versions", "permissions", "/lists", "search")
        ):
            body = self._body(self.listing)
        else:
            body = self._body(self.item)
        return self.status, {"Content-Type": "application/json"}, body


@pytest.fixture(params=["personal", "sharepoint"])
def onedrive(request):
    graph = _Graph()
    s = OneDriveSession.__new__(OneDriveSession)
    s._http = requests.Session()
    mount(s._http, graph)
    s._access_token = "t"
    s._app = mock.Mock()
    s._app.get_accounts.return_value = [{"username": "u"}]
    s._app.acquire_token_silent.return_value = {"access_token": "t"}
    s._cache = mock.Mock(has_state_changed=False)
    s._drive_type = request.param
    s._site_id = "SITE" if request.param == "sharepoint" else None
    s._site_url = ""
    s._tenant_id = "common"
    s._scopes = []
    s._proxies = {}
    yield graph, s


def _ops(s):
    return {
        "list_dir": lambda: s.list_dir("/"),
        "stat": lambda: s.stat("/a.txt"),
        "is_dir": lambda: s.is_dir("/sub"),
        "exists": lambda: s.exists("/a.txt"),
        "open_read": lambda: s.open_read("/a.txt").read(),
        "remove": lambda: s.remove("/a.txt"),
        "rename": lambda: s.rename("/a.txt", "/sub/b.txt"),
        "list_versions": lambda: s.list_versions("/a.txt"),
        "disk_usage": lambda: s.disk_usage("/"),
        "checksum": lambda: s.checksum("/a.txt"),
        "share": lambda: s.share("/a.txt"),
        "permissions_list": lambda: s.permissions_list("/a.txt"),
    }


def _sharepoint_ops(s):
    return {
        "lists": lambda: s.lists(),
        "items": lambda: s.items("L1", limit=3),
        "search": lambda: s.search("q", limit=3),
    }


def _check_items(result) -> None:
    items = result if isinstance(result, list) else [result]
    for item in items:
        if hasattr(item, "name"):
            assert isinstance(item.name, str) and item.name
            assert isinstance(item.size, int) and not isinstance(item.size, bool)
            assert item.size >= 0


def _all_ops(s, ctx):
    ops = _ops(s)
    if s._drive_type == "sharepoint":
        ops.update(_sharepoint_ops(s))
    for name, op in ops.items():
        result = check_contract(op, (OSError,), timeout=10.0, context=f"{ctx} {name}")
        if name in ("list_dir", "stat"):
            _check_items(result)


def test_happy_listing(onedrive):
    _graph, s = onedrive
    assert [(i.name, i.is_dir, i.size) for i in s.list_dir("/")] == [
        ("a.txt", False, 5),
        ("sub", True, 0),
    ]
    assert s.stat("/a.txt").size == 5
    assert s.open_read("/a.txt").read() == b"hello"


HOSTILE = {
    "list-top": [ITEM],
    "string-top": "x",
    "null-top": None,
    "value-null": {"value": None},
    "value-object": {"value": {"a": 1}},
    "entries-not-objects": {"value": [1, "x", None, [ITEM]]},
    "name-types": {"value": [{**ITEM, "name": 5}, {**ITEM, "name": None}, {**ITEM, "name": ""}]},
    "size-types": {"value": [{**ITEM, "size": "5"}, {**ITEM, "size": -1}, {**ITEM, "size": 1e300}]},
    "size-bool": {"value": [{**ITEM, "size": True}]},
    "date-types": {
        "value": [{**ITEM, "lastModifiedDateTime": 5}, {**ITEM, "lastModifiedDateTime": []}]
    },
    "date-absurd": {"value": [{**ITEM, "lastModifiedDateTime": "99999-01-01T00:00:00Z"}]},
    "traversal": {"value": [{**ITEM, "name": "../../x"}, {**ITEM, "name": "a/b"}]},
    "nextlink-type": {"value": [ITEM], "@odata.nextLink": 5},
    "deep": b"[" * 100000 + b"]" * 100000,
    "bigint": b'{"value":[{"name":"a","size":' + b"9" * 5000 + b"}]}",
    "not-json": b"<html>hi</html>",
    "invalid-utf8": b'{"value":[{"name":"\xff\xfe"}]}',
    "empty": b"",
}


@pytest.mark.parametrize("body", list(HOSTILE.values()), ids=list(HOSTILE))
def test_sad_hostile_answers(onedrive, body):
    graph, s = onedrive
    graph.listing = body
    graph.item = body
    _all_ops(s, repr(body)[:60])


def test_sad_mutated_answers(onedrive):
    graph, s = onedrive
    corpus = [json.dumps(LISTING).encode(), json.dumps(ITEM).encode()]
    for n, body in enumerate(mutants(corpus, seed=0x4F44, per_entry=iterations(80))):
        graph.listing = body
        graph.item = body
        _all_ops(s, f"mutant {n}")


@pytest.mark.parametrize("status", [400, 404, 429, 500, 503, 599])
def test_sad_error_status_with_garbage(onedrive, status):
    graph, s = onedrive
    graph.status = status
    graph.item = graph.listing = b"\xff\xfe<garbage>"
    _all_ops(s, f"status {status}")


@pytest.mark.parametrize(
    "exc",
    [requests.ConnectionError("reset"), requests.ReadTimeout("slow"), requests.TooManyRedirects()],
    ids=["reset", "timeout", "redirects"],
)
def test_sad_transport_failures(onedrive, exc):
    graph, s = onedrive
    graph.raise_exc = exc
    _all_ops(s, type(exc).__name__)


def test_edge_pagination_link_that_loops(onedrive):
    graph, s = onedrive
    graph.listing = {
        "value": [ITEM],
        "@odata.nextLink": "https://graph.microsoft.com/v1.0/x?page=1",
    }
    result = check_contract(lambda: s.list_dir("/"), (OSError,), timeout=10.0)
    assert isinstance(result, OSError)
