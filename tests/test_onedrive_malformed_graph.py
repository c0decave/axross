"""A Graph answer of the wrong shape is an OSError, not a crash or a hang.

Every Graph helper returned ``resp.json()`` as is and every caller
called ``.get()`` on it: a JSON list or string raised AttributeError,
``"value": null`` TypeError, a field of the wrong type AttributeError
(``lastModifiedDateTime.replace``) or a FileItem with a str size; nesting
deeper than the C stack (RecursionError) and an integer above the digit
limit (ValueError) escaped ``resp.json()``. A ``@odata.nextLink`` that
repeats kept ``list_dir`` paging forever, and ``list_versions`` sorted
aware dates next to the naive ``datetime.min`` fallback (TypeError).
Found by tests/test_fuzz_onedrive.py.
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

from requests_fuzz_adapter import mount  # noqa: E402

from core.onedrive_client import OneDriveSession  # noqa: E402


def _session(responder) -> OneDriveSession:
    s = OneDriveSession.__new__(OneDriveSession)
    s._http = requests.Session()
    mount(s._http, responder)
    s._access_token = "t"
    s._app = mock.Mock()
    s._app.get_accounts.return_value = [{"username": "u"}]
    s._app.acquire_token_silent.return_value = {"access_token": "t"}
    s._cache = mock.Mock(has_state_changed=False)
    s._drive_type = "personal"
    s._site_id = None
    s._site_url = ""
    s._tenant_id = "common"
    s._scopes = []
    s._proxies = {}
    return s


def _answer(obj):
    body = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
    return lambda request: (200, {"Content-Type": "application/json"}, body)


def test_happy_listing_follows_distinct_pages():
    pages = {
        "children": {"value": [{"name": "a", "size": 1}], "@odata.nextLink": "https://g/x?p=2"},
        "p=2": {"value": [{"name": "b", "size": 2, "folder": {}}]},
    }

    def responder(request):
        key = "p=2" if "p=2" in request.url else "children"
        return 200, {}, json.dumps(pages[key]).encode()

    items = _session(responder).list_dir("/")
    assert [(i.name, i.size, i.is_dir) for i in items] == [("a", 1, False), ("b", 2, True)]


@pytest.mark.parametrize(
    "body",
    [
        [{"name": "a"}],
        "x",
        None,
        {"value": None},
        {"value": {"a": 1}},
        b"[" * 100000,
        b'{"a":' + b"9" * 5000 + b"}",
    ],
    ids=["list", "string", "null", "value-null", "value-object", "deep", "bigint"],
)
def test_sad_answer_of_the_wrong_shape_is_an_oserror(body):
    s = _session(_answer(body))
    with pytest.raises(OSError):
        s.list_dir("/")
    if not (isinstance(body, dict) and "value" in body):
        with pytest.raises(OSError):
            s.stat("/a")


def test_edge_wrong_typed_fields_get_safe_defaults():
    entries = [
        1,
        None,
        {"name": 5},
        {"name": "ok", "size": "5", "lastModifiedDateTime": 7},
        {"name": "neg", "size": -3},
        {"name": "flag", "size": True},
    ]
    items = {i.name: i for i in _session(_answer({"value": entries})).list_dir("/")}
    assert set(items) == {"ok", "neg", "flag"}
    assert [items[n].size for n in ("ok", "neg", "flag")] == [0, 0, 0]


def test_edge_repeating_next_link_fails_instead_of_paging_forever():
    s = _session(_answer({"value": [{"name": "a"}], "@odata.nextLink": "https://g/x?p=1"}))
    with pytest.raises(OSError, match="repeats"):
        s.list_dir("/")


def test_edge_versions_with_and_without_dates_sort():
    versions = {
        "value": [
            {"id": "1", "lastModifiedDateTime": "2024-01-01T00:00:00Z", "size": 3},
            {"id": "2"},
            {"id": "3", "lastModifiedDateTime": 5, "size": "x"},
            "junk",
        ]
    }
    out = _session(_answer(versions)).list_versions("/a.txt")
    assert [v.version_id for v in out][0] == "1"
    assert {v.version_id for v in out} == {"1", "2", "3"}
    assert all(v.size >= 0 for v in out)


def test_sad_rename_parent_without_an_id():
    def responder(request):
        if request.method == "GET" and "sub" in request.url:
            return 200, {}, b'{"name": "sub"}'
        return 200, {}, b'{"id": "ID1"}'

    with pytest.raises(OSError, match="item ID"):
        _session(responder).rename("/a.txt", "/sub/b.txt")
