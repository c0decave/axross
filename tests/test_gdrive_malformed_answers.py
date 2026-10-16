"""A Drive API answer of the wrong shape is an OSError, not a crash or a hang.

The API calls were wrapped (``except Exception -> OSError``) but what
they returned was read unchecked: ``int(f.get("size", 0))`` raised
ValueError for a size that is no number, ``f["name"]`` / ``f["id"]`` /
``files[0]["id"]`` KeyError, ``resp.get`` on a JSON list AttributeError,
``_parse_time`` AttributeError for a non-string time, a repeating
``nextPageToken`` paged forever, and ``list_versions`` sorted aware dates
next to a naive ``datetime.min`` (TypeError). ``share`` and
``permissions_list`` let googleapiclient's HttpError through unwrapped,
and ``checksum`` labelled the md5 fallback with the algorithm that was
asked for. Found by tests/test_fuzz_gdrive.py.
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
from googleapiclient.discovery import build  # noqa: E402

from core.gdrive_client import GDriveSession  # noqa: E402

FILE = {"id": "F1", "name": "a.txt", "mimeType": "text/plain", "size": "5"}


class _Http:
    def __init__(self, answer, status: int = 200) -> None:
        self.answer, self.status = answer, status

    def request(self, uri, method="GET", body=None, headers=None, **_kwargs):
        answer = self.answer(uri) if callable(self.answer) else self.answer
        raw = answer if isinstance(answer, bytes) else json.dumps(answer).encode()
        resp = httplib2.Response({"status": str(self.status), "content-type": "application/json"})
        return resp, raw


def _session(answer, status: int = 200) -> GDriveSession:
    s = GDriveSession.__new__(GDriveSession)
    s._service = build("drive", "v3", http=_Http(answer, status), static_discovery=True)
    s._path_cache = {"/": "root"}
    return s


def test_happy_listing_reads_string_sizes():
    items = _session({"files": [FILE]}).list_dir("/")
    assert [(i.name, i.size) for i in items] == [("a.txt", 5)]


@pytest.mark.parametrize(
    "answer",
    [[FILE], {"files": None}, {"files": {"a": 1}}],
    ids=["list", "files-null", "files-object"],
)
def test_sad_listing_of_the_wrong_shape_is_an_oserror(answer):
    with pytest.raises(OSError):
        _session(answer).list_dir("/")


def test_sad_path_lookup_without_an_id_is_an_oserror():
    with pytest.raises(OSError):
        _session({"files": [{"name": "a.txt"}]}).stat("/a.txt")


def test_edge_wrong_typed_fields_get_safe_defaults():
    entries = [
        1,
        {"name": "noid"},
        {**FILE, "name": 5},
        {**FILE, "name": "junk-size", "size": "abc"},
        {**FILE, "name": "neg", "size": "-1"},
        {**FILE, "name": "huge", "size": "9" * 5000},
        {**FILE, "name": "time", "modifiedTime": 5},
    ]
    items = {i.name: i for i in _session({"files": entries}).list_dir("/")}
    assert set(items) == {"junk-size", "neg", "huge", "time"}
    assert [items[n].size for n in ("junk-size", "neg", "huge", "time")] == [0, 0, 0, 5]
    assert items["time"].modified.timestamp() == 0


def test_edge_repeating_page_token_fails_instead_of_paging_forever():
    s = _session({"files": [FILE], "nextPageToken": "same"})
    with pytest.raises(OSError, match="page token"):
        s.list_dir("/")


def test_edge_versions_with_and_without_dates_sort():
    def answer(uri):
        if "/revisions" in uri:
            return {
                "revisions": [
                    {"id": "1", "modifiedTime": "2024-01-01T00:00:00Z", "size": "3"},
                    {"id": "2"},
                    "junk",
                ]
            }
        return {"files": [FILE]}

    out = _session(answer).list_versions("/a.txt")
    assert [v.version_id for v in out] == ["1", "2"]
    assert [v.size for v in out] == [3, 0]


def test_sad_share_http_error_is_an_oserror():
    def answer(uri):
        return {"files": [FILE]} if "/files?" in uri else {"error": {"code": 403}}

    s = _session(answer)
    s._service = build(
        "drive", "v3", http=_Http({"error": {"code": 403}}, 403), static_discovery=True
    )
    s._path_cache["/a.txt"] = "F1"
    with pytest.raises(OSError):
        s.share("/a.txt")
    with pytest.raises(OSError):
        s.permissions_list("/a.txt")


def test_edge_checksum_fallback_is_labelled_md5():
    def answer(uri):
        if "/files?" in uri:
            return {"files": [FILE]}
        return {"md5Checksum": "abc"}

    assert _session(answer).checksum("/a.txt", "sha256") == "md5:abc"


def test_happy_checksum_of_the_requested_algorithm():
    def answer(uri):
        if "/files?" in uri:
            return {"files": [FILE]}
        return {"sha256Checksum": "def", "md5Checksum": "abc"}

    assert _session(answer).checksum("/a.txt", "sha256") == "sha256:def"
