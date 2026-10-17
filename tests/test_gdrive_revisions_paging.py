"""GDrive list_versions() follows nextPageToken.

revisions().list was asked once (pageSize=200) and its nextPageToken
never followed: Drive lists revisions oldest first, so a file with more
revisions than one page lost the NEWEST ones, and the newest of page 1
was labelled the current revision.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.gdrive_client import GDriveSession  # noqa: E402


def _rev(i: int) -> dict:
    when = f"2026-01-01T{i // 3600:02d}:{i // 60 % 60:02d}:{i % 60:02d}Z"
    return {"id": f"r{i}", "modifiedTime": when}


class _Req:
    def __init__(self, answer):
        self.answer = answer

    def execute(self):
        if isinstance(self.answer, BaseException):
            raise self.answer
        return self.answer


class _Revisions:
    def __init__(self, pages):
        self.pages = pages
        self.asked: list[dict] = []

    def list(self, **kw):
        self.asked.append(kw)
        return _Req(self.pages[kw.get("pageToken")])


def _session(pages) -> tuple[GDriveSession, _Revisions]:
    revs = _Revisions(pages)
    s = GDriveSession.__new__(GDriveSession)
    s._service = type("Svc", (), {"revisions": lambda self: revs})()
    s._path_cache = {"/": "root", "/f.bin": "FID"}
    return s, revs


def test_happy_every_page_is_read_and_the_newest_is_current():
    pages = {
        None: {"revisions": [_rev(i) for i in range(200)], "nextPageToken": "p2"},
        "p2": {"revisions": [_rev(i) for i in range(200, 250)]},
    }
    s, revs = _session(pages)
    out = s.list_versions("/f.bin")
    assert len(out) == 250
    assert [v.version_id for v in out if v.is_current] == ["r249"]
    assert out[0].version_id == "r249"
    assert [kw.get("pageToken") for kw in revs.asked] == [None, "p2"]
    assert all("nextPageToken" in kw["fields"] for kw in revs.asked)


# A failed listing stays what it was before: logged, and no versions -
# never the part that was read, whose newest entry is not the current one.


def test_sad_a_repeating_page_token_ends_instead_of_paging_forever(caplog):
    pages = {
        None: {"revisions": [_rev(0)], "nextPageToken": "same"},
        "same": {"revisions": [_rev(1)], "nextPageToken": "same"},
    }
    s, revs = _session(pages)
    assert s.list_versions("/f.bin") == []
    assert len(revs.asked) == 2
    assert "page token" in caplog.text


def test_sad_a_failing_second_page_returns_no_partial_list():
    pages = {
        None: {"revisions": [_rev(0)], "nextPageToken": "p2"},
        "p2": OSError("503 backendError"),
    }
    s, _ = _session(pages)
    assert s.list_versions("/f.bin") == []


def test_edge_a_single_page_is_one_request():
    s, revs = _session({None: {"revisions": [_rev(0), _rev(1)]}})
    out = s.list_versions("/f.bin")
    assert [v.version_id for v in out] == ["r1", "r0"]
    assert [v.is_current for v in out] == [True, False]
    assert len(revs.asked) == 1
