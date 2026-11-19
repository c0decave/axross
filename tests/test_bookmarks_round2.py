"""bookmarks.json: a file that cannot be read now is not set aside or
written over; a Smart Folder nested absurdly deep is dropped at load.

Review 2026-11-20 (bookmarks round 2), each reproduced before the fix:

* A read error of the file (EACCES, an EIO of a network home) at load
  was handled like a file that is no JSON: it was moved aside as
  ``bookmarks.json.unreadable-...`` and the user started with no
  bookmarks - json_store's rule is the opposite (unreadable: write
  nothing). And a save while the file could not be read wrote this
  manager's tree over it. Now a read error leaves the file where it is,
  and a save refuses (reported like any failed save) instead of writing.
* A Smart Folder search nested some 900 levels passed json.loads and the
  64 KiB check, then made every save raise RecursionError (asdict), with
  the tree already in memory. A search nested deeper than
  MAX_SEARCH_DEPTH is dropped at load like any damaged entry.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import bookmarks as BM  # noqa: E402


@pytest.fixture
def bfile(tmp_path, monkeypatch):
    path = tmp_path / "bookmarks.json"
    monkeypatch.setattr(BM, "BOOKMARKS_FILE", path)
    return path


def _unreadable(monkeypatch, path: Path):
    real_text, real_bytes = Path.read_text, Path.read_bytes

    def text(self, *a, **kw):
        if self == path:
            raise PermissionError(13, "Permission denied")
        return real_text(self, *a, **kw)

    def raw(self, *a, **kw):
        if self == path:
            raise PermissionError(13, "Permission denied")
        return real_bytes(self, *a, **kw)

    monkeypatch.setattr(Path, "read_text", text)
    monkeypatch.setattr(Path, "read_bytes", raw)


def test_sad_a_read_error_at_load_leaves_the_file_where_it_is(bfile, monkeypatch):
    bfile.write_text(json.dumps([{"name": "a", "path": "/a"}]), encoding="utf-8")
    with monkeypatch.context() as patch:
        _unreadable(patch, bfile)
        manager = BM.BookmarkManager()
    assert manager.all() == []
    assert [p.name for p in bfile.parent.iterdir() if "unreadable" in p.name] == []
    assert json.loads(bfile.read_text(encoding="utf-8"))[0]["name"] == "a"


def test_sad_a_save_while_the_file_cannot_be_read_does_not_write_over_it(bfile, monkeypatch):
    bfile.write_text(json.dumps([{"name": "a", "path": "/a"}]), encoding="utf-8")
    failures = []
    monkeypatch.setattr("core.json_store._SAVE_FAILURE_LISTENERS",
                        [lambda what, text: failures.append(what)])
    with monkeypatch.context() as patch:
        _unreadable(patch, bfile)
        manager = BM.BookmarkManager()
        manager.add(BM.Bookmark(name="b", path="/b"))
    assert failures == ["bookmarks"]
    assert [m["name"] for m in json.loads(bfile.read_text(encoding="utf-8"))] == ["a"]


def test_happy_once_readable_again_the_next_save_keeps_both(bfile, monkeypatch):
    bfile.write_text(json.dumps([{"name": "a", "path": "/a"}]), encoding="utf-8")
    with monkeypatch.context() as patch:
        _unreadable(patch, bfile)
        manager = BM.BookmarkManager()
    manager.add(BM.Bookmark(name="b", path="/b"))
    assert sorted(m["name"] for m in json.loads(bfile.read_text(encoding="utf-8"))) == ["a", "b"]


def test_sad_a_search_nested_too_deep_is_dropped_and_saves_still_work(bfile):
    depth = 900
    search = "{\"n\":" * depth + "1" + "}" * depth
    bfile.write_text('[{"name":"s","path":"search:1","backend_name":"Smart Folder","search":'
                     + search + '}, {"name":"keep","path":"/k"}]', encoding="utf-8")
    manager = BM.BookmarkManager()
    assert [b.name for b in manager.all()] == ["keep"]
    manager.add(BM.Bookmark(name="new", path="/new"))
    assert {m["name"] for m in json.loads(bfile.read_text(encoding="utf-8"))} == {"keep", "new"}
