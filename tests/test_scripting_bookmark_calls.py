"""axross.remove_bookmark and add_bookmark tell a script what did not happen.

Measured before: ``remove_bookmark(-1)`` (or any index past the end) did
nothing and returned as if it had removed something - the audit log even
named the last bookmark as removed; a bookmarks file that could not be
written was only logged, so ``add_bookmark`` and ``remove_bookmark`` returned
normally and the change was gone at the next start.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import bookmarks as BM  # noqa: E402
from core import scripting  # noqa: E402


@pytest.fixture()
def store(tmp_path):
    file = tmp_path / "bookmarks.json"
    with mock.patch.object(BM, "BOOKMARKS_FILE", file):
        yield file


def test_happy_remove_bookmark_removes_the_one_at_the_index(store):
    scripting.add_bookmark("a", "/a")
    scripting.add_bookmark("b", "/b")
    scripting.remove_bookmark(0)
    assert [b.name for b in scripting.list_bookmarks()] == ["b"]


@pytest.mark.parametrize("index", [-1, 2, 99])
def test_sad_an_index_out_of_range_raises(store, index):
    scripting.add_bookmark("a", "/a")
    scripting.add_bookmark("b", "/b")
    with pytest.raises(IndexError):
        scripting.remove_bookmark(index)
    assert [b.name for b in scripting.list_bookmarks()] == ["a", "b"]


def test_sad_a_bookmark_not_saved_raises(store, monkeypatch):
    scripting.add_bookmark("a", "/a")

    def full(self, bf):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(BM.BookmarkManager, "_write", full)
    with pytest.raises(OSError):
        scripting.add_bookmark("b", "/b")
    with pytest.raises(OSError):
        scripting.remove_bookmark(0)
