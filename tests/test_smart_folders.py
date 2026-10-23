"""Smart Folders: a saved Find Files search kept with the bookmarks.

It appears in the bookmark sidebar and the Bookmarks menu; a click runs
the search again. Corrupt entries in bookmarks.json are dropped or
refused with a message, never crash the sidebar.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import core.bookmarks as BM  # noqa: E402
from core import file_search as FS  # noqa: E402
from core.search_federation import SearchQuery  # noqa: E402


@pytest.fixture
def store(tmp_path, monkeypatch):
    path = tmp_path / "bookmarks.json"
    monkeypatch.setattr(BM, "BOOKMARKS_FILE", path)
    return path


def _saved(**query) -> dict:
    q = SearchQuery(**query)
    return FS.saved_search_to_dict(
        q, [{"backend_name": "Local", "profile_name": "", "path": "/home/u"}], use_index=False
    )


# --- saved search format -----------------------------------------------------


def test_happy_a_saved_search_round_trips() -> None:
    data = _saved(name="*.dat", contains="seed", categories=("crypto_wallets",),
                  search_archives=True, include_hidden=False, case_sensitive=True,
                  min_size=10, max_size=5000, modified_after=100.0, max_depth=12)
    query, scopes, options = FS.saved_search_from_dict(json.loads(json.dumps(data)))
    assert query.name == "*.dat" and query.contains == "seed"
    assert query.categories == ("crypto_wallets",)
    assert query.search_archives and not query.include_hidden and query.case_sensitive
    assert (query.min_size, query.max_size, query.modified_after, query.max_depth) == (
        10, 5000, 100.0, 12)
    assert scopes == [{"backend_name": "Local", "profile_name": "", "path": "/home/u"}]
    assert options == {"use_index": False, "tag": ""}


def test_happy_skipping_noise_folders_is_saved_as_a_switch() -> None:
    data = FS.saved_search_to_dict(SearchQuery(ignore_dirs=()), [], use_index=True)
    query, scopes, options = FS.saved_search_from_dict(data)
    assert query.ignore_dirs == () and scopes == [] and options["use_index"]
    query, _s, _o = FS.saved_search_from_dict(_saved())
    assert ".git" in query.ignore_dirs


@pytest.mark.parametrize(
    ("patch", "message"),
    [
        ({"version": 99}, "version"),
        ({"categories": ["secrets"]}, "unknown file category"),
        ({"categories": "images"}, "categories"),
        ({"regex": "["}, "invalid"),
        ({"min_size": "big"}, "min_size"),
        ({"search_archives": "yes"}, "search_archives"),
        ({"scopes": "everywhere"}, "scopes"),
        ({"scopes": [{"backend_name": "Local", "path": 7}]}, "path"),
        ({"scopes": [{"backend_name": "Local", "path": "/"}] * 40}, "scopes"),
        ({"name": "x" * 5000}, "name"),
    ],
)
def test_sad_a_damaged_saved_search_is_refused(patch, message) -> None:
    data = _saved()
    data.update(patch)
    with pytest.raises(ValueError, match=message):
        FS.saved_search_from_dict(data)


def test_sad_a_saved_search_must_be_a_mapping() -> None:
    with pytest.raises(ValueError):
        FS.saved_search_from_dict(["not", "a", "dict"])


def test_edge_unknown_keys_are_ignored_and_missing_ones_default() -> None:
    query, scopes, options = FS.saved_search_from_dict({"version": 1, "future_field": 1})
    assert query.name == "" and query.categories == () and scopes == []
    assert options == {"use_index": False, "tag": ""}


# --- bookmarks store ---------------------------------------------------------


def test_happy_a_smart_folder_is_stored_with_the_bookmarks(store) -> None:
    mgr = BM.BookmarkManager()
    smart = BM.new_smart_folder("Wallets", _saved(categories=("crypto_wallets",)))
    assert smart.is_smart_folder and smart.path.startswith("search:")
    assert smart.backend_name == BM.SMART_FOLDER_BACKEND
    assert mgr.add(smart)
    again = BM.BookmarkManager().all()
    assert [b.name for b in again] == ["Wallets"]
    assert again[0].is_smart_folder
    assert again[0].search["categories"] == ["crypto_wallets"]
    plain = BM.Bookmark(name="Home", path="/home/u")
    assert not plain.is_smart_folder


def test_happy_two_smart_folders_with_one_name_are_both_kept(store) -> None:
    mgr = BM.BookmarkManager()
    assert mgr.add(BM.new_smart_folder("Same", _saved(name="*.a")))
    assert mgr.add(BM.new_smart_folder("Same", _saved(name="*.b")))
    assert len(BM.BookmarkManager().all()) == 2


def test_sad_a_smart_folder_whose_search_is_not_a_mapping_is_dropped(store) -> None:
    store.write_text(json.dumps([
        {"name": "Broken", "path": "search:1", "backend_name": "Smart Folder", "search": "oops"},
        {"name": "Home", "path": "/home/u"},
    ]))
    assert [b.name for b in BM.BookmarkManager().all()] == ["Home"]


def test_sad_an_oversized_search_is_dropped(store) -> None:
    store.write_text(json.dumps([
        {"name": "Huge", "path": "search:2", "backend_name": "Smart Folder",
         "search": {"version": 1, "name": "x" * 70_000}},
    ]))
    assert BM.BookmarkManager().all() == []


def test_edge_a_damaged_search_mapping_is_kept_and_refused_when_run(store) -> None:
    # Kept: it is the user's entry; the click reports why it cannot run.
    store.write_text(json.dumps([
        {"name": "Odd", "path": "search:3", "backend_name": "Smart Folder",
         "search": {"version": 1, "regex": "["}},
    ]))
    marks = BM.BookmarkManager().all()
    assert [b.name for b in marks] == ["Odd"]
    with pytest.raises(ValueError):
        FS.saved_search_from_dict(marks[0].search)


def test_edge_a_merge_with_another_writer_keeps_the_search(store) -> None:
    first = BM.BookmarkManager()
    second = BM.BookmarkManager()
    first.add(BM.new_smart_folder("A", _saved(name="*.a")))
    second.add(BM.Bookmark(name="B", path="/b"))
    marks = {b.name: b for b in BM.BookmarkManager().all()}
    assert set(marks) == {"A", "B"}
    assert marks["A"].search["name"] == "*.a"


# --- sidebar -----------------------------------------------------------------


@pytest.fixture
def app():
    pytest.importorskip("PyQt6.QtWidgets")
    from PyQt6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def test_happy_the_sidebar_shows_a_smart_folder_and_a_click_asks_to_run_it(store, app) -> None:
    from PyQt6.QtCore import Qt
    from PyQt6.QtTest import QTest

    from ui.bookmark_sidebar import BookmarkSidebar

    mgr = BM.BookmarkManager()
    mgr.add(BM.new_smart_folder("Pictures", _saved(categories=("images",))))
    bar = BookmarkSidebar(mgr)
    bar.resize(300, 400)
    bar.show()
    app.processEvents()
    item = bar._tree.topLevelItem(0)
    assert item.text(0) == "Pictures"
    assert "Smart Folder" in item.toolTip(0) and "Images" in item.toolTip(0)
    clicked = []
    bar.navigate_requested.connect(clicked.append)
    rect = bar._tree.visualItemRect(item)
    QTest.mouseClick(bar._tree.viewport(), Qt.MouseButton.LeftButton, pos=rect.center())
    app.processEvents()
    assert len(clicked) == 1 and clicked[0].is_smart_folder
    bar.close()
    bar.deleteLater()


def test_sad_dropping_files_onto_a_smart_folder_is_no_transfer(store, app) -> None:
    from ui.bookmark_sidebar import BookmarkSidebar

    mgr = BM.BookmarkManager()
    smart = BM.new_smart_folder("S", _saved())
    mgr.add(smart)
    bar = BookmarkSidebar(mgr)
    transfers, marks = [], []
    bar.transfer_drop_requested.connect(lambda *a: transfers.append(a))
    bar.bookmark_drop_requested.connect(lambda *a: marks.append(a))
    payload = {"paths": ["/tmp/a.txt"], "dirs": [], "source_pane_id": "1"}
    bar._apply_external_drop(payload, smart, "onto", True)
    assert transfers == [] and marks == []
    bar.deleteLater()


def test_edge_editing_a_smart_folder_keeps_its_search(store, app) -> None:
    from ui.bookmark_edit_dialog import BookmarkEditDialog

    smart = BM.new_smart_folder("S", _saved(name="*.iso"))
    dialog = BookmarkEditDialog(smart)
    assert dialog._path_edit.isReadOnly()
    dialog._name_edit.setText("Renamed")
    result = dialog.result_bookmark()
    assert result.name == "Renamed" and result.search == smart.search
    assert result.path == smart.path
    dialog.deleteLater()


# -- an icon outside the picker's grid survives an edit (bughunt 2026-10-22: a
# Smart Folder's "find-index" is no grid icon, so the picker fell back to
# "bookmark" and a mere rename turned it into a plain bookmark's icon) -----------


def test_edge_renaming_a_smart_folder_keeps_its_search_icon(store, app) -> None:
    from ui.bookmark_edit_dialog import BookmarkEditDialog

    smart = BM.new_smart_folder("S", _saved(name="*.iso"))
    assert smart.icon_name == "find-index"
    dialog = BookmarkEditDialog(smart)
    dialog._name_edit.setText("Renamed")
    assert dialog.result_bookmark().icon_name == "find-index"
    # It is shown as the chosen one, and another icon can still be picked.
    button = dialog._picker._buttons["find-index"]
    assert button.isChecked()
    dialog._picker._on_pick("star")
    assert dialog.result_bookmark().icon_name == "star" and not button.isChecked()
    dialog.deleteLater()


def test_e2e_editing_a_smart_folder_in_the_sidebar_keeps_its_icon(store, app) -> None:
    from PyQt6.QtWidgets import QDialog

    from ui.bookmark_edit_dialog import BookmarkEditDialog
    from ui.bookmark_sidebar import BookmarkSidebar

    mgr = BM.BookmarkManager()
    mgr.add(BM.new_smart_folder("Pictures", _saved(categories=("images",))))
    bar = BookmarkSidebar(mgr)

    def accept_renamed(dialog):
        dialog._name_edit.setText("Photos")
        return QDialog.DialogCode.Accepted

    with mock.patch.object(BookmarkEditDialog, "exec", accept_renamed):
        bar.edit_node(mgr.all()[0])
    (stored,) = BM.BookmarkManager().all()
    assert stored.name == "Photos" and stored.icon_name == "find-index"
    bar.deleteLater()


def test_sad_an_icon_name_the_provider_does_not_know_still_falls_back(store, app) -> None:
    from ui.bookmark_edit_dialog import BookmarkEditDialog

    mark = BM.Bookmark("n", "/p", icon_name="no-such-icon")
    dialog = BookmarkEditDialog(mark)
    assert dialog.result_bookmark().icon_name == "bookmark"
    assert "no-such-icon" not in dialog._picker._buttons
    dialog.deleteLater()
