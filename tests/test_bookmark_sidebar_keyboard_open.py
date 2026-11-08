"""Enter / Return on a bookmark in the sidebar opens it.

Before: only ``itemClicked`` was connected, so a bookmark could be opened
with the mouse only - Enter on the selected row did nothing. Now
``itemActivated`` from a key opens a bookmark (and folds a group) as a
click does; an activation by the mouse (a double click) is left to the
click, so nothing opens twice.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def sidebar(tmp_path, monkeypatch):
    from core import bookmarks as BM
    from ui.bookmark_sidebar import BookmarkSidebar

    monkeypatch.setattr(BM, "BOOKMARKS_FILE", tmp_path / "bookmarks.json")
    manager = BM.BookmarkManager()
    group = manager.add_group("Work")
    manager.add(BM.Bookmark("etc", "/etc"), group=group)
    manager.add(BM.Bookmark("tmp", "/tmp"))
    bar = BookmarkSidebar(manager)
    bar.show()
    APP.processEvents()
    yield bar
    bar.close()
    bar.deleteLater()


def _row(bar, text):
    tree = bar._tree
    for i in range(tree.topLevelItemCount()):
        item = tree.topLevelItem(i)
        if item.text(0) == text:
            return item
    raise AssertionError(f"no row {text!r}")


def test_happy_return_and_enter_open_the_selected_bookmark(sidebar):
    got: list = []
    sidebar.navigate_requested.connect(lambda bm: got.append(bm.path))
    tree = sidebar._tree
    tree.setFocus()
    tree.setCurrentItem(_row(sidebar, "tmp"))
    QTest.keyClick(tree, Qt.Key.Key_Return)
    QTest.keyClick(tree, Qt.Key.Key_Enter)
    assert got == ["/tmp", "/tmp"]


def test_happy_return_on_a_group_folds_it(sidebar):
    tree = sidebar._tree
    group = _row(sidebar, "Work")
    tree.setFocus()
    tree.setCurrentItem(group)
    before = group.isExpanded()
    QTest.keyClick(tree, Qt.Key.Key_Return)
    assert group.isExpanded() is (not before)


def test_edge_an_activation_by_the_mouse_opens_nothing_more_than_its_click(sidebar):
    got: list = []
    sidebar.navigate_requested.connect(lambda bm: got.append(bm.path))
    tree = sidebar._tree
    item = _row(sidebar, "tmp")
    # A double click activates the row as well; its clicks already opened it.
    tree.itemActivated.emit(item, 0)
    assert got == []
    tree.setFocus()
    tree.setCurrentItem(item)
    QTest.keyClick(tree, Qt.Key.Key_Return)
    assert got == ["/tmp"]
