"""Bookmarks > Manage Bookmarks... is a real manager.

Reported: "manage bookmark tab, kann ja im grunde nur löschen und nicht
wirklich managen...oder? da fehlt doch was". Before, the dialog was a flat
list of "name -> path [backend]" with one button, "Delete Selected" (one
row, no question); groups were not shown at all, and with no bookmark it
did not open ("No bookmarks saved yet.") even when there were groups.

Now it shows the tree the sidebar shows (name, location, connection) and
does what the sidebar does, with the sidebar's own code and the same store:
Edit..., Rename..., New Group..., New Terminal Bookmark..., Move Up / Down /
to Top, Move to Group, Sort, Delete... for a whole selection, drag & drop.
Every change shows in the sidebar and the Bookmarks menu at once.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, Qt, QTimer  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import (  # noqa: E402
    QApplication,
    QDialog,
    QMessageBox,
    QPushButton,
    QTreeWidgetItemIterator,
)

import core.bookmarks as BM  # noqa: E402
from core.bookmarks import Bookmark, BookmarkGroup, BookmarkManager  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.03) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.005)


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert BM.BOOKMARKS_FILE == BM._DEFAULT_BOOKMARKS_FILE
    return tmp_path


@pytest.fixture
def mgr(home):
    m = BookmarkManager()
    projects = m.add_group("Projects")
    m.add(Bookmark("axross", "~/c0de/axross"), group=projects)
    for name in ("etc", "tmp", "var"):
        m.add(Bookmark(name, f"/{name}"))
    return m


@pytest.fixture
def dlg(mgr):
    from ui.bookmark_manager_dialog import BookmarkManagerDialog

    d = BookmarkManagerDialog(mgr)
    d.show()
    pump()
    yield d
    d.close()
    d.deleteLater()
    pump()


def _item(d, name):
    it = QTreeWidgetItemIterator(d._tree)
    while it.value():
        if it.value().text(0) == name:
            return it.value()
        it += 1
    raise AssertionError(f"no row {name!r}")


def _select(d, *names) -> None:
    """Select *names* as Ctrl+clicks would; the last one is current."""
    d._tree.clearSelection()
    d._tree.setCurrentItem(_item(d, names[-1]))
    for name in names:
        _item(d, name).setSelected(True)
    pump()


def _btn(d, text) -> QPushButton:
    for b in d.findChildren(QPushButton):
        if b.text().replace("&", "") == text:
            return b
    raise AssertionError(f"no button {text!r}: {[b.text() for b in d.findChildren(QPushButton)]}")


def _top_names(m) -> list[str]:
    return [n.name for n in m.tree()]


# -- what it shows ----------------------------------------------------------------


def test_happy_the_tree_shows_groups_bookmarks_and_where_they_lead(dlg) -> None:
    group = _item(dlg, "Projects")
    assert isinstance(group.data(0, Qt.ItemDataRole.UserRole), BookmarkGroup)
    child = group.child(0)
    assert child.text(0) == "axross"
    assert child.text(1) == "~/c0de/axross"
    assert child.text(2) == "Local"
    assert dlg._tree.headerItem().text(0) == "Name"
    for text in (
        "Edit…", "Rename…", "New Group…", "New Terminal Bookmark…", "Move Up", "Move Down",
        "Move to Top", "Move to Group", "Sort", "Delete…", "Close",
    ):
        _btn(dlg, text)


def test_sad_buttons_follow_the_selection(dlg) -> None:
    dlg._tree.clearSelection()
    pump()
    for text in ("Edit…", "Rename…", "Move Up", "Move Down", "Move to Top", "Move to Group",
                 "Delete…"):
        assert not _btn(dlg, text).isEnabled(), text
    _select(dlg, "etc", "tmp")
    for text in ("Edit…", "Rename…", "Move Up", "Move Down", "Move to Top"):
        assert not _btn(dlg, text).isEnabled(), text
    assert _btn(dlg, "Delete…").isEnabled() and _btn(dlg, "Move to Group").isEnabled()
    _select(dlg, "Projects")  # the first entry: it cannot move up
    assert not _btn(dlg, "Move Up").isEnabled() and _btn(dlg, "Move Down").isEnabled()


# -- edit, rename ---------------------------------------------------------------------


def test_happy_edit_opens_the_bookmark_dialog_and_saves(dlg, mgr) -> None:
    _select(dlg, "etc")

    def fake_exec(self):
        self._path_edit.setText("/etc/nginx")
        return QDialog.DialogCode.Accepted

    with mock.patch("ui.bookmark_edit_dialog.BookmarkEditDialog.exec", fake_exec):
        QTest.mouseClick(_btn(dlg, "Edit…"), Qt.MouseButton.LeftButton)
    pump()
    assert [b.path for b in mgr.all() if b.name == "etc"] == ["/etc/nginx"]
    assert BookmarkManager().find("/etc/nginx", "Local") is not None  # stored


def test_happy_a_double_click_edits_too(dlg) -> None:
    item = _item(dlg, "tmp")
    with mock.patch(
        "ui.bookmark_edit_dialog.BookmarkEditDialog.exec", return_value=QDialog.DialogCode.Rejected
    ) as opened:
        rect = dlg._tree.visualItemRect(item)
        # A real double click: press, release, then the double-click event.
        QTest.mouseClick(dlg._tree.viewport(), Qt.MouseButton.LeftButton,
                         Qt.KeyboardModifier.NoModifier, rect.center())
        QTest.mouseDClick(dlg._tree.viewport(), Qt.MouseButton.LeftButton,
                          Qt.KeyboardModifier.NoModifier, rect.center())
        pump()
    opened.assert_called_once()


def test_happy_rename_a_bookmark_and_a_group(dlg, mgr) -> None:
    _select(dlg, "tmp")
    rename = "ui.bookmark_manager_dialog.QInputDialog.getText"
    with mock.patch(rename, return_value=("scratch", True)):
        QTest.mouseClick(_btn(dlg, "Rename…"), Qt.MouseButton.LeftButton)
    _select(dlg, "Projects")
    with mock.patch(rename, return_value=("Code", True)):
        QTest.keyClick(dlg._tree, Qt.Key.Key_F2)
    pump()
    assert _top_names(mgr) == ["Code", "etc", "scratch", "var"]
    assert _top_names(BookmarkManager()) == ["Code", "etc", "scratch", "var"]  # stored
    assert dlg._tree.currentItem().text(0) == "Code"  # the selection follows


@pytest.mark.parametrize("answer", [("", True), ("   ", True), ("ignored", False)])
def test_sad_an_empty_or_cancelled_rename_changes_nothing(dlg, mgr, answer) -> None:
    _select(dlg, "tmp")
    with mock.patch("ui.bookmark_manager_dialog.QInputDialog.getText", return_value=answer):
        QTest.mouseClick(_btn(dlg, "Rename…"), Qt.MouseButton.LeftButton)
    pump()
    assert _top_names(mgr) == ["Projects", "etc", "tmp", "var"]


# -- groups, order ----------------------------------------------------------------------


def test_happy_new_group_and_move_to_group(dlg, mgr) -> None:
    with mock.patch("ui.bookmark_edit_dialog.GroupEditDialog.exec",
                    return_value=QDialog.DialogCode.Accepted), mock.patch(
        "ui.bookmark_edit_dialog.GroupEditDialog.result", return_value=("Servers", "server", "")
    ):
        QTest.mouseClick(_btn(dlg, "New Group…"), Qt.MouseButton.LeftButton)
    pump()
    assert "Servers" in _top_names(mgr)
    _select(dlg, "etc", "var")
    menu = _btn(dlg, "Move to Group").menu()
    menu.aboutToShow.emit()
    target = next(a for a in menu.actions() if a.text().strip() == "Servers")
    target.trigger()
    pump()
    servers = next(n for n in mgr.tree() if n.name == "Servers")
    assert [c.name for c in servers.children] == ["etc", "var"]
    assert _top_names(mgr) == ["Projects", "tmp", "Servers"]


def test_edge_a_group_cannot_be_moved_into_itself(dlg) -> None:
    _select(dlg, "Projects")
    menu = _btn(dlg, "Move to Group").menu()
    menu.aboutToShow.emit()
    own = next(a for a in menu.actions() if a.text().strip() == "Projects")
    assert not own.isEnabled()


def test_happy_move_up_down_top_keep_the_entry_selected(dlg, mgr) -> None:
    _select(dlg, "var")
    QTest.mouseClick(_btn(dlg, "Move Up"), Qt.MouseButton.LeftButton)
    assert _top_names(mgr) == ["Projects", "etc", "var", "tmp"]
    assert [i.text(0) for i in dlg._tree.selectedItems()] == ["var"]
    QTest.mouseClick(_btn(dlg, "Move to Top"), Qt.MouseButton.LeftButton)
    assert _top_names(mgr) == ["var", "Projects", "etc", "tmp"]
    QTest.mouseClick(_btn(dlg, "Move Down"), Qt.MouseButton.LeftButton)
    assert _top_names(mgr) == ["Projects", "var", "etc", "tmp"]


def test_happy_sort_the_top_level_or_the_selected_group(dlg, mgr) -> None:
    mgr.add(Bookmark("alpha", "/alpha"))
    dlg.rebuild()
    dlg._tree.clearSelection()
    pump()
    menu = _btn(dlg, "Sort").menu()
    menu.aboutToShow.emit()
    next(a for a in menu.actions() if a.text() == "By Name (Reverse)").trigger()
    pump()
    # Groups stay first (the sidebar's rule).
    assert _top_names(mgr) == ["Projects", "var", "tmp", "etc", "alpha"]


# -- delete ---------------------------------------------------------------------------------


def test_sad_delete_asks_once_and_no_keeps_everything(dlg, mgr) -> None:
    _select(dlg, "etc", "tmp")
    with mock.patch("ui.bookmark_sidebar.QMessageBox.question",
                    return_value=QMessageBox.StandardButton.No) as asked:
        QTest.mouseClick(_btn(dlg, "Delete…"), Qt.MouseButton.LeftButton)
    assert asked.call_count == 1 and "2 bookmarks" in asked.call_args[0][2]
    assert _top_names(mgr) == ["Projects", "etc", "tmp", "var"]


def test_happy_delete_a_selection_with_the_del_key(dlg, mgr) -> None:
    _select(dlg, "etc", "tmp")
    with mock.patch("ui.bookmark_sidebar.QMessageBox.question",
                    return_value=QMessageBox.StandardButton.Yes):
        QTest.keyClick(dlg._tree, Qt.Key.Key_Delete)
    pump()
    assert _top_names(mgr) == ["Projects", "var"]
    assert _top_names(BookmarkManager()) == ["Projects", "var"]


# -- one store: the main window --------------------------------------------------------------


@pytest.fixture
def window(home):
    from ui.main_window import MainWindow

    win = MainWindow()
    win._reconnect_timer.stop()
    win.resize(1100, 700)
    win.show()
    pump()
    yield win
    win.close()
    win.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    pump()


def _open_manager(win, check):
    """Bookmarks > Manage Bookmarks... as the menu does; *check* runs
    against the open dialog."""
    from ui.bookmark_manager_dialog import BookmarkManagerDialog

    seen = {}

    def inspect() -> None:
        d = next(w for w in APP.topLevelWidgets()
                 if isinstance(w, BookmarkManagerDialog) and w.isVisible())
        try:
            seen["result"] = check(d)
        except BaseException as exc:
            seen["error"] = exc
        d.reject()

    QTimer.singleShot(200, inspect)
    action = next(a for a in win._bookmarks_menu.actions()
                  if a.text().replace("&", "").startswith("Manage Bookmarks"))
    action.trigger()
    if "error" in seen:
        raise seen["error"]
    return seen.get("result")


def _sidebar_names(win) -> list[str]:
    tree = win._bookmark_sidebar._tree
    return [tree.topLevelItem(i).text(0) for i in range(tree.topLevelItemCount())]


def test_happy_e2e_a_change_in_the_manager_shows_in_the_sidebar_and_menu_at_once(window) -> None:
    m = window._bookmark_manager
    m.add(Bookmark("etc", "/etc"))
    m.add(Bookmark("tmp", "/tmp"))
    window._rebuild_bookmarks_menu()

    def check(d):
        _select(d, "tmp")
        with mock.patch("ui.bookmark_manager_dialog.QInputDialog.getText",
                        return_value=("scratch", True)):
            QTest.mouseClick(_btn(d, "Rename…"), Qt.MouseButton.LeftButton)
        pump()
        # Checked while the dialog is still open.
        return _sidebar_names(window), [a.text() for a in window._bookmarks_menu.actions()]

    sidebar, menu = _open_manager(window, check)
    assert sidebar == ["etc", "scratch"]
    assert any("scratch" in t for t in menu)


def test_edge_e2e_it_opens_with_no_bookmark_at_all(window) -> None:
    """Before: a message box "No bookmarks saved yet." and no dialog."""
    assert window._bookmark_manager.tree() == []

    def check(d):
        assert d._hint.isVisible()
        with mock.patch("ui.bookmark_edit_dialog.GroupEditDialog.exec",
                        return_value=QDialog.DialogCode.Accepted), mock.patch(
            "ui.bookmark_edit_dialog.GroupEditDialog.result", return_value=("Inbox", "folder", "")
        ):
            QTest.mouseClick(_btn(d, "New Group…"), Qt.MouseButton.LeftButton)
        pump()
        return _sidebar_names(window)

    with mock.patch("ui.main_window.QMessageBox.information") as told:
        assert _open_manager(window, check) == ["Inbox"]
    told.assert_not_called()


def test_edge_the_edited_bookmark_stays_selected(dlg, mgr) -> None:
    """An edit stores a new object in the old one's place; the row is
    selected again, so the next button acts on it."""
    _select(dlg, "tmp")

    def fake_exec(self):
        self._name_edit.setText("temp")
        return QDialog.DialogCode.Accepted

    with mock.patch("ui.bookmark_edit_dialog.BookmarkEditDialog.exec", fake_exec):
        QTest.mouseClick(_btn(dlg, "Edit…"), Qt.MouseButton.LeftButton)
    pump()
    assert [i.text(0) for i in dlg._tree.selectedItems()] == ["temp"]
    assert _btn(dlg, "Move Up").isEnabled()
