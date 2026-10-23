"""Several bookmarks at once in the bookmark sidebar.

Operator punch list item 22: "bookmarks mehrere bookmarks in eine gruppe
ziehen, also strg support und klassischer shift support". Before, the tree
was SingleSelection: one bookmark per drag, one per delete.

Ctrl+click adds to the selection, Shift+click selects a range, neither
navigates; a drag moves every selected entry, in tree order; the right-click
menu's Move to Group and Delete act on the whole selection, and Delete asks
once, naming the count.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, QPoint, QPointF, Qt  # noqa: E402
from PyQt6.QtGui import QDragMoveEvent, QDropEvent  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox, QTreeWidgetItemIterator  # noqa: E402

import core.bookmarks as BM  # noqa: E402
from core.bookmarks import Bookmark, BookmarkGroup, BookmarkManager  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.02) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.005)


@pytest.fixture
def home(tmp_path, monkeypatch):
    """The real store under an isolated HOME (no module constant patched)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    assert BM.BOOKMARKS_FILE == BM._DEFAULT_BOOKMARKS_FILE
    return tmp_path / ".config" / "axross" / "bookmarks.json"


@pytest.fixture
def mgr(home):
    m = BookmarkManager()
    work = m.add_group("Work")
    m.add(Bookmark("logs", "/var/log"), group=work)
    for name in ("a", "b", "c", "d"):
        m.add(Bookmark(name, f"/{name}"))
    return m


@pytest.fixture
def side(mgr):
    from ui.bookmark_sidebar import BookmarkSidebar

    s = BookmarkSidebar(mgr)
    s.resize(300, 500)
    s.show()
    pump()
    yield s
    s.close()
    s.deleteLater()
    pump()


def _item(side, name):
    it = QTreeWidgetItemIterator(side._tree)
    while it.value():
        if it.value().text(0) == name:
            return it.value()
        it += 1
    raise AssertionError(f"no item {name!r}")


def _click(side, name, modifier=Qt.KeyboardModifier.NoModifier):
    tree = side._tree
    QTest.mouseClick(
        tree.viewport(),
        Qt.MouseButton.LeftButton,
        modifier,
        tree.visualItemRect(_item(side, name)).center() + QPoint(20, 0),
    )
    pump()


def _selected(side) -> list[str]:
    return sorted(i.text(0) for i in side._tree.selectedItems())


def _names(nodes) -> list[str]:
    return [n.name for n in nodes]


def _stored(home) -> list:
    return json.loads(home.read_text(encoding="utf-8"))


def _plain(text: str) -> str:
    """A menu label as shown: the "&" mnemonic marks dropped."""
    return text.replace("&&", "\0").replace("&", "").replace("\0", "&")


def _action(menu, text):
    for action in menu.actions():
        if _plain(action.text()) == text:
            return action
        if action.menu() is not None:
            found = next((a for a in action.menu().actions() if _plain(a.text()) == text), None)
            if found is not None:
                return found
    raise AssertionError(f"no menu entry {text!r} in {[a.text() for a in menu.actions()]}")


def _drop(side, dragged: list[str], target: str, *, above: bool = False):
    """A real drop event of the selected rows onto *target*."""
    tree = side._tree
    items = [_item(side, n) for n in dragged]
    mime = tree.mimeData(items)
    rect = tree.visualItemRect(_item(side, target))
    pos = QPoint(rect.center().x(), rect.top() + 1) if above else rect.center()
    tree.dragMoveEvent(
        QDragMoveEvent(
            pos,
            Qt.DropAction.MoveAction,
            mime,
            Qt.MouseButton.LeftButton,
            Qt.KeyboardModifier.NoModifier,
            QEvent.Type.DragMove,
        )
    )
    tree.dropEvent(
        QDropEvent(
            QPointF(pos),
            Qt.DropAction.MoveAction,
            mime,
            Qt.MouseButton.LeftButton,
            Qt.KeyboardModifier.NoModifier,
        )
    )
    pump()


# --- happy -----------------------------------------------------------------


def test_happy_ctrl_click_adds_to_the_selection_without_navigating(side) -> None:
    nav = []
    side.navigate_requested.connect(nav.append)
    _click(side, "a")
    assert len(nav) == 1  # a plain click still opens the bookmark
    _click(side, "c", Qt.KeyboardModifier.ControlModifier)
    assert _selected(side) == ["a", "c"]
    assert len(nav) == 1  # Ctrl+click only selects


def test_happy_shift_click_selects_the_range(side) -> None:
    nav = []
    side.navigate_requested.connect(nav.append)
    _click(side, "a")
    _click(side, "d", Qt.KeyboardModifier.ShiftModifier)
    assert _selected(side) == ["a", "b", "c", "d"]
    assert len(nav) == 1


def test_happy_dragging_a_selection_into_a_group_moves_all_of_it(side, mgr, home) -> None:
    _click(side, "a")
    _click(side, "c", Qt.KeyboardModifier.ControlModifier)
    _drop(side, ["a", "c"], "Work")
    work = mgr.tree()[0]
    assert _names(work.children) == ["logs", "a", "c"]
    assert _names(mgr.tree()) == ["Work", "b", "d"]
    # persisted, in that order
    assert [c["name"] for c in _stored(home)[0]["children"]] == ["logs", "a", "c"]


def test_happy_move_to_group_from_the_menu_moves_the_selection(side, mgr) -> None:
    _click(side, "b")
    _click(side, "d", Qt.KeyboardModifier.ControlModifier)
    node = next(n for n in mgr.tree() if n.name == "d")
    menu = side._build_menu(node)
    _action(menu, "Work").trigger()
    pump()
    assert _names(mgr.tree()[0].children) == ["logs", "b", "d"]
    assert _names(BookmarkManager().tree()[0].children) == ["logs", "b", "d"]


def test_happy_delete_asks_once_naming_the_count(side, mgr) -> None:
    _click(side, "a")
    _click(side, "c", Qt.KeyboardModifier.ShiftModifier)
    node = next(n for n in mgr.tree() if n.name == "b")
    menu = side._build_menu(node)
    with mock.patch(
        "ui.bookmark_sidebar.QMessageBox.question", return_value=QMessageBox.StandardButton.Yes
    ) as ask:
        _action(menu, "Delete 3 Selected…").trigger()
        pump()
    assert ask.call_count == 1
    assert "3 bookmarks" in ask.call_args.args[2]
    assert _names(mgr.tree()) == ["Work", "d"]
    assert _names(BookmarkManager().tree()) == ["Work", "d"]


# --- sad -------------------------------------------------------------------


def test_sad_declining_the_delete_keeps_everything(side, mgr) -> None:
    _click(side, "a")
    _click(side, "b", Qt.KeyboardModifier.ControlModifier)
    node = next(n for n in mgr.tree() if n.name == "a")
    with mock.patch(
        "ui.bookmark_sidebar.QMessageBox.question", return_value=QMessageBox.StandardButton.No
    ):
        _action(side._build_menu(node), "Delete 2 Selected…").trigger()
        pump()
    assert _names(mgr.tree()) == ["Work", "a", "b", "c", "d"]


def test_sad_a_group_in_the_selection_is_not_dropped_into_itself(side, mgr) -> None:
    inner = mgr.add_group("Inner", parent=mgr.tree()[0])
    side.rebuild()
    pump()
    _click(side, "Work", Qt.KeyboardModifier.ControlModifier)  # selects, does not fold
    _click(side, "a", Qt.KeyboardModifier.ControlModifier)
    assert _selected(side) == ["Work", "a"]
    assert _item(side, "Work").isExpanded()
    # Work (and a) dropped onto Inner, which lies inside Work: nothing moves.
    before = BookmarkManager().tree()
    _drop(side, ["Work", "a"], "Inner")
    assert mgr.parent_of(inner) is mgr.tree()[0]
    assert _names(mgr.tree()) == ["Work", "a", "b", "c", "d"]
    assert _names(BookmarkManager().tree()) == _names(before)


def test_sad_move_nodes_rejects_unknown_nodes_without_changing_anything(mgr) -> None:
    stranger = Bookmark("x", "/x")
    a = mgr.tree()[1]
    with pytest.raises(KeyError):
        mgr.move_nodes([a, stranger], mgr.tree()[0])
    assert _names(mgr.tree()) == ["Work", "a", "b", "c", "d"]


# --- edge ------------------------------------------------------------------


def test_edge_a_right_click_outside_the_selection_acts_on_that_entry_only(side, mgr) -> None:
    _click(side, "a")
    _click(side, "b", Qt.KeyboardModifier.ControlModifier)
    tree = side._tree
    shown = []
    with mock.patch("ui.bookmark_sidebar.QMenu.exec", lambda menu, *_a: shown.append(menu)):
        side._show_context_menu(tree.visualItemRect(_item(side, "d")).center())
    assert _selected(side) == ["d"]
    texts = [_plain(a.text()) for a in shown[0].actions()]
    assert "Delete" in texts and not any("Selected" in t for t in texts)


def test_edge_a_child_selected_with_its_group_moves_with_the_group(side, mgr) -> None:
    other = mgr.add_group("Other")
    side.rebuild()
    pump()
    work = mgr.tree()[0]
    logs = work.children[0]
    assert mgr.move_nodes([work, logs], other) is True
    assert _names(other.children) == ["Work"]
    assert _names(work.children) == ["logs"]


def test_edge_moving_within_one_list_keeps_the_drop_position(mgr) -> None:
    a, b, c, d = mgr.tree()[1:]
    # a and b dropped above d (index 4 in the list as it is BEFORE the move)
    mgr.move_nodes([a, b], None, 4)
    assert _names(mgr.tree()) == ["Work", "c", "a", "b", "d"]
    _ = (c, d)


def test_edge_remove_nodes_deletes_a_group_but_keeps_its_bookmarks(mgr) -> None:
    work = mgr.tree()[0]
    a = mgr.tree()[1]
    assert mgr.remove_nodes([work, a]) == 2
    assert _names(mgr.tree()) == ["logs", "b", "c", "d"]
    assert isinstance(BookmarkManager().tree()[0], Bookmark)
    assert not any(isinstance(n, BookmarkGroup) for n in BookmarkManager().tree())


def test_edge_the_tree_allows_extended_selection(side) -> None:
    from PyQt6.QtWidgets import QAbstractItemView

    assert side._tree.selectionMode() == QAbstractItemView.SelectionMode.ExtendedSelection
