"""The pane's context menu from the keyboard opens at the current row.

Found in review (round 2 of the 2026-11 reviews, UI shell):

- the Menu key and Shift+F10 as the platform sends them (a
  QContextMenuEvent with reason Keyboard) opened the menu where the mouse
  pointer happened to be - perhaps far from the pane, on another
  screen - and F10 did the same (it computed the row's place and then
  used the pointer's);
- the Menu key and Shift+F10 as key presses (where the platform sends
  no context menu event of its own) did nothing.

Now all of them open the menu at the current row (scrolled into view),
or in the middle of the list when there is none. A right click still
opens it at the pointer.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QPoint, Qt  # noqa: E402
from PyQt6.QtGui import QContextMenuEvent, QCursor  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMenu  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from ui.file_pane import FilePaneWidget  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def pane(tmp_path):
    for i in range(60):
        (tmp_path / f"f{i:02d}.txt").write_text("x")
    widget = FilePaneWidget(LocalFS())
    widget.resize(600, 300)
    widget.show()
    widget.navigate(str(tmp_path))
    APP.processEvents()
    widget._table.setFocus()
    APP.processEvents()
    yield widget
    widget.close()
    widget.deleteLater()
    APP.processEvents()


@pytest.fixture
def shown():
    """Where each menu opened (QMenu.exec does not run)."""
    places: list[QPoint] = []
    with mock.patch.object(QMenu, "exec", lambda self, *a, **k: places.append(a[0]) or None):
        yield places


def _row_place(pane) -> QPoint:
    table = pane._table
    rect = table.visualRect(table.currentIndex())
    assert table.viewport().rect().contains(rect.center())
    return table.viewport().mapToGlobal(rect.bottomLeft())


def _go_down(pane, times: int) -> None:
    for _ in range(times):
        QTest.keyClick(pane._table, Qt.Key.Key_Down)


def test_happy_f10_opens_at_the_current_row(pane, shown):
    QCursor.setPos(1, 1)
    _go_down(pane, 3)
    QTest.keyClick(pane._table, Qt.Key.Key_F10)
    assert shown == [_row_place(pane)]


@pytest.mark.parametrize("target", ["table", "viewport"])
def test_sad_a_keyboard_context_menu_event_opens_at_the_row_not_the_pointer(pane, shown, target):
    QCursor.setPos(1, 1)
    _go_down(pane, 4)
    widget = pane._table if target == "table" else pane._table.viewport()
    event = QContextMenuEvent(QContextMenuEvent.Reason.Keyboard, QPoint(5, 5),
                              widget.mapToGlobal(QPoint(5, 5)))
    APP.sendEvent(widget, event)
    assert shown == [_row_place(pane)]


@pytest.mark.parametrize("key, mods", [
    (Qt.Key.Key_Menu, Qt.KeyboardModifier.NoModifier),
    (Qt.Key.Key_F10, Qt.KeyboardModifier.ShiftModifier),
])
def test_sad_the_menu_key_and_shift_f10_as_key_presses(pane, shown, key, mods):
    _go_down(pane, 2)
    QTest.keyClick(pane._table, key, mods)
    assert shown == [_row_place(pane)]


def test_edge_a_row_scrolled_out_of_view_is_scrolled_in(pane, shown):
    _go_down(pane, 2)
    pane._table.scrollToBottom()
    APP.processEvents()
    QTest.keyClick(pane._table, Qt.Key.Key_F10)
    assert shown == [_row_place(pane)]


def test_edge_a_right_click_still_opens_at_the_pointer(pane, shown):
    vp = pane._table.viewport()
    QCursor.setPos(vp.mapToGlobal(QPoint(30, 40)))
    event = QContextMenuEvent(QContextMenuEvent.Reason.Mouse, QPoint(30, 40),
                              vp.mapToGlobal(QPoint(30, 40)))
    APP.sendEvent(vp, event)
    assert shown == [QCursor.pos()]
