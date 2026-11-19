"""Splitting, closing and moving panes leave the keyboard in a file list.

Found in review (round 1 of the 2026-11 reviews, UI shell; reproduced with
the keys): Ctrl+Shift+H moved the focus from the file list to the tab bar
of the bottom docks (Transfers / Terminal / Log), so the next arrow key
switched dock tabs; Ctrl+W left it on the remaining pane's frame, where
the arrow keys moved nothing; Extract Pane to Root left no focus at all,
and closing the last pane of a workspace put it on the dock tab bar too.
Qt moves the focus on when the focused list is hidden by the reparenting -
the window now puts it back into the active pane's list.
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

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import agent_settings as AGS  # noqa: E402
from core import bookmarks as BM  # noqa: E402

APP = QApplication.instance() or QApplication([])
CTRL = Qt.KeyboardModifier.ControlModifier
SHIFT = Qt.KeyboardModifier.ShiftModifier
ALT = Qt.KeyboardModifier.AltModifier


def _pump(seconds: float = 0.2) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture
def win(tmp_path, monkeypatch):
    monkeypatch.setattr(AGS, "settings_file", lambda: tmp_path / "agent" / "settings.json")
    from core import agent_session as AS

    monkeypatch.setattr(AS, "sessions_dir", lambda: tmp_path / "agent" / "sessions")
    work = tmp_path / "work"
    work.mkdir()
    for name in ("a.txt", "b.txt"):
        (work / name).write_text(name)
    with mock.patch("pathlib.Path.home", return_value=tmp_path), \
            mock.patch.object(BM, "BOOKMARKS_FILE", tmp_path / "bookmarks.json"):
        from ui.main_window import MainWindow

        w = MainWindow()
        w._reconnect_timer.stop()
        w.resize(1200, 800)
        w.show()
        w.activateWindow()
        _pump(0.3)
        w._active_pane.navigate(str(work))
        _pump(0.3)
        yield w
        w._agent_dock.shutdown()
        w.close()
        w.deleteLater()
        _pump(0.1)


def _press(win, key, mods=Qt.KeyboardModifier.NoModifier) -> None:
    win._active_pane._table.setFocus()
    _pump(0.1)
    assert QApplication.focusWidget() is win._active_pane._table
    QTest.keyClick(QApplication.focusWidget(), key, mods)
    _pump(0.4)


def _focus_is_in_the_active_list(win) -> bool:
    pane = win._active_pane
    return pane in win._panes and QApplication.focusWidget() is pane._table


# -- happy ---------------------------------------------------------------------


@pytest.mark.parametrize("key", [Qt.Key.Key_H, Qt.Key.Key_V])
def test_happy_split_keeps_the_focus_in_the_list(win, key):
    pane = win._active_pane
    _press(win, key, CTRL | SHIFT)
    assert len(win._panes) == 2
    assert win._active_pane is pane
    assert QApplication.focusWidget() is pane._table, QApplication.focusWidget()


def test_happy_ctrl_w_puts_the_focus_into_the_remaining_list(win):
    _press(win, Qt.Key.Key_H, CTRL | SHIFT)
    _press(win, Qt.Key.Key_W, CTRL)
    assert len(win._panes) == 1
    assert _focus_is_in_the_active_list(win), QApplication.focusWidget()
    # ... and the arrow keys move in it.
    table = win._active_pane._table
    before = table.currentIndex().row()
    QTest.keyClick(table, Qt.Key.Key_Down)
    _pump(0.1)
    assert table.currentIndex().row() != before


def test_happy_new_workspace_has_the_focus_in_its_list(win):
    _press(win, Qt.Key.Key_N, CTRL | ALT)
    assert len(win._workspaces) == 2
    assert win.workspace_of(win._active_pane) is win._current_ws
    assert _focus_is_in_the_active_list(win), QApplication.focusWidget()


# -- sad -----------------------------------------------------------------------


def test_sad_extract_pane_to_root_leaves_the_focus_in_its_list(win):
    _press(win, Qt.Key.Key_H, CTRL | SHIFT)
    _press(win, Qt.Key.Key_V, CTRL | SHIFT)
    pane = win._active_pane
    _press(win, Qt.Key.Key_X, CTRL | SHIFT)
    assert win._active_pane is pane
    assert QApplication.focusWidget() is pane._table, QApplication.focusWidget()


def test_sad_closing_the_last_pane_of_a_workspace_focuses_a_list(win):
    _press(win, Qt.Key.Key_N, CTRL | ALT)
    assert len(win._workspaces) == 2
    _press(win, Qt.Key.Key_W, CTRL)
    assert len(win._workspaces) == 1
    assert _focus_is_in_the_active_list(win), QApplication.focusWidget()


# -- edge ----------------------------------------------------------------------


def test_edge_the_pane_frame_hands_its_focus_to_the_list(win):
    pane = win._active_pane
    pane.setFocus(Qt.FocusReason.OtherFocusReason)
    _pump(0.1)
    assert QApplication.focusWidget() is pane._table


def test_edge_thumbnail_view_keeps_its_own_focus(win):
    pane = win._active_pane
    _press(win, Qt.Key.Key_G, CTRL | SHIFT)
    assert pane.view_mode == "thumbnails"
    pane.setFocus(Qt.FocusReason.OtherFocusReason)
    _pump(0.1)
    assert QApplication.focusWidget() is pane._thumbs


def test_edge_a_split_from_the_path_bar_leaves_the_focus_there(win):
    """Only a focus that was in a pane's list is put back: one in a text
    field stays where it is."""
    win._active_pane._table.setFocus()
    _pump(0.1)
    QTest.keyClick(win._active_pane._table, Qt.Key.Key_L, CTRL)
    _pump(0.2)
    field = QApplication.focusWidget()
    assert field is not win._active_pane._table
    QTest.keyClick(field, Qt.Key.Key_H, CTRL | SHIFT)
    _pump(0.4)
    assert len(win._panes) == 2
    assert QApplication.focusWidget() is field
