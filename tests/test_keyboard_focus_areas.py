"""The keyboard reaches every area of the window, and only what is in view.

Found in review round 3 (UX, repros ``focus_trap.py`` / ``a11y_names.py``):

* Shift+Tab from a pane's path bar went through the title-bar buttons of
  the four panels tabbed away behind Transfers (Qt counts them visible)
  and ended in the Console REPL off screen, where Tab completes - there
  was no way out, Esc did nothing.
* No key moved between the window's areas: Tab in a file list cycles the
  panes, so Transfers or a panel could not be reached from the keyboard.
  Now View > Focus Next Area / Previous Area, Ctrl+F6 / Ctrl+Shift+F6
  (F6 is Move to Target).
* Twenty buttons showed only a glyph (↑ ⌂ ☆ ↻ ◉ ◎ ✕) or an icon (the
  panels' float and close) and had no accessible name: a screen reader
  read the glyph or nothing.
"""

from __future__ import annotations

import os
import re
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
from PyQt6.QtWidgets import QAbstractButton, QApplication, QDockWidget  # noqa: E402

from core import agent_settings as AGS  # noqa: E402
from core import bookmarks as BM  # noqa: E402

APP = QApplication.instance() or QApplication([])
CTRL = Qt.KeyboardModifier.ControlModifier
SHIFT = Qt.KeyboardModifier.ShiftModifier


def _pump(seconds: float = 0.15) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture
def win(tmp_path, monkeypatch):
    monkeypatch.setattr(AGS, "settings_file", lambda: tmp_path / "agent" / "settings.json")
    from core import agent_session as AS

    monkeypatch.setattr(AS, "sessions_dir", lambda: tmp_path / "agent" / "sessions")
    with mock.patch("pathlib.Path.home", return_value=tmp_path), \
            mock.patch.object(BM, "BOOKMARKS_FILE", tmp_path / "bookmarks.json"):
        from ui.main_window import MainWindow

        w = MainWindow()
        w._reconnect_timer.stop()
        w.resize(1280, 800)
        w.show()
        w.activateWindow()
        _pump(0.4)
        w._split_pane(Qt.Orientation.Horizontal)
        _pump(0.4)
        yield w
        w._agent_dock.shutdown()
        w.close()
        w.deleteLater()
        _pump(0.1)


def _dock_of(widget):
    while widget is not None and not isinstance(widget, QDockWidget):
        widget = widget.parentWidget()
    return widget


def _in_view(widget) -> bool:
    """Not inside a docked panel whose region is empty (tabbed away)."""
    dock = _dock_of(widget)
    return dock is None or dock.isFloating() or not dock.visibleRegion().isEmpty()


def _area_of(window, widget):
    for pane in window._panes:
        if pane is widget or pane.isAncestorOf(widget):
            return pane
    return _dock_of(widget)


def _press(key, mods=Qt.KeyboardModifier.NoModifier) -> None:
    QTest.keyClick(APP.focusWidget(), key, mods)
    _pump(0.05)


# -- happy ---------------------------------------------------------------------


@pytest.mark.parametrize("mods", [SHIFT, Qt.KeyboardModifier.NoModifier],
                         ids=["shift-tab-from-the-path-bar", "tab-from-the-status-bar"])
def test_happy_tab_stops_only_where_the_user_can_see(win, mods):
    """Shift+Tab went into the panels tabbed away and the off-screen REPL;
    Tab from the status bar into the Terminal panel behind Transfers."""
    assert win._console_dock.visibleRegion().isEmpty()  # behind Transfers
    start = win._active_pane._path_edit if mods == SHIFT else win._version_button
    start.setFocus()
    _pump()
    hidden = []
    for _ in range(60):
        _press(Qt.Key.Key_Tab, mods)
        focus = APP.focusWidget()
        if not _in_view(focus):
            hidden.append(f"{type(focus).__name__} in {_dock_of(focus).objectName()}")
    assert hidden == []
    assert APP.focusWidget() is not win._console_dock.repl


def test_happy_esc_in_the_console_goes_back_to_the_file_pane(win):
    win._console_dock.show()
    win._console_dock.raise_()
    _pump(0.3)
    repl = win._console_dock.repl
    repl.setFocus()
    _pump()
    assert APP.focusWidget() is repl
    QTest.keyClick(repl, Qt.Key.Key_Escape)
    _pump()
    assert APP.focusWidget() is win._active_pane._table


def test_happy_ctrl_f6_visits_the_panes_then_the_panels_in_view(win):
    first, second = win._panes[:2]
    first._table.setFocus()
    _pump()
    visited, active = [], []
    for _ in range(len(win._focus_areas())):
        _press(Qt.Key.Key_F6, CTRL)
        visited.append(_area_of(win, APP.focusWidget()))
        active.append(win._active_pane)
    assert visited[0] is second and active[0] is second
    assert win._transfer_dock in visited
    assert win._console_dock not in visited  # tabbed away behind Transfers
    assert visited[-1] is first  # round and back to the start
    assert all(_in_view(w) for w in visited)


def test_happy_ctrl_shift_f6_goes_back(win):
    first = win._panes[0]
    first._table.setFocus()
    _pump()
    _press(Qt.Key.Key_F6, CTRL | SHIFT)
    assert _area_of(win, APP.focusWidget()) is win._focus_areas()[-1]
    _press(Qt.Key.Key_F6, CTRL)
    assert APP.focusWidget() is first._table


def test_happy_symbol_buttons_have_an_accessible_name(win):
    unnamed = []
    for button in win.findChildren(QAbstractButton):
        if not button.isVisibleTo(win):
            continue
        text = button.text().replace("&", "").strip()
        if not re.search(r"[A-Za-zÄÖÜäöü]{2,}", text) and not button.accessibleName():
            unnamed.append((text, button.toolTip()[:40], button.objectName()))
    assert unnamed == []
    pane = win._active_pane
    assert pane._btn_up.accessibleName() == "Parent directory"
    assert pane._btn_target.accessibleName() == "Set as transfer target"
    bar = win._transfer_dock.titleBarWidget()
    assert "Transfers" in bar._close_btn.accessibleName()


# -- sad -----------------------------------------------------------------------


def test_sad_esc_with_a_modifier_stays_in_the_console(win):
    win._console_dock.show()
    win._console_dock.raise_()
    _pump(0.3)
    repl = win._console_dock.repl
    repl.setFocus()
    _pump()
    QTest.keyClick(repl, Qt.Key.Key_Escape, SHIFT)
    _pump()
    assert APP.focusWidget() is repl
    QTest.keyClick(repl, Qt.Key.Key_Escape)  # the plain key does leave
    _pump()
    assert APP.focusWidget() is win._active_pane._table


# -- edge ----------------------------------------------------------------------


def test_edge_a_raised_panel_becomes_an_area_and_the_one_behind_it_does_not(win):
    win._console_dock.show()
    win._console_dock.raise_()
    _pump(0.3)
    areas = win._focus_areas()
    assert win._console_dock in areas
    assert win._transfer_dock not in areas  # now the tab behind
    win._panes[0]._table.setFocus()
    _pump()
    for _ in range(len(areas)):
        if _area_of(win, APP.focusWidget()) is win._console_dock:
            break
        _press(Qt.Key.Key_F6, CTRL)
    assert APP.focusWidget() is win._console_dock.repl


def test_edge_the_area_keys_are_listed_and_in_the_view_menu(win):
    from ui.shortcuts_dialog import SHORTCUTS

    listed = {k for _s, keys, _d in SHORTCUTS for k in keys}
    assert {"Ctrl+F6", "Ctrl+Shift+F6", "Esc"} <= listed
    assert win._next_area_action.shortcut().toString() == "Ctrl+F6"
    assert win._prev_area_action.shortcut().toString() == "Ctrl+Shift+F6"
