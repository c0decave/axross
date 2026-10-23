"""The tool buttons never vanish off the edge of the window.

Reported: "kein agent icon in der menu leiste". All ~35 buttons sat in one
toolbar row; at the default 1200 px six of them (Trash ... Settings,
Features) were cut off, at 900 px (half a tiled screen) fourteen - the
Agent button among them - and Qt's overflow button was a 12 px strip with
no visible arrow in the dark themes.

Now the tools (Agent, Analysis, Terminal, Find Files, ... Features) are a
toolbar of their own, "Tools", that moves to a second row when both do not
fit side by side; and the overflow button, needed only when a single bar is
wider than the window, shows a visible arrow.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QToolBar, QToolButton  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def window(tmp_path):
    from ui import main_window as MW

    patches = [
        mock.patch.object(MW.MainWindow, "_SESSION_FILE", tmp_path / "s.json"),
        mock.patch.object(MW.MainWindow, "_RECENTS_FILE", tmp_path / "r.json"),
        mock.patch("pathlib.Path.home", return_value=tmp_path),
    ]
    for p in patches:
        p.start()
    try:
        win = MW.MainWindow()
    finally:
        for p in patches:
            p.stop()
    win.show()
    yield win
    win.close()
    win.deleteLater()


def _bar(win, title):
    return next(tb for tb in win.findChildren(QToolBar) if tb.windowTitle() == title)


def _resize(win, width):
    win.resize(width, 700)
    for _ in range(10):
        APP.processEvents()


def _visible(bar, action):
    widget = bar.widgetForAction(action)
    return widget is not None and widget.isVisible()


# --- happy ----------------------------------------------------------------


def test_happy_the_tools_are_a_toolbar_of_their_own(window):
    tools = _bar(window, "Tools")
    assert window._agent_dock.toggleViewAction() in tools.actions()
    assert window._settings_action in tools.actions()
    assert window._features_action in tools.actions()
    assert window._agent_dock.toggleViewAction() not in _bar(window, "Main").actions()


def test_happy_on_a_narrow_window_the_tools_wrap_and_every_tool_stays_visible(window):
    _resize(window, 900)
    tools = _bar(window, "Tools")
    assert window.toolBarBreak(tools)
    hidden = [a.toolTip() for a in tools.actions()
              if not a.isSeparator() and not _visible(tools, a)]
    assert hidden == []
    assert _visible(tools, window._agent_dock.toggleViewAction())


def test_happy_on_a_wide_window_both_bars_share_one_row(window):
    _resize(window, 2400)
    assert not window.toolBarBreak(_bar(window, "Tools"))
    main, tools = _bar(window, "Main"), _bar(window, "Tools")
    assert main.geometry().top() == tools.geometry().top()


# --- sad ------------------------------------------------------------------


def test_sad_a_window_narrower_than_one_bar_shows_a_visible_overflow_arrow(window):
    _resize(window, 420)
    main = _bar(window, "Main")
    ext = main.findChild(QToolButton, "qt_toolbar_ext_button")
    assert ext is not None and ext.isVisible()
    assert ext.width() >= 20
    image = ext.icon().pixmap(16, 16).toImage()
    painted = sum(1 for x in range(16) for y in range(16) if image.pixelColor(x, y).alpha() > 0)
    assert painted > 10


# --- edge -----------------------------------------------------------------


def test_edge_widening_again_joins_the_rows_and_no_break_piles_up(window):
    tools = _bar(window, "Tools")
    for width in (900, 2400, 900, 2400):
        _resize(window, width)
        assert window.toolBarBreak(tools) == (width == 900), width
    assert window.toolBarBreak(_bar(window, "Main")) is False
