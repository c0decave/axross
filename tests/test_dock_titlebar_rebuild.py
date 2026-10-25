"""A theme or icon switch rebuilds the dock title bars without leaking the old ones.

2026-10-25 performance round: ``_rebuild_dock_titlebars`` set a fresh
DockTitleBar on six docks per theme or icon-colour switch; QDockWidget
hides a replaced title bar but does not delete it. Each switch left 36
hidden widgets behind, and every later setStyleSheet repolished them too:
14 switches in a row went from 165 to 389 ms of GUI-thread CPU.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QDockWidget  # noqa: E402

from tests.settings_testkit import app, isolate  # noqa: E402
from ui import themes  # noqa: E402
from ui.dock_titlebar import DockTitleBar  # noqa: E402

APP = app()


@pytest.fixture
def stores(tmp_path, monkeypatch):
    s = isolate(tmp_path, monkeypatch)
    yield s
    s.close_windows()
    s.restore()


def _flush() -> None:
    APP.processEvents()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)


def _bars(win) -> dict[str, int]:
    """Title bars per dock title, the hidden replaced ones included."""
    return {dock.windowTitle(): len(dock.findChildren(DockTitleBar))
            for dock in win.findChildren(QDockWidget)}


def test_happy_theme_switches_keep_one_title_bar_per_dock(stores):
    win = stores.make_window()
    _flush()
    before = _bars(win)
    for theme, _label in themes.THEME_CHOICES * 2:
        win.set_theme(theme, store=False)
        _flush()
    assert _bars(win) == before
    assert all(count <= 1 for count in before.values()), before


def test_happy_the_new_title_bar_works_after_a_rebuild(stores):
    win = stores.make_window()
    dock = win._log_dock
    win.set_monochrome_icons(True, store=False)
    win.set_monochrome_icons(False, store=False)
    _flush()
    bar = dock.titleBarWidget()
    assert isinstance(bar, DockTitleBar) and len(dock.findChildren(DockTitleBar)) == 1
    dock.show()
    bar._close_btn.click()
    assert not dock.isVisible()


def test_edge_icon_colour_switches_do_not_grow_the_widget_count(stores):
    win = stores.make_window()
    _flush()
    start = len(APP.allWidgets())
    for choice in ("coloured", "theme", "coloured", "theme"):
        win.set_icon_colours(choice)
        _flush()
    assert len(APP.allWidgets()) <= start


def test_sad_a_dock_without_a_title_bar_gets_one_and_loses_nothing(stores):
    win = stores.make_window()
    dock = win._log_dock
    bar = dock.titleBarWidget()
    dock.setTitleBarWidget(None)  # Qt's own title bar again
    bar.deleteLater()
    _flush()
    assert dock.titleBarWidget() is None
    win._rebuild_dock_titlebars()
    _flush()
    assert isinstance(dock.titleBarWidget(), DockTitleBar)
    assert len(dock.findChildren(DockTitleBar)) == 1
