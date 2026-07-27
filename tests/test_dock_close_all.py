#!/usr/bin/env python3
"""Close-all button on the dock title bar.

The bottom dock area stacks four panels (Transfers, Terminal, Log,
Console). Dismissing them meant hitting each panel's X in turn, and
because they are tabified the next one only becomes reachable after the
previous closes — so "clear the bottom strip" was four aimed clicks.

``DockTitleBar`` therefore carries a second close button that clears
every panel sharing that dock's area in one go. Scope is deliberately
the dock AREA, not the whole window: pressing it on a bottom panel must
not also dismiss the Bookmarks sidebar on the left, which is a
different workspace decision.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import (  # noqa: E402
    QApplication,
    QDockWidget,
    QLabel,
    QMainWindow,
)

from ui.dock_titlebar import DockTitleBar  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _dock(window: QMainWindow, title: str, area: Qt.DockWidgetArea) -> QDockWidget:
    dock = QDockWidget(title, window)
    dock.setWidget(QLabel(title, dock))
    window.addDockWidget(area, dock)
    dock.setTitleBarWidget(DockTitleBar(title, "inbox", dock))
    dock.show()
    return dock


@pytest.fixture()
def window():
    win = QMainWindow()
    win.resize(900, 600)
    bottom = Qt.DockWidgetArea.BottomDockWidgetArea
    left = Qt.DockWidgetArea.LeftDockWidgetArea
    win.docks = {
        "transfers": _dock(win, "Transfers", bottom),
        "terminal": _dock(win, "Terminal", bottom),
        "log": _dock(win, "Log", bottom),
        "bookmarks": _dock(win, "Bookmarks", left),
    }
    win.show()
    APP.processEvents()
    try:
        yield win
    finally:
        win.close()
        win.deleteLater()
        APP.processEvents()


def _bar(dock: QDockWidget) -> DockTitleBar:
    return dock.titleBarWidget()


# --------------------------------------------------------------------------
# Happy path
# --------------------------------------------------------------------------


def test_happy_close_all_clears_every_dock_in_the_same_area(window):
    _bar(window.docks["log"])._close_all()
    APP.processEvents()

    for name in ("transfers", "terminal", "log"):
        assert not window.docks[name].isVisible(), f"{name} should have been closed"


def test_happy_other_dock_areas_are_left_alone(window):
    _bar(window.docks["log"])._close_all()
    APP.processEvents()

    assert window.docks["bookmarks"].isVisible(), (
        "close-all on a BOTTOM panel must not dismiss the LEFT sidebar"
    )


def test_happy_single_close_button_still_closes_only_its_own_dock(window):
    """The per-panel X keeps its old meaning — the new button is an
    addition, not a replacement."""
    window.docks["log"].close()
    APP.processEvents()

    assert not window.docks["log"].isVisible()
    assert window.docks["terminal"].isVisible()
    assert window.docks["transfers"].isVisible()


def test_happy_button_exists_and_is_reachable(window):
    bar = _bar(window.docks["terminal"])
    assert bar._close_all_btn is not None
    assert bar._close_all_btn.isEnabled()
    assert bar._close_all_btn.toolTip()


# --------------------------------------------------------------------------
# Edge cases
# --------------------------------------------------------------------------


def test_edge_already_hidden_docks_stay_hidden_and_do_not_raise(window):
    window.docks["terminal"].close()
    APP.processEvents()

    _bar(window.docks["log"])._close_all()
    APP.processEvents()

    assert not window.docks["terminal"].isVisible()
    assert not window.docks["log"].isVisible()


def test_edge_close_all_is_idempotent(window):
    bar = _bar(window.docks["log"])
    bar._close_all()
    APP.processEvents()
    bar._close_all()  # second press must be a no-op, not an error
    APP.processEvents()

    assert not window.docks["log"].isVisible()
    assert window.docks["bookmarks"].isVisible()


def test_edge_sibling_docks_includes_self_and_only_the_same_area(window):
    siblings = _bar(window.docks["log"]).sibling_docks()
    titles = {d.windowTitle() for d in siblings}
    assert titles == {"Transfers", "Terminal", "Log"}


# --------------------------------------------------------------------------
# Sad path
# --------------------------------------------------------------------------


def test_sad_dock_without_a_main_window_falls_back_to_closing_itself():
    """A dock that was never added to a QMainWindow has no area to
    enumerate. The button must degrade to a plain close instead of
    raising — a title bar is constructible before the dock is placed."""
    orphan = QDockWidget("Orphan")
    orphan.setWidget(QLabel("x", orphan))
    bar = DockTitleBar("Orphan", "inbox", orphan)
    orphan.setTitleBarWidget(bar)
    orphan.show()
    APP.processEvents()

    assert bar.sibling_docks() == [orphan]
    bar._close_all()
    APP.processEvents()
    assert not orphan.isVisible()

    orphan.deleteLater()
    APP.processEvents()


def test_sad_floating_dock_only_closes_itself(window):
    """A floated panel reports no dock area. Closing 'all' from it must
    not reach back into the area it was pulled out of — the user
    detached it precisely to treat it separately."""
    log = window.docks["log"]
    log.setFloating(True)
    APP.processEvents()

    _bar(log)._close_all()
    APP.processEvents()

    assert not log.isVisible()
    assert window.docks["terminal"].isVisible()
    assert window.docks["transfers"].isVisible()


# --------------------------------------------------------------------------
# Icon
# --------------------------------------------------------------------------


def test_close_all_icon_is_registered_and_distinct():
    from ui.icon_provider import ICONS, has_icon

    assert has_icon("close-all-panes")
    assert ICONS["close-all-panes"] != ICONS["close-pane"]
