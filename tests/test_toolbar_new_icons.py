"""New toolbar buttons for the features added lately: thumbnails, media
viewer, index search, compare, disk usage, metadata, pack, extensions -
in the toolbar's own icon style, for every theme."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QToolBar  # noqa: E402

from ui import icon_provider as IP  # noqa: E402

APP = QApplication.instance() or QApplication([])

NEW = (
    "thumbnails",
    "media-view",
    "find-index",
    "compare",
    "disk-usage",
    "metadata",
    "pack",
    "extensions",
)


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture
def window(tmp_path):
    from ui.main_window import MainWindow

    win = MainWindow()
    win._reconnect_timer.stop()
    win.show()
    win._active_pane.navigate(str(tmp_path))
    pump()
    yield win
    win.close()
    win.deleteLater()
    pump()


def _toolbar(win) -> QToolBar:
    return next(tb for tb in win.findChildren(QToolBar) if tb.windowTitle() == "Main")


def _by_icon(win) -> dict:
    return {a.property("axIcon"): a for a in _toolbar(win).actions() if a.property("axIcon")}


# --- happy -----------------------------------------------------------------


def test_happy_the_new_icons_exist_in_the_style_and_palette() -> None:
    for name in NEW:
        assert IP.has_icon(name), name
        svg = IP.ICONS[name]
        assert 'viewBox="0 0 24 24"' in svg and 'stroke="currentColor"' in svg
        assert IP._ICON_COLORS.get(name), name
        assert name in IP.available_icons()
        assert not IP.icon(name).isNull()


def test_happy_the_toolbar_carries_them_after_the_existing_ones(window) -> None:
    by_icon = _by_icon(window)
    for name in NEW:
        assert name in by_icon, name
        assert by_icon[name].toolTip()
    order = list(by_icon)
    assert order.index("duplicates") < order.index("thumbnails")


def test_happy_the_buttons_are_the_menu_actions(window) -> None:
    by_icon = _by_icon(window)
    assert by_icon["thumbnails"] is window.thumbnail_view_action
    by_icon["thumbnails"].trigger()
    assert window._active_pane.view_mode == "thumbnails"
    by_icon["thumbnails"].trigger()
    assert window._active_pane.view_mode == "details"


def test_happy_every_theme_and_monochrome_keep_the_icons(window) -> None:
    for theme in ("hacker", "amber", "modern-light", "default"):
        try:
            window._apply_theme(theme)
        except KeyError:
            continue
        pump()
        for name, action in _by_icon(window).items():
            assert not action.icon().isNull(), (theme, name)
    IP.set_monochrome(True)
    try:
        assert not IP.icon("pack").isNull()
    finally:
        IP.set_monochrome(False)


def test_happy_every_toolbar_icon_has_a_palette_colour(window) -> None:
    # The Duplicate Finder button had none and drew black on the dark
    # themes - next to invisible.
    missing = [name for name in _by_icon(window) if not IP._ICON_COLORS.get(name)]
    assert missing == [], missing


# --- sad -------------------------------------------------------------------


def test_sad_pack_and_metadata_without_a_selection(window, monkeypatch) -> None:
    opened = []
    pane = window._active_pane
    monkeypatch.setattr(pane, "open_metadata", lambda action: opened.append(action))
    by_icon = _by_icon(window)
    by_icon["pack"].trigger()  # nothing selected: says so, packs nothing
    assert "Select" in window.statusBar().currentMessage()
    by_icon["metadata"].trigger()  # the folder itself, as in the context menu
    assert opened == ["show"]


def test_sad_buttons_without_a_file_pane_do_not_raise(window) -> None:
    window._active_pane = None
    by_icon = _by_icon(window)
    for name in ("pack", "metadata"):
        by_icon[name].trigger()
    assert "No file pane" in window.statusBar().currentMessage()


# --- edge ------------------------------------------------------------------


def test_edge_no_shortcut_is_bound_twice_with_the_new_buttons(window) -> None:
    from PyQt6.QtGui import QAction

    owners: dict[str, set[int]] = {}
    for action in window.findChildren(QAction):
        for seq in action.shortcuts():
            if seq.toString():
                owners.setdefault(seq.toString(), set()).add(id(action))
    assert {k: len(v) for k, v in owners.items() if len(v) > 1} == {}
