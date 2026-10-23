"""Toolbar buttons for the tools: Agent, Analysis, Terminal, Find Files, Scripts,
Tagged Files, Trash, Media Player, Folder Treemap, Drives Overview,
Settings and Features.

The operator asked: "haben wir icons in der icon leiste fuer agent dock,
musik player, und viele andere coole tools die wir supporten? falls nicht
bitte passende icons erstellen, auch fuer alle themes und einbauen".
Before, the toolbar ended at "Manage extensions"; none of these had a
button, most had no icon at all. Each button is the menu's own QAction
where one exists (one shortcut owner, one check state). An extension tool
that is switched off asks to switch it on, then shows its panel.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QMessageBox, QToolBar  # noqa: E402

from ui import icon_provider as IP  # noqa: E402

APP = QApplication.instance() or QApplication([])

#: The new tool buttons, in toolbar order.
TOOLS = (
    "agent",
    "analysis",
    "terminal",
    "find-files",
    "scripts",
    "console",
    "tag",
    "trash",
    "media-player",
    "treemap",
    "drives",
    "settings",
    "features",
)
NEW_ICONS = ("agent", "analysis", "find-files", "scripts", "console", "media-player", "treemap",
             "drives", "features")
EXTENSIONS = {
    "media-player": "bundled:media_player",
    "treemap": "bundled:folder_treemap",
    "drives": "bundled:drives_overview",
}


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
    for ext_id in EXTENSIONS.values():
        win.extension_host.set_enabled(ext_id, False)
    win.close()
    win.deleteLater()
    pump()


def _by_icon(win) -> dict:
    # Main, then Tools (the tools moved to a bar of their own that wraps
    # to a second row on a narrow window): toolbar order.
    bars = [tb for title in ("Main", "Tools") for tb in win.findChildren(QToolBar)
            if tb.windowTitle() == title]
    return {a.property("axIcon"): a for bar in bars for a in bar.actions() if a.property("axIcon")}


def _luminance(hex_colour: str) -> float:
    def channel(c: int) -> float:
        c = c / 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = (int(hex_colour[i:i + 2], 16) for i in (1, 3, 5))
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def _contrast(a: str, b: str) -> float:
    la, lb = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


# --- happy -----------------------------------------------------------------


def test_happy_the_new_icons_exist_in_the_toolbar_style() -> None:
    for name in NEW_ICONS:
        assert IP.has_icon(name), name
        svg = IP.ICONS[name]
        assert 'viewBox="0 0 24 24"' in svg and 'stroke="currentColor"' in svg, name
        assert IP._ICON_COLORS.get(name), name
        assert not IP.icon(name).isNull(), name
        assert name in IP.available_icons()


def test_happy_the_tool_buttons_follow_the_feature_buttons(window) -> None:
    by_icon = _by_icon(window)
    order = list(by_icon)
    for name in TOOLS:
        assert name in by_icon, name
        assert by_icon[name].toolTip(), name
    positions = [order.index(n) for n in TOOLS]
    assert positions == sorted(positions)
    assert order.index("extensions") < positions[0]


def test_happy_dock_buttons_are_the_docks_own_toggles(window) -> None:
    by_icon = _by_icon(window)
    assert by_icon["agent"] is window._agent_dock.toggleViewAction()
    assert by_icon["analysis"] is window._analysis_dock.toggleViewAction()
    assert by_icon["scripts"] is window._scripts_dock.toggleViewAction()
    # The scripting engine: the Python console with the axross.* API.
    assert by_icon["console"] is window._console_dock.toggleViewAction()
    assert by_icon["terminal"] is window._terminal_dock.toggleViewAction()
    window._agent_dock.hide()
    pump()
    by_icon["agent"].trigger()
    pump()
    assert window._agent_dock.isVisible()
    by_icon["agent"].trigger()
    pump()
    assert not window._agent_dock.isVisible()


def test_happy_menu_buttons_are_the_menu_actions(window) -> None:
    by_icon = _by_icon(window)
    assert by_icon["find-files"] is window._find_files_action
    assert by_icon["settings"] is window._settings_action
    assert by_icon["features"] is window._features_action
    assert by_icon["tag"] is window._tagged_action


def test_happy_e2e_a_switched_off_extension_asks_then_shows_its_panel(window, monkeypatch) -> None:
    asked = []
    monkeypatch.setattr(QMessageBox, "question",
                        lambda *a, **k: asked.append(a[2]) or QMessageBox.StandardButton.Yes)
    host = window.extension_host
    ext_id = EXTENSIONS["treemap"]
    assert ext_id not in host.loaded_ids()
    _by_icon(window)["treemap"].trigger()
    pump(0.3)
    assert len(asked) == 1 and "Folder Treemap" in asked[0]
    assert ext_id in host.loaded_ids()
    dock = host.docks(ext_id)[0]
    assert dock.isVisible()
    _by_icon(window)["treemap"].trigger()  # loaded: the button toggles the panel
    pump()
    assert not dock.isVisible()
    _by_icon(window)["treemap"].trigger()
    pump()
    assert dock.isVisible() and len(asked) == 1


def test_happy_trash_opens_the_active_panes_trash(window, monkeypatch) -> None:
    opened = []
    monkeypatch.setattr(window._active_pane, "_show_trash_browser", lambda: opened.append(1))
    _by_icon(window)["trash"].trigger()
    assert opened == [1]


# --- sad -------------------------------------------------------------------


def test_sad_saying_no_leaves_the_extension_off(window, monkeypatch) -> None:
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.No)
    _by_icon(window)["drives"].trigger()
    pump()
    assert EXTENSIONS["drives"] not in window.extension_host.loaded_ids()


def test_sad_an_extension_that_cannot_load_says_why(window, monkeypatch) -> None:
    from core import extensions as EX

    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    monkeypatch.setattr(EX, "extensions_allowed", lambda: False)  # the paranoid mode
    _by_icon(window)["media-player"].trigger()
    pump()
    assert EXTENSIONS["media-player"] not in window.extension_host.loaded_ids()
    assert "paranoid" in window.statusBar().currentMessage()


def test_sad_trash_without_a_file_pane_does_not_raise(window) -> None:
    window._active_pane = None
    _by_icon(window)["trash"].trigger()
    assert "No file pane" in window.statusBar().currentMessage()


# --- edge ------------------------------------------------------------------


def test_edge_every_theme_and_monochrome_keep_the_tool_icons(window) -> None:
    for theme in ("hacker", "amber", "modern-light", "default"):
        try:
            window._apply_theme(theme)
        except KeyError:
            continue
        pump()
        for name in TOOLS:
            assert not _by_icon(window)[name].icon().isNull(), (theme, name)
    IP.set_monochrome(True)
    try:
        for name in NEW_ICONS:
            assert not IP.icon(name).isNull()
    finally:
        IP.set_monochrome(False)


def test_edge_the_new_colours_read_on_dark_and_light_backgrounds() -> None:
    # Medium saturation, as the rest of the palette: visible on the dark
    # (#1e1e2e) and the light (#ffffff) themes alike.
    for name in NEW_ICONS:
        colour = IP._ICON_COLORS[name]
        assert _contrast(colour, "#1e1e2e") >= 3.0, (name, colour)
        assert _contrast(colour, "#ffffff") >= 1.8, (name, colour)


def test_edge_an_extension_switched_off_again_asks_again(window, monkeypatch) -> None:
    asked = []
    monkeypatch.setattr(QMessageBox, "question",
                        lambda *a, **k: asked.append(1) or QMessageBox.StandardButton.Yes)
    button = _by_icon(window)["treemap"]
    button.trigger()
    pump(0.3)
    window.extension_host.set_enabled(EXTENSIONS["treemap"], False)
    button.trigger()
    pump(0.3)
    assert len(asked) == 2
    assert window.extension_host.docks(EXTENSIONS["treemap"])[0].isVisible()


def test_edge_no_shortcut_is_bound_twice(window) -> None:
    from PyQt6.QtGui import QAction

    owners: dict[str, set[int]] = {}
    for action in window.findChildren(QAction):
        for seq in action.shortcuts():
            if seq.toString():
                owners.setdefault(seq.toString(), set()).add(id(action))
    assert {k: len(v) for k, v in owners.items() if len(v) > 1} == {}


def test_happy_e2e_the_console_button_opens_the_scripting_engine(window) -> None:
    """Scripts (saved scripts and their editor) had a button; the Python
    console - the scripting engine with the axross.* API - had none."""
    by_icon = _by_icon(window)
    assert "console" in by_icon["console"].toolTip().lower()
    assert "editor" in by_icon["scripts"].toolTip().lower()
    window._console_dock.hide()
    pump()
    by_icon["console"].trigger()
    pump()
    assert window._console_dock.isVisible()
    assert by_icon["console"].isChecked()
    by_icon["console"].trigger()
    pump()
    assert not window._console_dock.isVisible()


def test_edge_the_console_icon_differs_from_the_terminal_icon() -> None:
    # Terminal (a shell) and console (Python) sit side by side.
    assert IP.ICONS["console"] != IP.ICONS["terminal"]
    assert IP._ICON_COLORS["console"] != IP._ICON_COLORS.get("terminal")
