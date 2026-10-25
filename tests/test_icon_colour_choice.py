"""Edit > Settings > Appearance > Icon colours: the icons' own colours in
every theme, the theme's choice, or one colour of the user's.

Requested: coloured icons in the themes that draw every icon in one colour
(Hacker green, Amber orange), and configurable. "Theme default" keeps what
the themes did; "Own colours in every theme" gives each icon its colour in
Hacker and Amber too; "One colour" draws every icon in a chosen colour.
Monochrome icons stay their own switch and win over the choice.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtGui import QColor  # noqa: E402

from tests.settings_testkit import app, isolate  # noqa: E402
from ui import icon_provider, themes  # noqa: E402
from ui import window_prefs as WP  # noqa: E402

APP = app()
AGENT = icon_provider._ICON_COLORS["agent"]


@pytest.fixture
def stores(tmp_path, monkeypatch):
    s = isolate(tmp_path, monkeypatch)
    yield s
    s.close_windows()
    s.restore()


def _session(stores) -> dict:
    if not stores.session.exists():
        return {}
    return json.loads(stores.session.read_text()).get("window", {})


def _write_session(stores, **window) -> None:
    stores.session.parent.mkdir(parents=True, exist_ok=True)
    stores.session.write_text(json.dumps({"window": window}))


# -- the stored value ------------------------------------------------------------------


def test_happy_the_choice_is_read_from_the_session():
    prefs = WP.parse({WP.ICON_COLOURS_KEY: "coloured"})
    assert prefs.icon_colours == "coloured" and prefs.icon_colour is None
    prefs = WP.parse({WP.ICON_COLOURS_KEY: "one", WP.ICON_COLOUR_KEY: "#FF00AA"})
    assert prefs.icon_colours == "one" and prefs.icon_colour == "#ff00aa"


@pytest.mark.parametrize("window", [
    {WP.ICON_COLOURS_KEY: "rainbow"},
    {WP.ICON_COLOURS_KEY: 3},
    {WP.ICON_COLOURS_KEY: "one"},  # one colour, but none stored
    {WP.ICON_COLOURS_KEY: "one", WP.ICON_COLOUR_KEY: "red"},
    {WP.ICON_COLOURS_KEY: "one", WP.ICON_COLOUR_KEY: ["#ff0000"]},
])
def test_sad_a_broken_choice_reads_as_the_theme_default(window):
    prefs = WP.parse(window)
    assert prefs.icon_colours == "theme"


def test_edge_an_old_session_without_the_key_keeps_the_theme_default():
    prefs = WP.parse({WP.MONOCHROME_KEY: True})
    assert prefs.icon_colours == "theme" and prefs.monochrome_icons is True
    assert WP.WindowPrefs().icon_colours == "theme"


# -- the window ------------------------------------------------------------------------


def test_happy_own_colours_in_the_hacker_theme(stores):
    win = stores.make_window()
    win.set_theme("hacker", store=False)
    assert icon_provider.stroke_colour("agent") == themes.icon_tint_for("hacker")
    win.set_icon_colours("coloured")
    assert icon_provider.get_tint() is None
    assert icon_provider.stroke_colour("agent") == AGENT
    assert _session(stores)[WP.ICON_COLOURS_KEY] == "coloured"
    # a theme switch keeps the choice
    win.set_theme("amber", store=False)
    assert icon_provider.stroke_colour("agent") == AGENT


def test_happy_one_colour_in_every_theme(stores):
    win = stores.make_window()
    win.set_icon_colours("one", "#3366FF")
    for theme in ("classic", "hacker", "light"):
        win.set_theme(theme, store=False)
        assert icon_provider.stroke_colour("agent") == "#3366ff", theme
    stored = _session(stores)
    assert stored[WP.ICON_COLOURS_KEY] == "one" and stored[WP.ICON_COLOUR_KEY] == "#3366ff"


def test_sad_one_colour_without_a_valid_colour_is_refused(stores):
    win = stores.make_window()
    win.set_theme("hacker", store=False)
    with pytest.raises(ValueError):
        win.set_icon_colours("one", "not-a-colour")
    with pytest.raises(ValueError):
        win.set_icon_colours("sparkly")
    assert icon_provider.stroke_colour("agent") == themes.icon_tint_for("hacker")
    assert WP.ICON_COLOURS_KEY not in _session(stores)


def test_edge_monochrome_wins_over_the_choice(stores):
    win = stores.make_window()
    win.set_theme("classic", store=False)
    win.set_icon_colours("one", "#ff0000")
    win.set_monochrome_icons(True, store=False)
    text = APP.palette().color(APP.palette().ColorRole.WindowText).name()
    assert icon_provider.stroke_colour("agent") == text
    win.set_monochrome_icons(False, store=False)
    assert icon_provider.stroke_colour("agent") == "#ff0000"


def test_edge_the_theme_default_is_what_the_themes_did(stores):
    win = stores.make_window()
    win.set_icon_colours("coloured")
    win.set_icon_colours("theme")
    win.set_theme("amber", store=False)
    assert icon_provider.stroke_colour("agent") == themes.icon_tint_for("amber")
    win.set_theme("classic", store=False)
    assert icon_provider.stroke_colour("agent") == AGENT


def test_happy_e2e_the_next_start_keeps_the_choice(stores):
    _write_session(stores, **{WP.THEME_KEY: "hacker", WP.ICON_COLOURS_KEY: "coloured"})
    win = stores.make_window()
    assert win.current_window_prefs().icon_colours == "coloured"
    assert icon_provider.stroke_colour("agent") == AGENT
    # the toolbar's category tint is computed from the icons as drawn now
    toolbar_icons = win.toolbar_button_colours()
    assert toolbar_icons


# -- Settings > Appearance -------------------------------------------------------------


def test_happy_e2e_settings_switch_the_icon_colours_live(stores):
    win = stores.make_window()
    win.set_theme("hacker", store=False)
    dialog = stores.settings_dialog(win, "appearance")
    page = dialog.page("appearance")
    combo = page.icon_colours_combo
    assert combo.currentData() == "theme"
    combo.setCurrentIndex(combo.findData("coloured"))
    assert dialog.apply()
    assert icon_provider.stroke_colour("agent") == AGENT
    assert _session(stores)[WP.ICON_COLOURS_KEY] == "coloured"


def test_happy_e2e_settings_one_colour_takes_the_chosen_colour(stores):
    win = stores.make_window()
    dialog = stores.settings_dialog(win, "appearance")
    page = dialog.page("appearance")
    assert not page.icon_colour_button.isEnabled()
    page.icon_colours_combo.setCurrentIndex(page.icon_colours_combo.findData("one"))
    assert page.icon_colour_button.isEnabled()
    with mock.patch("ui.settings_dialog.QColorDialog.getColor", return_value=QColor("#aa5500")):
        page.icon_colour_button.click()
    assert dialog.apply()
    assert icon_provider.stroke_colour("agent") == "#aa5500"
    stored = _session(stores)
    assert stored[WP.ICON_COLOURS_KEY] == "one" and stored[WP.ICON_COLOUR_KEY] == "#aa5500"


def test_sad_settings_one_colour_cancelled_keeps_the_previous_choice(stores):
    win = stores.make_window()
    win.set_theme("hacker", store=False)
    dialog = stores.settings_dialog(win, "appearance")
    page = dialog.page("appearance")
    page.icon_colours_combo.setCurrentIndex(page.icon_colours_combo.findData("one"))
    with mock.patch("ui.settings_dialog.QColorDialog.getColor", return_value=QColor()):
        page.icon_colour_button.click()
    # "One colour" with no colour chosen yet cannot be applied as such
    assert page.icon_colours_combo.currentData() == "theme"
    assert dialog.apply()
    assert icon_provider.stroke_colour("agent") == themes.icon_tint_for("hacker")


def test_edge_settings_monochrome_locks_the_icon_colours(stores):
    win = stores.make_window()
    dialog = stores.settings_dialog(win, "appearance")
    page = dialog.page("appearance")
    page.monochrome_check.setChecked(True)
    assert not page.icon_colours_combo.isEnabled()
    assert "Monochrome" in page.icon_colours_combo.toolTip()
    page.monochrome_check.setChecked(False)
    assert page.icon_colours_combo.isEnabled()
