"""Every toolbar icon reads on its button in every theme (3:1, WCAG 1.4.11).

Review round 3 (UX) sampled the toolbar of Modern Light: 9 of 13 icons
stayed below 3:1 against their button, the yellow pie of Disk Usage at
1.5:1. The icon palette (ui.icon_provider._ICON_COLORS) was picked for a
dark bar; on a light one the medium colours are pastel, and the category
tint behind them (ui.toolbar_categories) only kept 90 % of what little
contrast they had. Measured on the rendered window: 20 of 36 icons below
3:1 in Modern Light, 24 in Light Mode, one (the purple puzzle) in Classic.

Now the window tells the icon provider the bar's colour (set_backdrop), and
an icon's own colour that does not reach ICON_CONTRAST on it is drawn
darker on a light bar and lighter on a dark one, same hue.

The measurement is made on pixels: the icon's stroke colour from its
rendered pixmap, the button's background from a grab of the button.
"""

from __future__ import annotations

import os
import sys
import time
from collections import Counter
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QToolBar, QToolButton  # noqa: E402

from tests.settings_testkit import app, isolate  # noqa: E402
from ui import icon_provider as IP  # noqa: E402
from ui import themes  # noqa: E402

APP = app()

#: Every theme a user can pick ("modern" resolves to one of its variants).
THEMES = [theme for theme, _label in themes.THEME_CHOICES if theme != "modern"]


def pump(seconds: float = 0.1) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.005)


@pytest.fixture(scope="module")
def window(tmp_path_factory):
    from _pytest.monkeypatch import MonkeyPatch

    patch = MonkeyPatch()
    stores = isolate(tmp_path_factory.mktemp("icon-contrast"), patch)
    win = stores.make_window()
    win.resize(1600, 800)
    win.show()
    pump(0.3)
    try:
        yield win
    finally:
        win._apply_theme(themes.DEFAULT_THEME)
        stores.close_windows()
        stores.restore()
        patch.undo()


def _name(rgb) -> str:
    return "#%02x%02x%02x" % rgb


def _icon_contrasts(win) -> list[tuple[str, str, str, float]]:
    """(icon, stroke colour, button background, contrast) of each visible
    toolbar button."""
    out = []
    for bar in win.findChildren(QToolBar):
        if not bar.isVisible():
            continue
        for button in bar.findChildren(QToolButton):
            action = button.defaultAction()
            if action is None or not button.isVisible() or action.icon().isNull():
                continue
            shot = button.grab().toImage()
            back = shot.pixelColor(3, shot.height() // 2)
            pixmap = action.icon().pixmap(32, 32).toImage()
            opaque = Counter()
            for x in range(pixmap.width()):
                for y in range(pixmap.height()):
                    pixel = pixmap.pixelColor(x, y)
                    if pixel.alpha() >= 250:
                        opaque[(pixel.red(), pixel.green(), pixel.blue())] += 1
            if not opaque:
                continue
            stroke = _name(opaque.most_common(1)[0][0])
            background = _name((back.red(), back.green(), back.blue()))
            out.append((str(action.property("axIcon")), stroke, background,
                        themes.contrast_ratio(stroke, background)))
    return out


@pytest.mark.parametrize("theme", THEMES)
def test_happy_every_toolbar_icon_reads_on_its_button(window, theme):
    window._apply_theme(theme)
    pump(0.2)
    measured = _icon_contrasts(window)
    assert len(measured) >= 20, measured  # the bars were there to measure
    weak = [(name, stroke, back, round(ratio, 2))
            for name, stroke, back, ratio in measured if ratio < 3.0]
    assert weak == [], f"{theme}: {len(weak)} of {len(measured)} icons below 3:1: {weak}"


def test_happy_a_light_theme_darkens_and_a_dark_one_keeps_the_colours(window):
    """The yellow pie: dark gold on a light bar, the palette's yellow on a
    dark one (where it read already)."""
    window._apply_theme("modern-light")
    pump()
    light = IP.stroke_colour("disk-usage")
    assert themes.contrast_ratio(light, window.toolbar_background()) >= IP.ICON_CONTRAST
    window._apply_theme("modern-dark")
    pump()
    assert IP.stroke_colour("disk-usage") == "#f1c40f"


def test_sad_without_a_backdrop_the_colours_stay_as_they_are():
    before = IP.get_backdrop()
    IP.set_backdrop(None)
    try:
        assert IP.readable_colour("#f1c40f") == "#f1c40f"
        assert IP.stroke_colour("disk-usage") == "#f1c40f"
    finally:
        IP.set_backdrop(before)


def test_sad_a_backdrop_that_is_no_colour_is_ignored():
    before = IP.get_backdrop()
    try:
        IP.set_backdrop(None)
        IP.set_backdrop("white; } svg { fill: red")  # spliced into nothing
        assert IP.get_backdrop() is None
    finally:
        IP.set_backdrop(before)


def test_edge_readable_colour_moves_only_as_far_as_needed():
    # already readable: unchanged
    assert IP.readable_colour("#1e8449", "#ffffff") == "#1e8449"
    # light backdrop: darker, same direction for every channel
    dark = IP.readable_colour("#f1c40f", "#ffffff")
    assert themes.contrast_ratio(dark, "#ffffff") >= IP.ICON_CONTRAST
    assert all(int(dark[i:i + 2], 16) <= int("f1c40f"[i - 1:i + 1], 16) for i in (1, 3, 5))
    # dark backdrop: lighter
    light = IP.readable_colour("#8e44ad", "#1e1e2e")
    assert themes.contrast_ratio(light, "#1e1e2e") >= IP.ICON_CONTRAST
    assert themes._relative_luminance(light) > themes._relative_luminance("#8e44ad")
    # a tint and a chosen colour are the user's: not changed
    before = IP.get_backdrop()
    try:
        IP.set_backdrop("#ffffff")
        IP.set_tint("#ffd700")
        assert IP.stroke_colour("disk-usage") == "#ffd700"
    finally:
        IP.set_tint(None)
        IP.set_backdrop(before)
