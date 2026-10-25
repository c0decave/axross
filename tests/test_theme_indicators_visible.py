"""An unchecked check box or radio button can be seen in every theme.

Seen on the README screenshots of 2026-10-25: in Amber Mode the boxes of
"Compact mode" and "Monochrome icons" (Settings > Appearance) were not
there at all - the indicator was drawn dark on dark. Measured on the drawn
pixels: inside the indicator something must stand out from the background
by at least 3:1 (WCAG 2.1 SC 1.4.11, non-text contrast), checked and
unchecked, and checked must look different from unchecked.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import (  # noqa: E402
    QCheckBox,
    QRadioButton,
    QStyle,
    QStyleOptionButton,
    QVBoxLayout,
    QWidget,
)

from tests.settings_testkit import app, isolate  # noqa: E402
from ui import themes  # noqa: E402

APP = app()
THEMES = [theme for theme, _label in themes.THEME_CHOICES]
NON_TEXT_CONTRAST = 3.0


@pytest.fixture(scope="module")
def window(tmp_path_factory):
    mp = pytest.MonkeyPatch()
    s = isolate(tmp_path_factory.mktemp("ind"), mp)
    win = s.make_window()
    yield win
    s.close_windows()
    s.restore()
    mp.undo()


def _indicator_pixels(button) -> tuple[list[str], str]:
    """The colours drawn inside *button*'s indicator and its background."""
    option = QStyleOptionButton()
    button.initStyleOption(option)
    element = (QStyle.SubElement.SE_CheckBoxIndicator if isinstance(button, QCheckBox)
               else QStyle.SubElement.SE_RadioButtonIndicator)
    rect = button.style().subElementRect(element, option, button)
    image = button.grab().toImage()
    ratio = image.devicePixelRatio()
    colours = set()
    for x in range(rect.left(), rect.right() + 1):
        for y in range(rect.top(), rect.bottom() + 1):
            colours.add(image.pixelColor(round(x * ratio), round(y * ratio)).name())
    background = image.pixelColor(image.width() - 2, image.height() // 2).name()
    return sorted(colours), background


def _best_contrast(colours, background) -> float:
    return max(themes.contrast_ratio(c, background) for c in colours)


def _host(window, cls, checked):
    host = QWidget(window)
    host.setWindowFlags(host.windowFlags())
    layout = QVBoxLayout(host)
    button = cls("Compact mode " * 4)
    button.setChecked(checked)
    layout.addWidget(button)
    host.resize(400, 60)
    host.show()
    APP.processEvents()
    return host, button


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("cls", [QCheckBox, QRadioButton], ids=["checkbox", "radio"])
def test_happy_an_unchecked_indicator_stands_out(window, theme, cls):
    window.set_theme(theme, store=False)
    host, button = _host(window, cls, False)
    try:
        colours, background = _indicator_pixels(button)
        assert _best_contrast(colours, background) >= NON_TEXT_CONTRAST, (theme, colours, background)
    finally:
        host.deleteLater()


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("cls", [QCheckBox, QRadioButton], ids=["checkbox", "radio"])
def test_happy_checked_stands_out_and_differs_from_unchecked(window, theme, cls):
    window.set_theme(theme, store=False)
    host, off = _host(window, cls, False)
    host2, on = _host(window, cls, True)
    try:
        on_colours, background = _indicator_pixels(on)
        assert _best_contrast(on_colours, background) >= NON_TEXT_CONTRAST, (theme, on_colours)
        assert on_colours != _indicator_pixels(off)[0], theme
    finally:
        host.deleteLater()
        host2.deleteLater()


def test_sad_the_measure_catches_an_invisible_indicator():
    """Negative control: an indicator painted in the background colour fails."""
    colours, background = ["#0a0a0a", "#0b0b0b"], "#0a0a0a"
    assert _best_contrast(colours, background) < NON_TEXT_CONTRAST


def test_edge_a_disabled_box_is_not_held_to_it(window):
    """Disabled controls are exempt from SC 1.4.11; it only must not crash."""
    window.set_theme("amber", store=False)
    host, button = _host(window, QCheckBox, False)
    try:
        button.setEnabled(False)
        APP.processEvents()
        colours, _background = _indicator_pixels(button)
        assert colours
    finally:
        host.deleteLater()
