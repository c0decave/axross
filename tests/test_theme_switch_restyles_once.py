"""A theme switch restyles each widget about once, not once per widget
above it.

Measured on 2026-11-02 (feedback: optimise everything, measured): a theme
switch took 0.8 s on a quiet host with the main window's 580 widgets, and
4-10 s on a busy one - three tests that switch themes a few times ran past
pytest's 300 s limit in full parallel runs. Most of it was Qt replacing the
application style sheet: QStyleSheetStyle::repolish walks every widget and,
for each, its children again, so a widget n levels deep is repolished n
times - 4500 style, 9000 palette and up to 7000 font changes per switch.
Set as a first sheet (the old one cleared before), each widget is polished
once per pass: 1900, 2400 and 1300, about a third of the time. The style is
set only when it changes.

The tests count events, not time: a chain of nested widgets shows how the
count grows with the depth.
"""

from __future__ import annotations

import os
import sys
from collections import Counter
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, QObject  # noqa: E402
from PyQt6.QtWidgets import QVBoxLayout, QWidget  # noqa: E402

from tests.settings_testkit import app, isolate  # noqa: E402
from ui import themes  # noqa: E402

APP = app()
DEPTH = 40


class _Count(QObject):
    """StyleChange and PaletteChange events, per kind."""

    KINDS = (QEvent.Type.StyleChange, QEvent.Type.PaletteChange)

    def __init__(self) -> None:
        super().__init__()
        self.seen: Counter = Counter()

    def eventFilter(self, obj, event) -> bool:  # noqa: N802 - Qt override
        if event.type() in self.KINDS:
            self.seen[(obj, event.type())] += 1
        return False


@pytest.fixture(scope="module")
def window(tmp_path_factory):
    mp = pytest.MonkeyPatch()
    s = isolate(tmp_path_factory.mktemp("restyle"), mp)
    win = s.make_window()
    yield win
    s.close_windows()
    s.restore()
    mp.undo()


@pytest.fixture
def chain(window):
    """A top-level widget with a chain of DEPTH widgets nested in it; the
    innermost one is returned."""
    top = QWidget()
    parent = top
    for _ in range(DEPTH):
        child = QWidget(parent)
        QVBoxLayout(parent).addWidget(child)
        parent = child
    top.show()
    APP.processEvents()
    yield parent
    top.close()
    top.deleteLater()
    APP.processEvents()


def _switch(window, theme: str) -> _Count:
    count = _Count()
    APP.installEventFilter(count)
    try:
        window._apply_theme(theme)
        APP.processEvents()
    finally:
        APP.removeEventFilter(count)
    return count


def test_happy_the_innermost_widget_is_restyled_a_few_times_not_once_per_level(window, chain):
    _switch(window, "modern-dark")
    for theme in ("amber", "modern-light", "hacker"):
        count = _switch(window, theme)
        style = count.seen[(chain, QEvent.Type.StyleChange)]
        palette = count.seen[(chain, QEvent.Type.PaletteChange)]
        # Replacing the sheet sent the innermost of 40 levels 41 style
        # changes; a first sheet sends one per pass.
        assert style <= 4, (theme, style)
        assert palette <= 8, (theme, palette)


def test_happy_the_result_is_the_theme_asked_for(window):
    for theme in ("modern-dark", "classic", "amber", "modern-light"):
        window._apply_theme(theme)
        APP.processEvents()
        scheme = themes.system_scheme()
        assert APP.styleSheet() == themes.stylesheet_for(
            theme, scheme, compact=window._compact_mode)
        tokens = themes.palette_tokens_for(themes.resolve(theme, scheme))
        if tokens is not None:
            expected = themes.qpalette_for(tokens)
            for role in (expected.ColorRole.Window, expected.ColorRole.WindowText,
                         expected.ColorRole.Highlight):
                assert APP.palette().color(role) == expected.color(role), (theme, role)
        assert window._current_theme == theme


def test_edge_the_same_style_is_not_set_again(window, monkeypatch):
    """Setting the style is a pass over every widget of its own: a switch
    between two Fusion themes leaves the style as it is."""
    window._apply_theme("modern-dark")
    APP.processEvents()
    set_to: list = []
    original = type(APP).setStyle  # static in PyQt6
    monkeypatch.setattr(type(APP), "setStyle",
                        staticmethod(lambda style: (set_to.append(style), original(style))[1]))
    window._apply_theme("amber")
    window._apply_theme("modern-dark")
    assert set_to == []
