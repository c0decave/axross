"""axross-markdown 0.17.2: the page's font is its text font whatever fonts are installed.

0.17.1's CI (an ubuntu-24.04 runner with Noto Color Emoji): the page's emoji family was put after the
default font's family - "Sans Serif", a fontconfig alias Qt finds no family of that name for in a list of
families - so Qt took the next, the emoji font, for all of the page: letters of 2,550 pixels on average to
its metrics, no margins (text_width 204,000), 120 characters a line, tables wider than the view, every
golden picture different. Any family put after the alias does it - these tests take one this machine has.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")

from PyQt6.QtGui import QFont, QFontDatabase, QFontInfo, QFontMetrics  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _pump(seconds: float) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.005)


def _other_family() -> str:
    """An installed family the default font is not set in (one whose letters are of another width)."""
    real = QFontInfo(QFont()).family()
    others = [family for family in QFontDatabase.families() if family != real and not family.startswith(".")]
    preferred = [family for family in others if "mono" in family.lower() or "serif" in family.lower()]
    if not (preferred or others):
        pytest.skip("one font family installed: nothing to put after it")
    return (preferred or others)[0]


def test_sad_the_emoji_family_never_takes_the_place_of_the_text_font(monkeypatch):
    from ui import markdown_view as MV

    other = _other_family()
    monkeypatch.setattr(MV, "_EMOJI_FAMILY", [other])
    plain = QFont()
    font = MV.with_emoji_family(plain)
    assert font.families()[0] == QFontInfo(plain).family()  # (the family it is really set in, not an alias)
    assert font.families()[-1] == other and len(font.families()) == len(set(font.families()))
    assert QFontInfo(font).family() == QFontInfo(plain).family()
    assert QFontMetrics(font).averageCharWidth() == QFontMetrics(plain).averageCharWidth()
    assert MV.text_font(font).families() == font.families()[:1]


@pytest.mark.parametrize("full", [True, False], ids=["markdown-it", "md4c"])
def test_sad_the_page_s_width_and_margins_are_the_same_with_any_emoji_family(monkeypatch, full):
    """The view's measure of a line (80 letters of its text font) and the margins around it, as with no
    emoji family at all - the CI's 16-pixel margins and 120 letters a line came from the emoji font's."""
    pytest.importorskip("markdown_it")
    from ui import markdown_view as MV

    def measured(families: list[str]) -> tuple:
        monkeypatch.setattr(MV, "_EMOJI_FAMILY", families)
        view = MV.MarkdownView(None)
        view.full = view.full and full
        view.resize(1400, 700)
        view.show()
        view.render("Plain words of a paragraph, " * 40 + "\n")
        end = time.monotonic() + 60
        while time.monotonic() < end and not view._readable:
            _pump(0.02)
        _pump(0.3)
        result = (view.text_width(), view.browser.margins()[0], QFontInfo(view.browser.font()).family())
        view.close()
        view.deleteLater()
        return result

    alone = measured([])
    with_other = measured([_other_family()])
    assert with_other == alone, (alone, with_other)
    assert alone[1] > 200  # (a wide view: the text in its middle)
