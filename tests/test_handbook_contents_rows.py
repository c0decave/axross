"""The handbook's contents: every row as tall as the first.

Measured before (UX review round 4, German handbook at 1060x700): from
about the twelfth entry on the rows of the contents were squeezed together
(text touching text) - the rows below the first screen were laid out
lazily, before the style's padding applied. The contents now have uniform
row heights.
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

from PyQt6.QtWidgets import QApplication, QTreeWidgetItemIterator  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _pump(seconds: float = 0.3) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.01)


def _rows(tree):
    it = QTreeWidgetItemIterator(tree)
    while it.value():
        yield it.value()
        it += 1


@pytest.fixture(params=["en", "de"])
def dialog(request):
    """The handbook under the window's style (its item padding), as Help >
    Handbook shows it: the squeeze needed the stylesheet."""
    from core import i18n
    from ui import themes
    from ui.handbook import HandbookDialog

    before = APP.styleSheet()
    APP.setStyleSheet(themes.stylesheet_for("modern", "dark"))
    i18n.install(request.param)
    dlg = HandbookDialog(language=request.param)
    dlg.resize(1060, 700)
    dlg.show()
    _pump()
    yield dlg
    dlg.close()
    dlg.deleteLater()
    i18n.install("en")
    APP.setStyleSheet(before)


def _heights(tree) -> list[int]:
    """The height of each row, scrolled into view one after the other."""
    out = []
    for item in _rows(tree):
        tree.scrollToItem(item)
        APP.processEvents()
        out.append(tree.visualItemRect(item).height())
    return out


def test_happy_every_row_is_as_tall_as_the_first(dialog):
    heights = _heights(dialog.contents)
    assert len(heights) > 20  # the whole contents, not a stub
    assert set(heights) == {heights[0]}, heights


def test_sad_rows_below_the_first_screen_are_not_squeezed(dialog):
    tree = dialog.contents
    items = list(_rows(tree))
    first = tree.visualItemRect(items[0]).height()
    tree.scrollToItem(items[-1])
    _pump(0.1)
    last = tree.visualItemRect(items[-1]).height()
    assert last == first > 0


def test_edge_uniform_rows_after_switching_the_language(dialog):
    from core import handbook as H

    dialog._show(H.load("en" if dialog.handbook.language != "en" else "de"))
    _pump(0.1)
    heights = _heights(dialog.contents)
    assert set(heights) == {heights[0]}
    assert dialog.contents.uniformRowHeights()
