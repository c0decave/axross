"""Round 3 (low from round 2): ElidedLabel's size hint was the width of
its whole text - a 5000-character status (a long name quoted in it) asked
for some 35 000 px, and the pane footer's row, the pane and a window
sized from its hint (adjustSize, a detached pane) with it. The hint is
capped now; the label still cuts with "…" and its whole text is the
tooltip, and ``needed_width`` still tells the full width."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QHBoxLayout, QWidget  # noqa: E402

from ui.elided_label import MAX_HINT_CHARS, ElidedLabel  # noqa: E402

APP = QApplication.instance() or QApplication([])


def test_sad_a_huge_status_does_not_ask_for_a_huge_width():
    label = ElidedLabel()
    label.setText("x" * 5000)
    cap = label.fontMetrics().averageCharWidth() * (MAX_HINT_CHARS + 2) + 40
    assert label.sizeHint().width() <= cap
    assert label.needed_width() > 10_000          # the real width is still known
    holder = QWidget()
    row = QHBoxLayout(holder)
    row.addWidget(label)
    holder.adjustSize()
    assert holder.width() <= cap + 40
    assert label.is_elided()
    assert label.toolTip() == "x" * 5000
    holder.deleteLater()


def test_happy_a_short_status_asks_for_its_own_width():
    label = ElidedLabel("12 items, 3 selected")
    assert label.sizeHint().width() == label.needed_width()
    label.deleteLater()
