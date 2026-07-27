#!/usr/bin/env python3
"""A pane must not jump while it is being navigated.

``FilePaneWidget.navigate`` shows a 3-px indeterminate progress bar
before it starts loading (ui/file_pane.py) and hides it again in the
``finally`` block. The bar lives in the pane's ``QVBoxLayout``, and Qt's
default ``QSizePolicy`` has ``retainSizeWhenHidden == False`` — so
``hide()`` does not just blank the widget, it removes the layout cell
entirely and every widget below it (the file table, the status bar)
slides up by the bar's height plus the layout spacing.

Measured on the real geometry: 3 px height + 2 px spacing = a 5 px jump
DOWN when navigation starts and 5 px back UP when it ends. Every
directory change produced that twitch, which is what the pane felt like
in use.

The fix is to reserve the cell while hidden. These tests pin both the
policy and the behaviour it is there to produce, because the policy on
its own is easy to drop in a refactor without anything visibly breaking
in a headless test run.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from ui.file_pane import FilePaneWidget  # noqa: E402

# One QApplication for the module; reuse any pre-existing instance.
APP = QApplication.instance() or QApplication([])


@pytest.fixture()
def pane(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "a.txt").write_text("a")
    widget = FilePaneWidget(LocalFS())
    widget.resize(700, 500)
    widget.show()
    APP.processEvents()
    try:
        yield widget
    finally:
        widget.close()
        widget.deleteLater()
        APP.processEvents()


def _table_top(widget: FilePaneWidget) -> int:
    """Y coordinate of the file table inside the pane."""
    return widget._table.geometry().y()


# --------------------------------------------------------------------------
# Happy path — the layout holds still across a show/hide cycle
# --------------------------------------------------------------------------


def test_happy_table_does_not_move_when_progress_bar_toggles(pane):
    before = _table_top(pane)
    pane._progress_bar.show()
    APP.processEvents()
    during = _table_top(pane)
    pane._progress_bar.hide()
    APP.processEvents()
    after = _table_top(pane)

    assert during == before, (
        f"file table jumped {during - before}px when the progress bar appeared — "
        "the hidden bar is not reserving its layout cell"
    )
    assert after == before


def test_happy_status_row_does_not_move_either(pane):
    """The status line sits below the table, so it moves for the same
    reason and is the part the eye actually tracks."""
    before = pane._status.geometry().y()
    pane._progress_bar.show()
    APP.processEvents()
    during = pane._status.geometry().y()
    pane._progress_bar.hide()
    APP.processEvents()
    assert during == before
    assert pane._status.geometry().y() == before


# --------------------------------------------------------------------------
# The policy itself
# --------------------------------------------------------------------------


def test_progress_bar_retains_its_size_when_hidden(pane):
    assert pane._progress_bar.sizePolicy().retainSizeWhenHidden() is True


def test_progress_bar_starts_hidden(pane):
    """Reserving the space must not make the bar visible at rest — the
    pane should look idle, just without the twitch."""
    assert pane._progress_bar.isVisibleTo(pane) is False


# --------------------------------------------------------------------------
# Sad / edge — a real navigation, and a failing one
# --------------------------------------------------------------------------


def test_edge_navigation_into_and_out_of_a_directory_is_stable(tmp_path, pane):
    """The reported reproducer: step into a directory and back out."""
    (tmp_path / "sub" / "nested.txt").write_text("x")
    pane.navigate(str(tmp_path))
    APP.processEvents()
    baseline = _table_top(pane)

    for target in (tmp_path / "sub", tmp_path, tmp_path / "sub", tmp_path):
        pane.navigate(str(target))
        APP.processEvents()
        assert _table_top(pane) == baseline, f"table moved after navigating to {target}"


def test_sad_failed_navigation_still_leaves_the_layout_put(pane, tmp_path):
    """``navigate`` hides the bar in a ``finally``, so the error path
    toggles it too — it must not shift the layout either."""
    baseline = _table_top(pane)
    pane.navigate(str(tmp_path / "does-not-exist"))
    APP.processEvents()
    assert _table_top(pane) == baseline
