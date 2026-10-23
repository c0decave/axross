"""Equalize Pane Sizes makes every pane of the layout equal.

Reported: neither Ctrl+Shift+E nor the Equalize button evened out the
panes any more, and no test had caught it. Reproduced with the built-in
actions alone: Split
Horizontal twice gives root[inner[A, C], B] - _split_pane nests a splitter
of the same orientation - with A=324, C=324, B=651. Equalize acted only on
the active pane's own splitter (inner), which was already even: nothing
changed, by button and by key alike. Now the whole tree of the active
pane's layout is evened out, each child weighted by the panes it holds
along that axis.
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

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QSplitter  # noqa: E402

APP = QApplication.instance() or QApplication([])
H, V = Qt.Orientation.Horizontal, Qt.Orientation.Vertical


def pump(seconds: float = 0.1) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture
def window(tmp_path):
    from ui.main_window import MainWindow

    win = MainWindow()
    win._reconnect_timer.stop()
    win.resize(1500, 900)
    win.show()
    win._active_pane.navigate(str(tmp_path))
    pump()
    yield win
    win.close()
    win.deleteLater()
    pump()


def _widths(win) -> list[int]:
    return sorted(p.width() for p in win._panes if p.isVisible())


def _skew(win) -> None:
    """Make every splitter of the layout uneven."""
    root = win._active_pane.parent()
    while isinstance(root.parent(), QSplitter):
        root = root.parent()
    for sp in [root, *root.findChildren(QSplitter)]:
        if sp.count() > 1:
            sp.setSizes([900] + [100] * (sp.count() - 1))
    pump()


def _even(values: list[int], tolerance: int = 6) -> bool:
    return max(values) - min(values) <= tolerance


def test_happy_three_panes_from_two_splits_become_equal(window) -> None:
    window._split_pane(H)
    window._split_pane(H)
    pump()
    _skew(window)
    assert not _even(_widths(window))
    window._equalize_action.trigger()
    pump()
    assert len(_widths(window)) == 3
    assert _even(_widths(window)), _widths(window)


def test_happy_the_key_does_the_same(window) -> None:
    window._split_pane(H)
    window._split_pane(H)
    pump()
    _skew(window)
    window.activateWindow()
    window._active_pane.setFocus()
    QTest.keyClick(window, Qt.Key.Key_E,
                   Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier)
    pump()
    assert _even(_widths(window)), _widths(window)


def test_happy_a_mixed_layout_is_even_along_each_axis(window) -> None:
    # Split Horizontal, then Split Vertical on the active pane: (A / C) | B.
    # The pair takes as much width as B, and A and C share the height.
    window._split_pane(H)
    window._split_pane(V)
    pump()
    _skew(window)
    window._equalize_action.trigger()
    pump()
    visible = [p for p in window._panes if p.isVisible()]
    stacked = [p for p in visible if p.parent().orientation() == V]
    (alone,) = [p for p in visible if p.parent().orientation() == H]
    assert len(stacked) == 2
    assert abs(alone.width() - stacked[0].width()) <= 8, (alone.width(), stacked[0].width())
    assert abs(stacked[0].height() - stacked[1].height()) <= 8


def test_sad_no_active_pane_and_a_single_pane_change_nothing(window) -> None:
    window._equalize_action.trigger()  # one pane: nothing to even out
    pump()
    window._active_pane = None
    window._equalize_action.trigger()  # must not raise
    pump()


def test_edge_a_terminal_pane_counts_as_a_pane(window) -> None:
    window._split_pane(H)
    pump()
    window._open_shell_pane()
    pump(0.5)
    _skew(window)
    window._equalize_action.trigger()
    pump()
    from ui.terminal_pane import TerminalPaneWidget

    terms = [t for t in window.findChildren(TerminalPaneWidget) if t.isVisible()]
    panes = [p for p in window._panes if p.isVisible()]
    sizes = [w.width() if w.parent().orientation() == H else w.height() for w in terms]
    assert terms and panes
    assert all(s > 150 for s in sizes), sizes


def test_edge_the_toolbar_button_is_the_same_action(window) -> None:
    from PyQt6.QtWidgets import QToolBar

    bar = next(tb for tb in window.findChildren(QToolBar) if tb.windowTitle() == "Main")
    assert window._equalize_action in bar.actions()
