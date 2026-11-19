"""Splitting a pane never makes the window larger than it is.

Found in review (round 2 of the 2026-11 reviews, UI shell; repro at
1024x600: Ctrl+Shift+H three times, or Ctrl+Shift+V twice): a split went
on when the pane had no room for two panes at their smallest, and the
splitter's minimum widened the window past the screen - 1098 wide with
the fourth pane side by side, 653 high with the third one above the
other. Now the split is refused with a word in the status bar.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _pump(seconds: float = 0.25) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture
def win(tmp_path):
    from ui import main_window as MW

    home = tmp_path / "home"
    home.mkdir()
    with mock.patch("pathlib.Path.home", return_value=home), \
            mock.patch.object(MW.MainWindow, "_SESSION_FILE", tmp_path / "s.json"), \
            mock.patch.object(MW.MainWindow, "_RECENTS_FILE", tmp_path / "r.json"):
        window = MW.MainWindow()
    window._reconnect_timer.stop()
    window._quit_with_transfers = True
    window.resize(1024, 600)
    window.show()
    _pump()
    yield window
    window._agent_dock.shutdown()
    window.close()
    window.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def test_happy_one_split_each_way_still_fits(win):
    win._split_pane(Qt.Orientation.Horizontal)
    _pump()
    assert len(win._panes) == 2
    assert (win.width(), win.height()) == (1024, 600)


@pytest.mark.parametrize("orientation", [Qt.Orientation.Horizontal, Qt.Orientation.Vertical])
def test_sad_splitting_on_and_on_keeps_the_window_size(win, orientation):
    for _ in range(6):
        win._split_pane(orientation)
        _pump(0.15)
    assert (win.width(), win.height()) == (1024, 600)
    assert win.minimumSizeHint().width() <= 1024 and win.minimumSizeHint().height() <= 600
    assert 2 <= len(win._panes) < 7
    assert "No room to split" in win.statusBar().currentMessage()


def test_edge_a_refused_split_leaves_the_panes_and_the_focus(win):
    for _ in range(6):
        win._split_pane(Qt.Orientation.Vertical)
        _pump(0.15)
    panes = list(win._panes)
    active = win._active_pane
    win._split_pane(Qt.Orientation.Vertical)
    _pump(0.15)
    assert win._panes == panes and win._active_pane is active


def test_sad_dropping_a_pane_where_there_is_no_room_is_refused(win):
    win._split_pane(Qt.Orientation.Horizontal)
    _pump()
    left, right = win._panes[0], win._panes[1]
    win._active_pane = left
    win._split_pane(Qt.Orientation.Vertical)
    _pump()
    top = left
    assert len(win._panes) == 3 and top.height() < 2 * top.minimumSizeHint().height() + 10
    win._on_pane_drop(str(id(right)), top, "top")
    _pump()
    assert (win.width(), win.height()) == (1024, 600)
    assert right.isVisible()
    assert "No room to split" in win.statusBar().currentMessage()
