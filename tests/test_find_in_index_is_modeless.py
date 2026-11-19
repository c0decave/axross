"""Find in Index does not block the window behind it.

Found in review (round 1 of the 2026-11 reviews, UI shell; repro:
Ctrl+Shift+F, then a key in the file list): the window was opened with
``QDialog.open()`` - window-modal - so while it was open the panes, menus
and shortcuts of the main window took no input. Opening a hit showed the
file selected in a pane the user could not reach, and *Edit → Index
Active Folder…* (minutes on a large tree) held the whole window for as
long as the indexing ran. Find Files was always modeless; Find in Index
is too now, and Ctrl+Shift+F raises the one that is open.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import bookmarks as BM  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _pump(seconds: float = 0.1) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture
def window(tmp_path, monkeypatch):
    monkeypatch.setattr(BM, "BOOKMARKS_FILE", tmp_path / "bookmarks.json")
    with mock.patch("pathlib.Path.home", return_value=tmp_path):
        from ui.main_window import MainWindow

        win = MainWindow()
    win._reconnect_timer.stop()
    win.show()
    _pump(0.2)
    yield win
    if win._index_dialog is not None:
        win._index_dialog.close()
    win._agent_dock.shutdown()
    win.close()
    win.deleteLater()
    _pump()


def test_happy_ctrl_shift_f_opens_a_modeless_window(window):
    window._find_index_action.trigger()
    _pump()
    dlg = window._index_dialog
    assert dlg is not None and dlg.isVisible()
    assert dlg.windowModality() == Qt.WindowModality.NonModal
    assert QApplication.activeModalWidget() is None
    # The window behind still takes its keys.
    window._split_pane(Qt.Orientation.Horizontal)
    assert len(window._panes) == 2


def test_sad_a_second_ctrl_shift_f_raises_the_open_window(window):
    window._find_index_action.trigger()
    _pump()
    first = window._index_dialog
    window._find_index_action.trigger()
    _pump()
    assert window._index_dialog is first
    visible = [w for w in APP.topLevelWidgets()
               if type(w).__name__ == "MetadataSearchDialog" and w.isVisible()]
    assert visible == [first]


def test_sad_it_indexes_the_pane_active_now_not_a_closed_one(window, tmp_path):
    window._find_index_action.trigger()
    _pump()
    dlg = window._index_dialog
    first = window._active_pane
    window._split_pane(Qt.Orientation.Horizontal)
    second = next(p for p in window._panes if p is not first)
    window._set_active_pane(second)
    window._close_pane(first)
    _pump()
    assert dlg._active_pane is second
    window._set_active_pane(second)
    assert dlg._active_pane is window._active_pane


def test_edge_closing_it_forgets_it_and_the_next_one_is_new(window):
    window._find_index_action.trigger()
    _pump()
    first = window._index_dialog
    first.close()
    _pump()
    assert window._index_dialog is None
    window._find_index_action.trigger()
    _pump()
    assert window._index_dialog is not None and window._index_dialog is not first
