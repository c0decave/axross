"""A 1024x600 window gives the file list the room.

UX review round 5 (major): on a 1024x600 screen the two toolbar rows, the
empty Transfers dock with its idle "0%" bar and the table header left the
file list four rows. Now a window under 700 px keeps the toolbars in one
row (the rest behind the overflow button), and an empty Transfers dock is one
short line - no table, no "0%" - whose area grows back when a transfer runs.
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

from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.3) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture
def make(tmp_path):
    made = []

    def build(width: int, height: int):
        from ui.main_window import MainWindow

        home = tmp_path / f"home{len(made)}"
        home.mkdir()
        with mock.patch("pathlib.Path.home", return_value=home):
            win = MainWindow()
        win._reconnect_timer.stop()
        win._quit_with_transfers = True
        win.resize(width, height)
        # As a first start lays the window out (the bottom area at its
        # default height; one the user made taller is left alone).
        if not win.apply_first_start_layout():
            win.apply_layout_preset(win.FIRST_START_PRESET)
        win.show()
        pump(0.6)
        made.append(win)
        return win

    yield build
    for win in made:
        win.close()
        win.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def test_happy_a_short_window_keeps_one_toolbar_row(make):
    win = make(1024, 600)
    assert not win.toolBarBreak(win._tools_toolbar)
    assert win._main_toolbar.y() == win._tools_toolbar.y()


def test_happy_the_idle_transfers_dock_is_one_line_without_0_percent(make):
    win = make(1024, 600)
    dock = win._transfer_dock
    assert dock.idle
    assert not dock._table.isVisibleTo(dock)
    assert not dock._overall_progress.isVisibleTo(dock)
    assert dock._idle_label.isVisibleTo(dock)
    assert dock._btn_retry.isVisibleTo(dock)  # the tours point at it
    assert dock.height() <= dock.minimumSizeHint().height() + 4


def test_sad_a_transfer_brings_the_table_and_the_height_back(make, tmp_path):
    from core.local_fs import LocalFS

    win = make(1024, 600)
    dock = win._transfer_dock
    idle_height = dock.height()
    (tmp_path / "f.txt").write_text("x")
    (tmp_path / "dst").mkdir()
    win._transfer_manager.transfer_files(LocalFS(), LocalFS(), [str(tmp_path / "f.txt")],
                                         str(tmp_path / "dst"))
    pump(0.6)
    assert not dock.idle
    assert dock._table.isVisibleTo(dock) and dock._overall_progress.isVisibleTo(dock)
    assert dock.height() > idle_height + 40


def test_edge_a_tall_window_may_still_wrap_the_toolbars(make):
    win = make(900, 900)
    main, tools = win._main_toolbar, win._tools_toolbar
    needs_two = main.sizeHint().width() + tools.sizeHint().width() > win.width()
    assert win.toolBarBreak(tools) == needs_two
