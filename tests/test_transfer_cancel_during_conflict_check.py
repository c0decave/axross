"""Cancel All also stops a copy or move whose destination check is running.

Measured before: F5 / F6 / a drop first list the destination on a worker
thread (the conflict check, MainWindow._request_transfer) and queue the
jobs when it is done. Cancel All in the transfer dock only reached jobs
the manager knew, so pressing it while a slow destination was still
being checked did nothing: the check finished and the transfer ran - a
cancelled move still moved the files. (The same gap as the background
walk, one step earlier.)

Now the manager counts Cancel All presses (``cancel_epoch``); a check
that started before the last one queues nothing.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


class _GatedDest(LocalFS):
    """A destination whose listings wait for *gate* (a slow share)."""

    def __init__(self) -> None:
        self.gate = threading.Event()
        self.listings = 0

    def list_dir(self, path):
        self.listings += 1
        self.gate.wait(10)
        return super().list_dir(path)


@pytest.fixture
def win(tmp_path, monkeypatch):
    from ui.main_window import MainWindow

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    window = MainWindow()
    window._reconnect_timer.stop()
    yield window
    window.close()
    window.deleteLater()


def _pump(cond, timeout: float = 10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    APP.processEvents()
    return cond()


def _two_panes(win, src: Path, dst: Path, dest_backend):
    left = win._active_pane
    left.navigate(str(src))
    win._split_pane(Qt.Orientation.Horizontal)
    right = win._active_pane
    right.navigate(str(dst))
    right._backend = dest_backend  # the slow share, from here on
    win._set_active_pane(left)
    win._set_target_pane(right)
    return left, right


def test_happy_cancel_all_in_the_dock_stops_a_move_still_being_checked(win, tmp_path):
    from PyQt6.QtTest import QTest

    src, dst = tmp_path / "src", tmp_path / "dst"
    src.mkdir()
    dst.mkdir()
    (src / "a.txt").write_text("a")
    dest = _GatedDest()
    left, right = _two_panes(win, src, dst, dest)
    win._request_transfer(left, right, [str(src / "a.txt")], move=True)
    assert _pump(lambda: dest.listings > 0)
    QTest.mouseClick(win._transfer_dock._btn_cancel, Qt.MouseButton.LeftButton)
    dest.gate.set()
    assert _pump(lambda: not win._conflict_checks)
    _pump(lambda: False, timeout=0.5)  # a queued job would run now
    assert win._transfer_manager.all_jobs() == []
    assert (src / "a.txt").read_text() == "a"
    assert not (dst / "a.txt").exists()


def test_edge_a_check_started_after_cancel_all_runs_normally(win, tmp_path):
    src, dst = tmp_path / "src", tmp_path / "dst"
    src.mkdir()
    dst.mkdir()
    (src / "a.txt").write_text("a")
    dest = _GatedDest()
    dest.gate.set()
    left, right = _two_panes(win, src, dst, dest)
    win._transfer_manager.cancel_all()  # nothing in flight
    win._request_transfer(left, right, [str(src / "a.txt")])
    assert _pump(lambda: (dst / "a.txt").exists())
    assert (dst / "a.txt").read_text() == "a"


def test_sad_cancel_epoch_counts_every_cancel_all(win):
    manager = win._transfer_manager
    before = manager.cancel_epoch
    manager.cancel_all()
    manager.cancel_all()
    assert manager.cancel_epoch == before + 2
