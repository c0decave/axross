"""A sync makes its folders off the GUI thread.

Audit (feedback: no blocked windows): Compare > Sync created every
missing folder with one mkdir() per folder on the GUI thread before it
queued the copies - a deep tree on a server froze the window for as many
round trips. The folders are made on a worker now ("Sync: creating
folders N of M…"); the copies are queued on the GUI thread once they
exist - and not at all when a compared pane was closed meanwhile.
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

from PyQt6.QtCore import QTimer  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from tests.test_compare_copy_keeps_relative_paths import (  # noqa: E402
    _drain_sync,
    _Pane,
    _sync_item,
    _Win,
)

APP = QApplication.instance() or QApplication([])

# TICKS_NOTE: a timer that ticked at all ran during the wait - a GUI thread
# held by the call gets none (the timer stops before the loop runs again).
# How often it ticked depends on the host's load, so only "at all" counts.


class SlowFolders:
    def __init__(self, inner) -> None:
        self._inner = inner
        self.made: list[tuple[str, str]] = []

    def mkdir(self, path):
        self.made.append((path, threading.current_thread().name))
        time.sleep(0.1)

    def __getattr__(self, name):
        return getattr(self._inner, name)


def _plan(n: int) -> list[dict]:
    items = [_sync_item(f"d{i}", "mkdir") for i in range(n)]
    return items + [_sync_item(f"d{i}/f.txt") for i in range(n)]


def test_happy_the_folders_are_made_off_the_gui_thread_then_the_copies_queued():
    win, left, right = _Win(), _Pane("/l"), _Pane("/r")
    right.backend = SlowFolders(right.backend)
    ticks = []
    timer = QTimer()
    timer.setInterval(20)
    timer.timeout.connect(lambda: ticks.append(1))
    timer.start()
    start = time.perf_counter()
    win._apply_sync(left, right, _plan(5))
    assert time.perf_counter() - start < 0.2
    assert win._transfer_manager.calls == []  # not before the folders exist
    _drain_sync(win)
    timer.stop()
    assert [p for p, _t in right.backend.made] == [f"/r/d{i}" for i in range(5)]
    assert all(t != "MainThread" for _p, t in right.backend.made)
    assert len(win._transfer_manager.calls) == 5
    assert len(ticks) >= 1


def test_sad_a_pane_closed_meanwhile_queues_nothing():
    win, left, right = _Win(), _Pane("/l"), _Pane("/r")
    right.backend = SlowFolders(right.backend)
    open_panes = {"yes": True}
    win._compared_panes_open = lambda *panes: open_panes["yes"]
    win._apply_sync(left, right, _plan(3))
    open_panes["yes"] = False  # the pane goes while the folders are made
    _drain_sync(win)
    assert win._transfer_manager.calls == []


def test_edge_a_plan_without_folders_queues_at_once():
    win, left, right = _Win(), _Pane("/l"), _Pane("/r")
    win._apply_sync(left, right, [_sync_item("a.txt")])
    assert win._transfer_manager.calls == [(["/l/a.txt"], "/r")]
