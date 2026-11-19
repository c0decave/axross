"""Long-lived receivers report through one thread-relay entry, not one per call.

Measured before: each GuiCall adds an entry to the relay's table that goes
only once its receiver is deleted. The Analysis dock's folder lister made a
new one for every folder listed and the main window one for every scheduled
run (tests/test_scheduler_run_now_and_relay.py): the table grew with every
use for as long as the window lived.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import thread_relay  # noqa: E402

APP = QApplication.instance() or QApplication([])


class _Backend:
    def list_dir(self, path):
        return []

    def join(self, a, b):
        return f"{a}/{b}"


def test_sad_the_analysis_lister_keeps_one_relay_entry(tmp_path):
    from ui.analysis_dock import _Lister

    lister = _Lister()
    got = []
    lister.listed.connect(lambda token, targets, error: got.append(token))
    lister.list(_Backend(), "/a", 0)
    entries = len(thread_relay._TARGETS)
    for token in range(1, 6):
        lister.list(_Backend(), "/a", token)
    deadline = time.monotonic() + 5
    while len(got) < 6 and time.monotonic() < deadline:
        APP.processEvents()
        time.sleep(0.01)
    assert sorted(got) == list(range(6))
    assert len(thread_relay._TARGETS) == entries
