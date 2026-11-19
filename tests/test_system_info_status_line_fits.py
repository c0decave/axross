"""System Information's status line does not widen the window.

Found in review (round 1 of the 2026-11 reviews, UI shell; repro: every
menu window opened on a 1024x600 screen): on a machine where several
sources are missing (a VM, a container) the status line reads
"Gathered at … · not available: Machine & Firmware, Graphics & Displays,
…" in one line, and the window could not get narrower than that line -
1144 px, past a 1024 px screen. An error naming a long path did the same.
The line wraps within the window now.
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

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import system_info as SI  # noqa: E402
from tests.system_info_fixture import build_laptop, fake_usage  # noqa: E402
from ui import system_info_window as W  # noqa: E402

APP = QApplication.instance() or QApplication([])
LIMIT = 984


@pytest.fixture
def win(tmp_path):
    root = build_laptop(tmp_path / "root")
    window = W.SystemInfoWindow(
        None, live=False,
        info_factory=lambda: SI.SystemInfo(root, usage=fake_usage, hostname="x1",
                                           system="Linux", env={}, addresses=lambda: {}))
    window.show()
    end = time.monotonic() + 20
    while window.report is None and time.monotonic() < end:  # gathered: the line is ours
        APP.processEvents()
        time.sleep(0.01)
    assert window.report is not None
    yield window
    window.close()
    window.deleteLater()
    APP.processEvents()


def test_happy_a_short_status_line_still_reads_in_full(win):
    win.status.setText("Gathered at 12:00:00 in 0.1 s")
    APP.processEvents()
    assert win.status.text() == "Gathered at 12:00:00 in 0.1 s"
    assert win.minimumSizeHint().width() <= LIMIT


def test_sad_many_missing_sources_do_not_widen_the_window(win):
    win.status.setText("Gathered at 19:57:37 in 0.0 s · not available: " + ", ".join(
        ["Machine & Firmware", "Graphics & Displays", "Battery & Power", "Sensors",
         "Bluetooth", "Printers", "Audio Devices", "Input Devices", "Cameras"] * 2))
    APP.processEvents()
    assert win.minimumSizeHint().width() <= LIMIT, win.minimumSizeHint()
    # ... and it is all there, in more than one line.
    win.resize(900, 600)
    for _ in range(5):
        APP.processEvents()
    assert win.status.height() >= 2 * win.status.fontMetrics().height(), win.status.height()


def test_edge_an_error_with_a_long_path_does_not_widen_the_window(win):
    win.status.setText("Could not gather the system information: " + "/very-long" * 200)
    APP.processEvents()
    assert win.minimumSizeHint().width() <= LIMIT, win.minimumSizeHint()
