"""Opening a member of an archive extracts it off the GUI thread.

Found by the second audit (feedback: no blocked windows): a double-click
on a member in the archive view (and Open as Hex / Text) extracted it on
the GUI thread - one member can be gigabytes, and a .tar.gz is
decompressed up to it, every window frozen meanwhile. It runs through
MainWindow._extract_off_the_gui_thread now, as a nested archive did: a
worker, the window live, a Cancel dialog after 250 ms; a cancel opens
nothing.
"""

from __future__ import annotations

import os
import sys
import threading
import time
import zipfile
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QTimer  # noqa: E402
from PyQt6.QtWidgets import QApplication, QProgressDialog  # noqa: E402

from core import archive as ARCH  # noqa: E402

APP = QApplication.instance() or QApplication([])

# TICKS_NOTE: a timer that ticked at all ran during the wait - a GUI thread
# held by the call gets none (the timer stops before the loop runs again).
# How often it ticked depends on the host's load, so only "at all" counts.


@pytest.fixture
def window():
    from ui.main_window import MainWindow

    win = MainWindow()
    yield win
    win._cleanup_archive_tempdirs()
    win.close()
    win.deleteLater()
    APP.processEvents()


@pytest.fixture
def archive(tmp_path):
    path = tmp_path / "pack.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("docs/readme.txt", "hello")
    return path


def test_happy_the_member_is_extracted_off_the_gui_thread(window, archive):
    real = ARCH.extract_members
    threads: list[str] = []

    def slow(*a, **k):
        threads.append(threading.current_thread().name)
        time.sleep(0.3)
        return real(*a, **k)

    ticks = []
    timer = QTimer()
    timer.setInterval(20)
    timer.timeout.connect(lambda: ticks.append(1))
    timer.start()
    with mock.patch.object(ARCH, "extract_members", slow):
        extracted = window._extract_single_member(str(archive), "docs/readme.txt")
    timer.stop()
    assert Path(extracted).read_text() == "hello"
    assert threads and "MainThread" not in threads
    assert len(ticks) >= 1


def test_sad_cancel_opens_nothing(window, archive):
    def endless(archive_path, target, members, progress=None):
        while True:
            progress(0, 1, "x")
            time.sleep(0.01)

    def press_cancel():
        for widget in APP.allWidgets():
            if isinstance(widget, QProgressDialog) and widget.isVisible():
                widget.cancel()  # what Esc does: only wasCanceled() says so

    QTimer.singleShot(600, press_cancel)
    with mock.patch.object(ARCH, "extract_members", endless):
        assert window._extract_single_member(str(archive), "docs/readme.txt") is None
    assert window._archive_last_member_tempdir is None
