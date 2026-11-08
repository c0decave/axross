"""A run_off_gui whose thread cannot start leaves no window unclosable.

Before: ``run_off_gui`` entered the close hold before its ``try`` and
started the worker outside it. When the thread could not start ("can't
start new thread"), the hold was never left: its application event
filter stayed installed, and every window shown then refused its close
for the rest of the session - also after later waits that worked.

Now the worker starts inside the ``try`` whose ``finally`` leaves the hold.
"""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QWidget  # noqa: E402

from ui import off_gui  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def no_thread(monkeypatch):
    real = threading.Thread.start

    def start(self):
        if self.name == "off-gui":
            raise RuntimeError("can't start new thread")
        return real(self)

    monkeypatch.setattr(threading.Thread, "start", start)


@pytest.fixture
def window():
    w = QWidget()
    w.show()
    APP.processEvents()
    yield w
    w.close()
    w.deleteLater()


def test_happy_the_error_is_raised_and_the_window_closes_afterwards(no_thread, window):
    with pytest.raises(RuntimeError, match="can't start new thread"):
        off_gui.run_off_gui(lambda: 1)
    assert off_gui._hold._depth == 0 and off_gui._hold._windows == {}
    assert window.close() is True
    assert not window.isVisible()


def test_sad_a_later_wait_that_works_also_leaves_the_windows_free(window, monkeypatch):
    real = threading.Thread.start
    failures = [RuntimeError("can't start new thread")]   # only the first one

    def start(self):
        if self.name == "off-gui" and failures:
            raise failures.pop()
        return real(self)

    monkeypatch.setattr(threading.Thread, "start", start)
    with pytest.raises(RuntimeError):
        off_gui.run_off_gui(lambda: 1)
    assert off_gui.run_off_gui(lambda: 2) == 2
    assert off_gui._hold._depth == 0
    assert window.close() is True


def test_edge_the_busy_cursor_and_status_are_not_left_behind(no_thread, window, monkeypatch):
    monkeypatch.setattr(off_gui, "BUSY_CURSOR_AFTER_MS", 0)
    told: list[str] = []
    with pytest.raises(RuntimeError):
        off_gui.run_off_gui(lambda: 1, status=told.append, text="Saving…")
    for _ in range(5):
        APP.processEvents()                 # the busy timer, had it stayed running
    assert QApplication.overrideCursor() is None
    assert told in ([], ["Saving…", ""])
    assert window.close() is True
