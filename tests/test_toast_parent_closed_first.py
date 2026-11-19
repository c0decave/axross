"""A toast whose window is closed before the toast times out goes quietly.

Review 2026-11-19 (round 1): a toast is a child of the first visible
top-level window - a viewer, a dialog, a detached workspace. Closed and
deleted before the toast's timeout, it took the toast with it, and the
toast's dismissal then called close() on the deleted widget:
"wrapped C/C++ object of type QFrame has been deleted" went to the
excepthook, an error dialog in the GUI. The stack's re-layout touched the
dead window as well.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")

from PyQt6 import sip  # noqa: E402
from PyQt6.QtWidgets import QApplication, QWidget  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _pump(seconds: float) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture
def errors(monkeypatch):
    seen: list = []
    monkeypatch.setattr(sys, "excepthook", lambda *exc: seen.append(exc[1]))
    yield seen


def test_sad_the_window_of_a_toast_deleted_before_its_timeout(errors):
    from core import ui_helpers as U

    for w in APP.topLevelWidgets():
        w.hide()
    window = QWidget()
    window.show()
    U.toast("hello", timeout=0.5)
    U.toast("second", timeout=3.0)
    sip.delete(window)
    _pump(0.9)
    assert errors == []
    with U._toasts_lock:
        assert all(not sip.isdeleted(t) for t in U._active_toasts)


def test_happy_toasts_on_a_living_window_still_stack_and_go(errors):
    from core import ui_helpers as U

    window = QWidget()
    window.show()
    U.toast("one", timeout=0.5)
    U.toast("two", timeout=0.5)
    _pump(0.9)
    window.close()
    window.deleteLater()
    assert errors == []
    with U._toasts_lock:
        assert U._active_toasts == []
