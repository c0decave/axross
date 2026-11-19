"""axross.toast(): a timeout out of range neither raises nor leaves the
toast on the screen for good.

Review 2026-11-20 (toasts round 2): the toast was shown first and its
dismissal timer set after, with ``int(timeout * 1000)`` milliseconds. A
timeout of a month (``timeout=3e6``), ``float("inf")`` or a string raised
from QTimer (OverflowError / TypeError) into the script - with the toast
already on the screen and in the stack, where nothing ever took it away
again. The timeout is checked first now: not a number is refused before
anything is shown, NaN is the default, and it is held to 0.5 s .. 1 h.
"""

from __future__ import annotations

import math
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")

from PyQt6.QtWidgets import QApplication, QWidget  # noqa: E402

from core import ui_helpers as UH  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def timers(monkeypatch):
    from PyQt6.QtCore import QTimer

    started: list[int] = []
    real = QTimer.singleShot

    def spy(msec, *args):
        started.append(msec)
        return real(min(int(msec), 10), *args)

    monkeypatch.setattr(QTimer, "singleShot", spy)
    window = QWidget()
    window.show()
    yield started
    window.close()
    window.deleteLater()
    APP.processEvents()


@pytest.mark.parametrize("timeout", [3e6, float("inf"), 1e300])
def test_sad_a_huge_timeout_is_held_to_an_hour(timers, timeout):
    UH.toast("long", timeout=timeout)
    assert timers and timers[-1] == 3600 * 1000


def test_sad_a_timeout_that_is_no_number_is_refused_before_anything_shows(timers):
    before = len(UH._active_toasts)
    with pytest.raises(TypeError):
        UH.toast("x", timeout="soon")
    assert len(UH._active_toasts) == before


def test_edge_nan_and_a_negative_timeout(timers):
    UH.toast("nan", timeout=math.nan)
    UH.toast("neg", timeout=-5)
    assert timers[-2:] == [4000, 500]


def test_happy_a_normal_timeout_is_kept(timers):
    UH.toast("ok", timeout=2.5)
    assert timers[-1] == 2500
