"""A media viewer result posted while the viewer closes is released.

Before: a TaskRunner worker marked its result current under the lock and
posted it after the lock was released. When the viewer was shut down and
deleted in that gap, the GuiCall dropped the result (its receiver was
gone), and nothing released it: the temp copy of a remote file
(``release()``) stayed in /tmp.

Now a posted result is kept until the GUI thread takes it; shutdown()
- and a worker that finds its runner deleted - releases what is left.
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

from PyQt6 import sip  # noqa: E402
from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.thread_relay import GuiCall  # noqa: E402
from ui import media_viewer as MV  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _pump(seconds: float = 0.2) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.005)


def _wait(cond, timeout: float = 10.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.005)
    return cond()


class _Copy:
    def __init__(self, released: list):
        self._released = released

    def release(self):
        self._released.append(self)


@pytest.fixture
def held_post(monkeypatch):
    """The worker stops between its check and its post until told to go on."""
    posting, go_on = threading.Event(), threading.Event()

    class HeldCall(GuiCall):
        __slots__ = ()

        def __call__(self, *args):
            posting.set()
            go_on.wait(10)
            super().__call__(*args)

    monkeypatch.setattr(MV, "GuiCall", HeldCall)
    yield posting, go_on
    go_on.set()


def _workers_done(runner_threads) -> bool:
    return not any(t.is_alive() for t in runner_threads)


def test_happy_shutdown_and_delete_in_the_gap_releases_the_copy(held_post):
    posting, go_on = held_post
    released: list = []
    runner = MV.TaskRunner(workers=1)
    threads = list(runner._threads)
    delivered = []
    runner.finished.connect(lambda k, v, e: delivered.append(v))
    runner.submit("prepare", lambda cancel: _Copy(released))
    assert posting.wait(10)
    runner.shutdown()                       # the viewer closes ...
    runner.deleteLater()                    # ... and goes
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    assert sip.isdeleted(runner)
    go_on.set()
    assert _wait(lambda: _workers_done(threads))
    _pump()
    assert delivered == []
    assert len(released) == 1, "the copy was never released"


def test_sad_deleted_without_shutdown_the_idle_worker_releases_it(held_post, monkeypatch):
    monkeypatch.setattr(MV, "_IDLE_CHECK_SECONDS", 0.05)
    posting, go_on = held_post
    released: list = []
    runner = MV.TaskRunner(workers=1)
    threads = list(runner._threads)
    runner.submit("prepare", lambda cancel: _Copy(released))
    assert posting.wait(10)
    runner.deleteLater()                    # a window collected without its stop()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    go_on.set()
    assert _wait(lambda: _workers_done(threads))
    _pump()
    assert len(released) == 1


def test_edge_two_results_in_the_gap_are_each_released_once_a_delivered_one_never(monkeypatch):
    posted, go_on = [], threading.Event()
    hold = [False]

    class HeldCall(GuiCall):
        __slots__ = ()

        def __call__(self, *args):
            if hold[0]:
                posted.append(1)
                go_on.wait(10)
            super().__call__(*args)

    monkeypatch.setattr(MV, "GuiCall", HeldCall)
    released: list = []
    runner = MV.TaskRunner(workers=2)
    threads = list(runner._threads)
    delivered = []
    runner.finished.connect(lambda k, v, e: delivered.append(v))
    runner.submit("shown", lambda cancel: _Copy(released))
    assert _wait(lambda: delivered)          # taken by its owner, who releases it
    hold[0] = True
    both = threading.Barrier(2)             # both workers busy at once

    def prepare(cancel):
        both.wait(10)
        return _Copy(released)

    for key in ("a", "b"):
        runner.submit(key, prepare)
    try:
        assert _wait(lambda: len(posted) == 2)
        runner.shutdown()
        runner.deleteLater()
        APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    finally:
        go_on.set()
    assert _wait(lambda: _workers_done(threads))
    _pump()
    assert len(delivered) == 1
    assert len(released) == 2 and len({id(c) for c in released}) == 2
