"""core/thread_relay.py: calls from worker threads into the GUI thread that
survive the receiver being deleted meanwhile."""

from __future__ import annotations

import gc
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6 import sip  # noqa: E402
from PyQt6.QtCore import QObject  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import thread_relay as TR  # noqa: E402

APP = QApplication.instance() or QApplication([])


class Receiver(QObject):
    def __init__(self) -> None:
        super().__init__()
        self.calls: list = []

    def on_result(self, *args) -> None:
        self.calls.append((args, threading.current_thread()))


def _pump_until(cond, seconds: float = 5.0) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.005)
    return False


# --- happy ---------------------------------------------------------------------


def test_happy_a_worker_s_call_runs_in_the_gui_thread_with_its_arguments():
    r = Receiver()
    call = TR.GuiCall(r.on_result)
    worker = threading.Thread(target=call, args=(1, "two", None))
    worker.start()
    worker.join()
    assert _pump_until(lambda: r.calls)
    assert r.calls == [((1, "two", None), threading.main_thread())]


# --- sad -----------------------------------------------------------------------


def test_sad_a_call_for_a_deleted_receiver_is_dropped():
    r = Receiver()
    call = TR.GuiCall(r.on_result)
    seen = r.calls
    worker = threading.Thread(target=call, args=("late",))
    worker.start()
    worker.join()
    sip.delete(r)  # deleted before the GUI thread got to the call
    APP.processEvents()
    assert seen == []


def test_sad_only_a_method_of_a_qobject_is_taken():
    with pytest.raises(TypeError):
        TR.GuiCall(lambda: None)
    with pytest.raises(TypeError):
        TR.GuiCall(object().__str__)


# --- edge ----------------------------------------------------------------------


def test_edge_the_call_never_keeps_its_receiver_alive():
    r = Receiver()
    call = TR.GuiCall(r.on_result)
    key = call._key
    del r
    gc.collect()
    ref, _func = TR._TARGETS[key]
    assert ref() is None
    TR._sweep()
    assert key not in TR._TARGETS


_COLLECTED_IN_CYCLES = """
import gc, os, sys
sys.path.insert(0, os.getcwd())
from PyQt6.QtCore import QObject
from PyQt6.QtWidgets import QApplication, QDialog
app = QApplication([])
from core.thread_relay import GuiCall

class R(QObject):
    def slot(self):
        pass

for i in range(2000):
    r = R()
    r.call = GuiCall(r.slot)
    r.cycle = r
    d = QDialog()
    child = R(d)
    child.call = GuiCall(child.slot)
    d.cycle = d
    d.child = child
    del r, d, child
    if i % 50 == 0:
        gc.collect()
        app.processEvents()
print("ok")
"""


def test_edge_receivers_collected_in_reference_cycles_do_not_crash_the_collector():
    """A first version hooked a Python slot on each receiver's ``destroyed``
    and took a lock there: the garbage collector, deleting such receivers as
    part of a cycle, segfaulted every time in this loop."""
    env = dict(os.environ, QT_QPA_PLATFORM="offscreen")
    run = subprocess.run([sys.executable, "-c", _COLLECTED_IN_CYCLES], cwd=ROOT, env=env,
                         capture_output=True, text=True, timeout=120)
    assert run.returncode == 0, (run.returncode, run.stderr[-2000:])
    assert run.stdout.strip().endswith("ok")


def test_edge_the_exit_clean_up_leaves_the_relay_alone():
    """main.py deletes every Python-owned QObject after app.exec() while
    daemon workers may still call into the relay: it must not be one."""
    from core.qt_exit import _python_owned, _qt

    relay = TR._relay()
    assert not sip.ispyowned(relay)
    assert all(obj is not relay for obj in _python_owned(_qt()))


def test_edge_a_relay_deleted_anyway_is_replaced_for_new_calls():
    old = TR._relay()
    try:
        sip.delete(old)
        r = Receiver()
        call = TR.GuiCall(r.on_result)
        threading.Thread(target=call, args=("again",)).start()
        assert _pump_until(lambda: r.calls)
        assert TR._relay() is not old
    finally:
        TR._RELAY = TR._relay()


def test_edge_scan_job_wakes_through_the_relay():
    """ScanJob's end-of-work wake-up is a GuiCall, not a signal emitted by
    the worker on the job itself."""
    from ui.scan_job import ScanJob

    job = ScanJob()
    assert isinstance(job._wake, TR.GuiCall)
    done = []
    job.finished.connect(lambda kind, value, cancelled: done.append((kind, value)))
    job._timer.setInterval(60_000)  # only the wake-up can report in time
    job.start(lambda cancel, progress: 42)
    assert _pump_until(lambda: done, 5)
    assert done == [("done", 42)]
