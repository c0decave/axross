"""Run Now, the thread relay and a store that cannot be written.

Measured before:

* Scheduled Jobs > Run Now recorded the moment the run *ended* as its last
  run (only the tick noted a start), so a long run moved the next slot by
  its own length - the tick records the start.
* Every scheduled run made a new ``GuiCall`` to report back: each left an
  entry in the thread relay's table for as long as the window lived.
* An OSError saving the schedule (a full disk, a read-only config folder)
  from Add, Remove or Enable/Disable went up to the global error dialog.
"""

from __future__ import annotations

import os
import sys
import time
import types
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QObject  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core import thread_relay  # noqa: E402
from core.scheduler import Job, JobStore  # noqa: E402

APP = QApplication.instance() or QApplication([])


class _Stub(QObject):
    pass


def _window(store: JobStore, runner):
    from ui.main_window import MainWindow

    stub = _Stub()
    stub._scheduler_jobs = store.load()
    stub._job_store = lambda: store
    stub._scheduled_runner = runner
    stub.statusBar = lambda: types.SimpleNamespace(showMessage=lambda *a: None)
    for name in ("_run_job_now", "_run_scheduled_job", "_with_running_flags",
                 "_on_scheduled_job_finished"):
        setattr(stub, name, types.MethodType(getattr(MainWindow, name), stub))
    return stub


def _wait_idle(stub, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        APP.processEvents()
        if not getattr(stub, "_scheduler_threads", None) and not any(
            j.running for j in stub._scheduler_jobs
        ):
            return
        time.sleep(0.01)
    raise AssertionError("the job did not finish")


def _slow(job, cancel_event=None, lease_dir=None):
    time.sleep(0.6)
    return "done"


def test_sad_run_now_records_the_start_not_the_finish(tmp_path):
    store = JobStore(tmp_path / "jobs.json")
    store.save([Job("j1", "nightly", "script", "mirror", 3600)])
    stub = _window(store, _slow)
    before = datetime.now()
    assert stub._run_job_now(store.load()[0])
    _wait_idle(stub)
    after_start = before.timestamp() + 0.4
    recorded = store.load()[0].last_run_at
    assert recorded is not None
    assert before.timestamp() - 1 <= recorded.timestamp() < after_start, (before, recorded)


def test_sad_scheduled_runs_leave_no_relay_entry_each(tmp_path):
    store = JobStore(tmp_path / "jobs.json")
    store.save([Job("j1", "nightly", "script", "mirror", 3600)])
    stub = _window(store, lambda job, cancel_event=None, lease_dir=None: "ok")
    stub._run_job_now(store.load()[0])
    _wait_idle(stub)
    entries = len(thread_relay._TARGETS)
    for _ in range(5):
        assert stub._run_job_now(store.load()[0])
        _wait_idle(stub)
    assert len(thread_relay._TARGETS) == entries
    assert store.load()[0].last_ok is True


def test_sad_an_unwritable_store_is_told_in_the_window(tmp_path, monkeypatch):
    from ui.scheduler_dialog import SchedulerDialog

    store = JobStore(tmp_path / "jobs.json")
    store.save([Job("j1", "nightly", "script", "mirror", 3600)])
    dlg = SchedulerDialog(store)
    shown: list[str] = []
    monkeypatch.setattr(QMessageBox, "warning", lambda parent, title, text, *a: shown.append(text))
    monkeypatch.setattr(QMessageBox, "question",
                        lambda *a, **k: QMessageBox.StandardButton.Yes)

    def full(change):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(store, "update", full)
    dlg._table.selectRow(0)
    dlg._on_toggle()  # raised into the global error dialog before
    dlg._on_remove()
    monkeypatch.setattr(dlg, "_saved_scripts", lambda: ["mirror"])
    dlg._name_edit.setText("again")
    dlg._target_edit.setText("mirror")
    dlg._on_add()
    assert len(shown) == 3
    assert all("No space left on device" in text for text in shown)
    assert dlg.displayed_names() == ["nightly"]
    assert store.load()[0].enabled is True
    dlg.deleteLater()
