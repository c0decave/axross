"""Scheduled jobs: the tick and the open Scheduled Jobs window, the
cadence, re-enabling a job, the shortest interval.

What was wrong (review round 2):

* MainWindow refreshed its job list only after the Scheduled Jobs window
  closed (after ``dlg.exec()``), while the 60 s tick kept firing inside
  exec(): a job switched off or removed in the open window still started.
* ``last_run_at`` was the finish of a run: "every 1 h" drifted by each
  run's length (and the tick's delay).
* A job re-enabled after it disabled itself kept ``consecutive_failures``
  at 10: one more transient failure disabled it again, and its row said
  "disabled after 10 consecutive failures" while it was enabled.
* The window's custom interval accepted 1 s against the stated
  five-minute minimum.
"""

from __future__ import annotations

import os
import sys
import types
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.scheduler import (  # noqa: E402
    MAX_CONSECUTIVE_FAILURES,
    Job,
    JobStore,
    record_result,
)

APP = QApplication.instance() or QApplication([])


def _window(store: JobStore):
    """The scheduler part of MainWindow on a stand-in object."""
    from ui.main_window import MainWindow

    started: list[str] = []
    stub = types.SimpleNamespace(_scheduler_jobs=store.load(),
                                 _run_scheduled_job=lambda job: started.append(job.job_id),
                                 _job_store=lambda: store)
    for name in ("_scheduler_tick", "_with_running_flags", "_on_scheduled_job_finished"):
        setattr(stub, name, types.MethodType(getattr(MainWindow, name), stub))
    return stub, started


def test_sad_a_job_switched_off_or_removed_in_the_open_window_does_not_start(tmp_path):
    from ui.scheduler_dialog import SchedulerDialog

    store = JobStore(tmp_path / "jobs.json")
    store.save([Job("j1", "nightly", "script", "mirror", 300),
                Job("j2", "hourly", "script", "mirror", 300),
                Job("j3", "kept", "script", "mirror", 300)])        # never ran: all due now
    window, started = _window(store)
    dlg = SchedulerDialog(store)                                     # open, its exec() running
    dlg.set_enabled("j1", False)
    dlg.remove_job("j2")
    window._scheduler_tick()                                         # the timer fires inside exec()
    assert started == ["j3"]
    # j3 is in flight: the next tick, which reloads the store, does not start it again.
    window._scheduler_tick()
    assert started == ["j3"]
    dlg.deleteLater()


def test_sad_last_run_is_the_planned_slot_not_the_finish(tmp_path):
    store = JobStore(tmp_path / "jobs.json")
    slot_before = datetime.now().replace(microsecond=0) - timedelta(hours=1, seconds=40)
    store.save([Job("j1", "hourly", "script", "mirror", 3600, last_run_at=slot_before,
                    last_ok=True)])
    window, started = _window(store)
    window._scheduler_tick()
    assert started == ["j1"]
    window._on_scheduled_job_finished("j1", True, "ran mirror")      # some minutes later, say
    job = store.load()[0]
    assert job.last_run_at == slot_before + timedelta(hours=1)
    assert not window._scheduler_jobs[0].running


def test_edge_a_slot_missed_by_a_whole_interval_counts_from_now():
    from core.scheduler import planned_start

    now = datetime(2026, 11, 9, 8, 0, 30)
    hourly = Job("j", "n", "script", "t", 3600, last_run_at=now - timedelta(days=3))
    assert planned_start(hourly, now=now) == now                     # no catching up
    on_time = Job("j", "n", "script", "t", 3600, last_run_at=now - timedelta(hours=1, seconds=30))
    assert planned_start(on_time, now=now) == now - timedelta(seconds=30)
    assert planned_start(Job("j", "n", "script", "t", 3600), now=now) == now   # never ran


def test_sad_re_enabling_a_self_disabled_job_starts_its_failure_count_over(tmp_path):
    from ui.scheduler_dialog import SchedulerDialog, job_row

    store = JobStore(tmp_path / "jobs.json")
    dlg = SchedulerDialog(store)
    job = dlg.add_job(name="nightly", kind="script", target="mirror", interval_s=3600)
    for _ in range(MAX_CONSECUTIVE_FAILURES):
        store.update(lambda js: [record_result(j, ok=False, at=datetime.now(), detail="host down")
                                 for j in js])
    assert store.load()[0].enabled is False
    dlg.reload()
    dlg.set_enabled(job.job_id, True)
    j = store.load()[0]
    assert j.enabled and j.consecutive_failures == 0
    assert "disabled after" not in job_row(j)["Detail"] and job_row(j)["Detail"] == "host down"
    store.update(lambda js: [record_result(x, ok=False, at=datetime.now(), detail="host down")
                             for x in js])
    assert store.load()[0].enabled is True                          # one failure is not ten
    dlg.deleteLater()


def test_sad_a_custom_interval_below_five_minutes_is_not_accepted(tmp_path, monkeypatch):
    from ui.scheduler_dialog import SchedulerDialog

    monkeypatch.setattr(SchedulerDialog, "_saved_scripts", staticmethod(lambda: ["mirror"]))

    store = JobStore(tmp_path / "jobs.json")
    dlg = SchedulerDialog(store)
    dlg._custom_spin.setValue(1)
    assert dlg._custom_spin.value() == 300                           # snapped up to the minimum
    dlg._custom_spin.setValue(299)
    assert dlg._custom_spin.value() == 0                             # going down: back to the list
    dlg._custom_spin.setValue(600)
    assert dlg._custom_spin.value() == 600
    with pytest.raises(ValueError):
        dlg.add_job(name="fast", kind="script", target="mirror", interval_s=60)
    dlg._custom_spin.setValue(1)
    dlg._name_edit.setText("fast")
    dlg._target_edit.setText("mirror")
    dlg._on_add()
    assert [j.interval_s for j in store.load()] == [300]
    dlg.deleteLater()
