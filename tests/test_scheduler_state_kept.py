"""The schedule keeps what is true across the dialog and finishing runs.

Before:
* Closing Tools > Scheduler reloaded the jobs from disk, and the store
  never holds the in-process ``running`` flag: the next tick started a job
  that was still in flight a second time, concurrently.
* A job finishing while the dialog was open saved the main window's own
  stale list over the edits just made in the dialog (a disabled job came
  back enabled, an added job vanished); a dialog edit after a run saved the
  dialog's stale list over the run's result.
* The dialog suggested "Script name, e.g. mirror.py", but scripts are run
  by name ([A-Za-z0-9_-]+), so a job added that way failed on every run.
* jobs.json was written with the process umask (0644) next to 0600 files.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

import ui.main_window as mw  # noqa: E402
import ui.scheduler_dialog as SD  # noqa: E402
from core import scheduler, scripting  # noqa: E402
from core.scheduler import Job, JobStore, run_job  # noqa: E402

APP = QApplication.instance() or QApplication([])


class _Window:
    """The scheduler part of MainWindow, without the rest of the window."""

    _scheduler_tick = mw.MainWindow._scheduler_tick
    _on_scheduled_job_finished = mw.MainWindow._on_scheduled_job_finished
    _open_scheduler = mw.MainWindow._open_scheduler
    _with_running_flags = mw.MainWindow._with_running_flags

    def __init__(self, path: Path) -> None:
        self.path = path
        self.started: list[str] = []
        self._scheduler_jobs = self._job_store().load()

    def _job_store(self) -> JobStore:
        return JobStore(self.path)

    def _run_scheduled_job(self, job) -> None:
        self.started.append(job.job_id)  # stays in flight

    def statusBar(self):  # noqa: N802 - Qt name
        class _Bar:
            def showMessage(self, *_a):  # noqa: N802 - Qt name
                pass

        return _Bar()


def _job(job_id: str = "j1", **kw) -> Job:
    kw.setdefault("name", f"job {job_id}")
    kw.setdefault("kind", "script")
    kw.setdefault("target", "mirror")
    kw.setdefault("interval_s", 300)
    return Job(job_id=job_id, **kw)


@pytest.fixture
def window(tmp_path):
    path = tmp_path / "jobs.json"
    JobStore(path).save([_job()])
    return _Window(path)


def _dialog_doing(monkeypatch, action) -> None:
    """Replace the dialog the window opens by one that runs *action* on a
    real SchedulerDialog over the same store, as a user would, then closes."""

    real_dialog = SD.SchedulerDialog

    class _Dialog:
        def __init__(self, store, parent=None):
            self.real = real_dialog(store)

        def exec(self):
            action(self.real)
            return 0

    monkeypatch.setattr(SD, "SchedulerDialog", _Dialog)


def test_happy_closing_the_scheduler_keeps_a_running_job_running(window, monkeypatch):
    window._scheduler_tick()
    assert window.started == ["j1"]
    _dialog_doing(monkeypatch, lambda dlg: None)
    window._open_scheduler()
    assert [j.running for j in window._scheduler_jobs] == [True]
    window._scheduler_tick()
    assert window.started == ["j1"]  # not started a second time


def test_happy_a_run_finishing_while_the_dialog_is_open_keeps_its_edits(window, monkeypatch):
    window._scheduler_tick()
    dlg = SD.SchedulerDialog(window._job_store())
    dlg.add_job(name="backup", kind="script", target="backup", interval_s=3600)
    dlg.set_enabled("j1", False)
    window._on_scheduled_job_finished("j1", True, "ran mirror")
    stored = {j.name: j for j in window._job_store().load()}
    assert sorted(stored) == ["backup", "job j1"]
    assert stored["job j1"].enabled is False
    assert stored["job j1"].last_ok is True
    assert sorted(j.name for j in window._scheduler_jobs) == ["backup", "job j1"]


def test_edge_a_dialog_edit_after_a_run_keeps_the_runs_result(window):
    window._scheduler_tick()
    dlg = SD.SchedulerDialog(window._job_store())  # opened while the job runs
    window._on_scheduled_job_finished("j1", True, "ran mirror")
    dlg.add_job(name="backup", kind="script", target="backup", interval_s=3600)
    stored = {j.name: j for j in window._job_store().load()}
    assert stored["job j1"].last_ok is True
    assert stored["job j1"].last_run_at is not None


def test_edge_a_job_removed_while_running_is_not_brought_back(window):
    window._scheduler_tick()
    SD.SchedulerDialog(window._job_store()).remove_job("j1")
    window._on_scheduled_job_finished("j1", True, "ran mirror")
    assert window._job_store().load() == []


def test_edge_other_running_flags_survive_a_finished_run(tmp_path):
    path = tmp_path / "jobs.json"
    JobStore(path).save([_job("j1"), _job("j2", target="other")])
    window = _Window(path)
    window._scheduler_tick()
    window._on_scheduled_job_finished("j1", True, "ran mirror")
    running = {j.job_id: j.running for j in window._scheduler_jobs}
    assert running == {"j1": False, "j2": True}


def test_happy_the_placeholder_names_a_script_the_runner_accepts(tmp_path):
    dlg = SD.SchedulerDialog(JobStore(tmp_path / "jobs.json"))
    assert ".py" not in dlg._target_edit.placeholderText()


def test_happy_a_target_typed_with_py_is_stored_as_the_script_name(tmp_path):
    store = JobStore(tmp_path / "jobs.json")
    dlg = SD.SchedulerDialog(store)
    dlg._name_edit.setText("nightly")
    dlg._target_edit.setText("mirror.py")
    dlg._on_add()
    assert [j.target for j in store.load()] == ["mirror"]


def test_sad_an_invalid_target_is_refused_with_a_message(tmp_path, monkeypatch):
    shown: list[str] = []
    monkeypatch.setattr(SD.QMessageBox, "warning", lambda *a: shown.append(a[2]))
    store = JobStore(tmp_path / "jobs.json")
    dlg = SD.SchedulerDialog(store)
    dlg._name_edit.setText("nightly")
    dlg._target_edit.setText("../evil")
    dlg._on_add()
    assert store.load() == []
    assert shown and "script name" in shown[0]


def test_edge_a_stored_target_with_py_still_runs():
    scripting.save_script("sched_legacy_target", "x = 1\n")
    try:
        outcome: list[tuple] = []
        run_job(
            _job(target="sched_legacy_target.py"),
            runner=scheduler.run_script_job,
            on_finished=lambda j, ok, d: outcome.append((ok, d)),
        )
        assert outcome == [(True, "ran sched_legacy_target")]
    finally:
        scripting.delete_script("sched_legacy_target")


def test_sad_the_job_store_is_private(tmp_path):
    path = tmp_path / "state" / "jobs.json"
    JobStore(path).save([_job()])
    assert path.stat().st_mode & 0o777 == 0o600
    assert [p.name for p in path.parent.iterdir() if p.name != "jobs.json.lock"] == [
        "jobs.json"
    ]
