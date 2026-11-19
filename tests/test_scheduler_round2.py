"""Scheduled jobs: one run at a time across processes, no failures for a
refusal, a short failure detail, a clock that went back.

Review 2026-11-20 (scheduler round 2), each reproduced before the fix:

* "A job still running is not started again" held inside one process
  only: the running flag lives in memory and the store learns of a run
  when it ends. A second axross (no single-instance guard) or a restart
  after a crash - the script child of the dead process runs on - started
  the same job beside the first: two writers on one destination. A run
  now takes the job's lease first (an flock on ``jobs.leases/<id>.lock``
  beside the store), which its script child inherits; a job whose lease
  is held elsewhere is not started and not counted as a failure.
* In the paranoid security mode every slot of every job was a recorded
  failure ("blocks saved script execution"): after ten each job was
  disabled for good, and leaving the mode did not bring them back. A run
  the security mode refuses is not run, not failed.
* A failure's detail was the script's whole last stderr line - up to the
  1 000 000 character output limit - stored in jobs.json, logged and put
  into the status bar (0.6 s for that one call). It is held to its last
  DETAIL_MAX_CHARS characters.
* A last run stamped more than an interval in the future (the clock was
  set back: the end of daylight saving time for a 5-minute job, an NTP
  correction) held the job until the clock caught up - an hour, or a
  month. Such a job is due now.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import scheduler, scripting  # noqa: E402
from core.scheduler import Job, run_job  # noqa: E402

posix_only = pytest.mark.skipif(os.name != "posix", reason="flock")


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("AXROSS_SECURITY_MODE", raising=False)
    (tmp_path / "state").mkdir()
    return tmp_path


def _job(target: str, job_id: str = "j1", interval_s: int = 300, **kw) -> Job:
    return Job(job_id=job_id, name=target, kind="script", target=target,
               interval_s=interval_s, **kw)


def _run(job: Job, **kw) -> list[tuple]:
    outcome: list[tuple] = []
    run_job(job, runner=lambda j: scheduler.run_script_job(j, **kw),
            on_finished=lambda j, ok, detail: outcome.append((ok, detail)))
    return outcome


@posix_only
def test_sad_a_job_running_in_another_process_is_not_started_again(home):
    marker = home / "ran"
    scripting.save_script("lease_twice", f"open({str(marker)!r}, 'a').write('x')\n")
    leases = home / "state"
    held = scheduler.take_job_lease(leases, "j1")  # the other process's run
    assert isinstance(held, int)
    try:
        [(ok, detail)] = _run(_job("lease_twice"), lease_dir=leases)
    finally:
        os.close(held)
    assert ok is None and "another" in detail
    assert not marker.exists()
    assert _run(_job("lease_twice"), lease_dir=leases) == [(True, "ran lease_twice")]
    assert marker.read_text() == "x"


@posix_only
@pytest.mark.skipif(not Path("/proc/self/fd").is_dir(), reason="Linux /proc")
def test_sad_the_script_child_holds_the_lease_itself(home):
    """An orphan of a crashed axross keeps the job taken."""
    out = home / "fds"
    scripting.save_script("lease_child", (
        "import os\n"
        "links = []\n"
        "for f in os.listdir('/proc/self/fd'):\n"
        "    try:\n"
        "        links.append(os.readlink('/proc/self/fd/' + f))\n"
        "    except OSError:\n"
        "        pass\n"
        f"open({str(out)!r}, 'w').write('\\n'.join(l for l in links if l.endswith('.lock')))\n"
    ))
    assert _run(_job("lease_child"), lease_dir=home / "state")[0][0] is True
    assert "jobs.leases" in out.read_text()


@posix_only
def test_edge_a_run_in_flight_keeps_the_job_taken_until_it_ends(home):
    scripting.save_script("lease_slow", "import time\ntime.sleep(1.5)\n")
    leases = home / "state"
    first: list = []
    worker = threading.Thread(target=lambda: first.extend(_run(_job("lease_slow"),
                                                               lease_dir=leases)))
    worker.start()
    time.sleep(0.5)
    [(ok, _detail)] = _run(_job("lease_slow"), lease_dir=leases)
    worker.join(30)
    assert ok is None
    assert first == [(True, "ran lease_slow")]


def test_edge_a_job_id_never_leaves_the_lease_folder(home):
    fd = scheduler.take_job_lease(home / "state", "../../etc/x")
    try:
        names = os.listdir(home / "state" / "jobs.leases")
        assert len(names) == 1 and "/" not in names[0] and ".." not in names[0]
    finally:
        if isinstance(fd, int):
            os.close(fd)


def test_sad_the_paranoid_mode_refuses_without_counting_a_failure(home, monkeypatch):
    from core import security_mode

    monkeypatch.setattr(security_mode, "_CURRENT", security_mode.policy_from_name("paranoid"))
    [(ok, detail)] = _run(_job("anything"))
    assert ok is None
    assert "paranoid" in detail


def test_sad_a_long_failure_detail_is_held_to_its_end():
    job = _job("x")
    detail = "A" * 900_000 + "the end"
    recorded = scheduler.record_result(job, ok=False, at=datetime.now(), detail=detail)
    assert len(recorded.last_detail) <= scheduler.DETAIL_MAX_CHARS
    assert recorded.last_detail.endswith("the end")


def test_edge_a_long_detail_still_names_the_disabling():
    job = _job("x", consecutive_failures=scheduler.MAX_CONSECUTIVE_FAILURES - 1)
    recorded = scheduler.record_result(job, ok=False, at=datetime.now(), detail="B" * 10_000)
    assert recorded.enabled is False
    assert len(recorded.last_detail) <= scheduler.DETAIL_MAX_CHARS
    assert recorded.last_detail.endswith("consecutive failures")


def test_sad_a_hand_edited_long_detail_is_held_on_load(tmp_path):
    store = scheduler.JobStore(tmp_path / "jobs.json")
    store.save([_job("x", last_detail="C" * 50_000)])
    [job] = store.load()
    assert len(job.last_detail) <= scheduler.DETAIL_MAX_CHARS


def test_sad_a_last_run_far_in_the_future_is_due_now():
    now = datetime(2026, 11, 20, 12, 0)
    job = _job("x", last_run_at=now + timedelta(days=30))
    assert scheduler.due_jobs([job], now=now) == [job]
    assert scheduler.planned_start(job, now=now) == now


def test_edge_the_end_of_daylight_saving_does_not_hold_a_short_job():
    # 02:55 summer time, then the clock goes back to 02:00.
    job = _job("x", interval_s=300, last_run_at=datetime(2026, 10, 25, 2, 55))
    assert scheduler.due_jobs([job], now=datetime(2026, 10, 25, 2, 1)) == [job]


def test_happy_a_daily_job_is_not_run_twice_when_the_clock_goes_back_an_hour():
    job = _job("x", interval_s=86_400, last_run_at=datetime(2026, 10, 25, 2, 30))
    assert scheduler.due_jobs([job], now=datetime(2026, 10, 25, 2, 5)) == []


# -- the window's side ------------------------------------------------------------


_APP = []


def _qt():
    """The QApplication, kept alive for the module (a dropped one aborts)."""
    pytest.importorskip("PyQt6.QtWidgets")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PyQt6.QtWidgets import QApplication

    if not _APP:
        _APP.append(QApplication.instance() or QApplication([]))
    return _APP[0]


def test_sad_the_tick_starts_nothing_in_the_paranoid_mode(home, monkeypatch, tmp_path):
    _qt()
    import ui.main_window as mw
    from core import security_mode

    class Host:
        _scheduler_tick = mw.MainWindow._scheduler_tick
        _with_running_flags = mw.MainWindow._with_running_flags

        def __init__(self, path):
            self.path, self.started = path, []
            self._scheduler_jobs = self._job_store().load()

        def _job_store(self):
            return scheduler.JobStore(self.path)

        def _run_scheduled_job(self, job):
            self.started.append(job.job_id)

    path = tmp_path / "jobs.json"
    scheduler.JobStore(path).save([_job("x", last_run_at=datetime.now() - timedelta(hours=2))])
    monkeypatch.setattr(security_mode, "_CURRENT", security_mode.policy_from_name("paranoid"))
    host = Host(path)
    host._scheduler_tick()
    assert host.started == []
    monkeypatch.setattr(security_mode, "_CURRENT", security_mode.policy_from_name("normal"))
    host._scheduler_tick()
    assert host.started == ["j1"]


def test_happy_the_window_runs_with_the_lease_beside_the_store(home, monkeypatch):
    import ui.main_window as mw

    seen = {}
    monkeypatch.setattr(scheduler, "run_script_job",
                        lambda job, **kw: seen.update(kw) or "ran")
    mw.MainWindow._scheduled_runner(_job("x"), cancel_event=None, lease_dir=home / "state")
    assert seen["lease_dir"] == home / "state"


def test_happy_the_window_says_why_a_job_did_not_run(tmp_path):
    _qt()
    from ui.scheduler_dialog import SchedulerDialog

    store = scheduler.JobStore(tmp_path / "jobs.json")
    store.save([_job("mirror")])
    dlg = SchedulerDialog(store, run_now=lambda job: True)
    try:
        dlg.job_finished("j1", None, "not started: the job is running in another axross process")
        assert "another axross process" in dlg._status.text()
        dlg.job_finished("j1", None, "cancelled: the application closed during the run")
        assert "application closed" in dlg._status.text()
    finally:
        dlg.deleteLater()
