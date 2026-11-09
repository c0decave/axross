"""A scheduled run stopped because the application closed is no failure.

Review round 6 (F6): closing axross while a scheduled script ran ended the
child (as it should) and then recorded the run as failed - "failed" in the
Scheduler, one more towards "disabled after 3 consecutive failures", and
the slot counted as run. It is recorded as not run now.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import scheduler  # noqa: E402
from core.scheduler import Job, RunCancelled, run_job  # noqa: E402


def _job(**kw) -> Job:
    return Job(job_id="j1", name="nightly", kind="script", target="nightly",
               interval_s=300, **kw)


def _outcome(runner) -> list:
    out: list = []
    run_job(_job(), runner=runner, on_finished=lambda j, ok, d: out.append((ok, d)))
    return out


def test_sad_a_run_cancelled_by_the_close_is_reported_as_not_run():
    def runner(_job):
        raise RunCancelled("cancelled: the application closed during the run")

    assert _outcome(runner) == [(None, "cancelled: the application closed during the run")]


def test_happy_a_real_failure_is_still_a_failure():
    def runner(_job):
        raise RuntimeError("exited with status 1")

    assert _outcome(runner) == [(False, "exited with status 1")]


def test_edge_run_script_job_raises_run_cancelled(monkeypatch):
    from core import script_runner, scripting

    monkeypatch.setattr(scripting, "load_script", lambda name: "")
    monkeypatch.setattr(script_runner, "run_bounded", lambda *a, **k: SimpleNamespace(
        cancelled=True, timed_out=False, exit=None, output=""))
    try:
        scheduler.run_script_job(_job())
    except RunCancelled:
        pass
    else:  # pragma: no cover
        raise AssertionError("no RunCancelled")


def test_edge_the_window_records_nothing_for_a_stopped_run():
    from ui.main_window import MainWindow

    stored = _job(last_ok=True, last_detail="ok", last_run_at=datetime(2026, 1, 1),
                  running=True)
    finished = []
    fake = SimpleNamespace(
        _scheduler_planned={"j1": datetime(2026, 1, 2)},
        _scheduler_jobs=[stored],
        _scheduler_dialog=SimpleNamespace(job_finished=lambda *a: finished.append(a)),
        _job_store=lambda: (_ for _ in ()).throw(AssertionError("nothing is stored")),
    )
    MainWindow._on_scheduled_job_finished(fake, "j1", None, "cancelled: closed")
    [job] = fake._scheduler_jobs
    assert (job.running, job.last_ok, job.consecutive_failures) == (False, True, 0)
    assert job.last_run_at == datetime(2026, 1, 1)
    assert fake._scheduler_planned == {}
    assert finished == [("j1", None, "cancelled: closed")]
