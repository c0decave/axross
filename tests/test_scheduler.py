#!/usr/bin/env python3
"""Recurring jobs.

axross has scripts, profiles and a transfer engine, but nothing that
runs any of it on a timer — "mirror this nightly" meant an external
cron entry that knows none of the app's connections.

The scheduling logic is deliberately separate from anything that
executes: deciding WHEN a job is due is pure arithmetic over stored
state, and keeping it pure is what makes "did it skip a run?" a
question with a testable answer rather than an observation you wait a
day for.

Two behaviours carry the weight:

* A job that is already running is not started again. Overlapping runs
  of a mirror would have two writers on one destination.
* A missed window does not queue up. A laptop closed over the weekend
  must not wake to forty-eight backlogged hourly runs; it runs once and
  carries on.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.scheduler import (  # noqa: E402
    Job,
    JobStore,
    due_jobs,
    next_run_at,
    record_result,
)

T0 = datetime(2026, 6, 1, 12, 0, 0)


def _job(**kw) -> Job:
    kw.setdefault("job_id", "j1")
    kw.setdefault("name", "nightly mirror")
    kw.setdefault("kind", "script")
    kw.setdefault("target", "mirror.py")
    kw.setdefault("interval_s", 3600)
    return Job(**kw)


# --------------------------------------------------------------------------
# next_run_at
# --------------------------------------------------------------------------


def test_happy_first_run_is_due_immediately():
    """A job that has never run should not wait a full interval before
    doing anything — the user just created it."""
    assert next_run_at(_job(last_run_at=None), now=T0) == T0


def test_happy_next_run_is_one_interval_after_the_last():
    job = _job(last_run_at=T0, interval_s=3600)
    assert next_run_at(job, now=T0) == T0 + timedelta(seconds=3600)


def test_edge_a_disabled_job_is_never_due():
    assert next_run_at(_job(enabled=False, last_run_at=None), now=T0) is None


def test_edge_a_zero_interval_is_rejected_rather_than_spinning():
    """An interval of zero would make the job due on every tick — a
    tight loop wearing the disk, not a schedule."""
    with pytest.raises(ValueError):
        _job(interval_s=0)


def test_edge_a_negative_interval_is_rejected():
    with pytest.raises(ValueError):
        _job(interval_s=-60)


# --------------------------------------------------------------------------
# due_jobs
# --------------------------------------------------------------------------


def test_happy_job_becomes_due_after_its_interval():
    job = _job(last_run_at=T0, interval_s=60)
    assert due_jobs([job], now=T0 + timedelta(seconds=59)) == []
    assert due_jobs([job], now=T0 + timedelta(seconds=61)) == [job]


def test_sad_a_running_job_is_not_started_again():
    """Two concurrent runs of a mirror means two writers on one
    destination."""
    job = _job(last_run_at=T0 - timedelta(hours=5), running=True)
    assert due_jobs([job], now=T0) == []


def test_edge_a_long_outage_produces_one_run_not_a_backlog():
    """A laptop closed over the weekend must not wake to 48 queued
    hourly runs."""
    job = _job(last_run_at=T0 - timedelta(days=2), interval_s=3600)
    due = due_jobs([job], now=T0)
    assert due == [job]


def test_edge_disabled_jobs_are_skipped_even_when_overdue():
    job = _job(last_run_at=T0 - timedelta(days=1), enabled=False)
    assert due_jobs([job], now=T0) == []


def test_edge_due_jobs_on_an_empty_list():
    assert due_jobs([], now=T0) == []


# --------------------------------------------------------------------------
# record_result
# --------------------------------------------------------------------------


def test_happy_a_successful_run_moves_the_clock_forward():
    job = record_result(_job(last_run_at=None), ok=True, at=T0, detail="12 files")
    assert job.last_run_at == T0
    assert job.last_ok is True
    assert job.last_detail == "12 files"
    assert job.running is False


def test_happy_a_failed_run_still_moves_the_clock():
    """Otherwise a permanently failing job retries as fast as the tick
    allows, hammering a host that is already unhappy."""
    job = record_result(_job(last_run_at=None), ok=False, at=T0, detail="host down")
    assert job.last_run_at == T0
    assert job.last_ok is False
    assert job.consecutive_failures == 1


def test_happy_failures_accumulate_and_reset_on_success():
    job = _job(last_run_at=None)
    for _ in range(3):
        job = record_result(job, ok=False, at=T0, detail="nope")
    assert job.consecutive_failures == 3
    job = record_result(job, ok=True, at=T0, detail="fine")
    assert job.consecutive_failures == 0


def test_edge_a_job_that_keeps_failing_is_disabled_rather_than_looping_forever():
    """A schedule that fails every time is not a schedule, it is a
    retry loop against a host that has already said no."""
    job = _job(last_run_at=None)
    for _ in range(10):
        job = record_result(job, ok=False, at=T0, detail="nope")
    assert job.enabled is False
    assert "fail" in job.last_detail.lower()


# --------------------------------------------------------------------------
# JobStore — persistence
# --------------------------------------------------------------------------


def test_happy_jobs_round_trip_through_the_store(tmp_path):
    store = JobStore(tmp_path / "jobs.json")
    store.save([_job(job_id="a"), _job(job_id="b", name="second")])
    loaded = store.load()
    assert [j.job_id for j in loaded] == ["a", "b"]
    assert loaded[1].name == "second"


def test_happy_last_run_survives_a_round_trip(tmp_path):
    store = JobStore(tmp_path / "jobs.json")
    store.save([_job(last_run_at=T0, last_ok=True, last_detail="ok")])
    assert store.load()[0].last_run_at == T0


def test_edge_loading_a_missing_file_yields_no_jobs(tmp_path):
    assert JobStore(tmp_path / "nope.json").load() == []


def test_sad_a_corrupt_store_does_not_take_the_app_down(tmp_path):
    """This file sits in the user's state directory and is written by a
    running app; a truncated write must degrade to "no jobs", not to a
    crash at startup."""
    path = tmp_path / "jobs.json"
    path.write_text("{not json at all")
    assert JobStore(path).load() == []


def test_edge_a_row_with_an_impossible_interval_is_dropped_not_fatal(tmp_path):
    path = tmp_path / "jobs.json"
    path.write_text('[{"job_id": "bad", "name": "x", "kind": "script", '
                    '"target": "y", "interval_s": 0}]')
    assert JobStore(path).load() == []


def test_happy_running_flag_is_not_persisted(tmp_path):
    """It describes this process, not the schedule. Persisting it would
    leave a job permanently "running" after a crash, and it would never
    start again."""
    store = JobStore(tmp_path / "jobs.json")
    store.save([_job(running=True)])
    assert store.load()[0].running is False


# --------------------------------------------------------------------------
# Running a job must not block the caller
#
# The first wiring called run_script straight from the timer slot, which
# is the GUI thread. A nightly mirror over SFTP would freeze the whole
# window for as long as it took — the one thing a background schedule
# must never do.
# --------------------------------------------------------------------------


def test_happy_runner_reports_success_through_the_callback():
    from core.scheduler import run_job

    done: list = []
    run_job(
        _job(),
        runner=lambda job: "12 files",
        on_finished=lambda job, ok, detail: done.append((job.job_id, ok, detail)),
    )
    assert done == [("j1", True, "12 files")]


def test_sad_a_raising_job_is_reported_not_propagated():
    """A scheduled job that throws must not take down whatever invoked
    the tick."""
    from core.scheduler import run_job

    done: list = []

    def _boom(job):
        raise OSError("host down")

    run_job(_job(), runner=_boom, on_finished=lambda j, ok, d: done.append((ok, d)))
    assert done == [(False, "host down")]


def test_edge_runner_returning_nothing_still_counts_as_success():
    from core.scheduler import run_job

    done: list = []
    run_job(_job(), runner=lambda job: None, on_finished=lambda j, ok, d: done.append(ok))
    assert done == [True]
