"""A hand-edited jobs.json never stops the start, the minute tick or the
Scheduler window, and a value of the wrong kind never runs a job.

The store is a JSON file in the user's state directory; ``JobStore.load``
promises "every read path degrades to no jobs rather than raising". Found
by a mutation sweep of every hand-editable store (each value replaced by
null, bools, huge and non-finite numbers, strings, lists, objects):

- ``"interval_s": Infinity`` (or ``1e999``) raised OverflowError out of
  ``load()`` - the main window loads the store while it is built, so
  axross did not start;
- ``"consecutive_failures": Infinity`` the same;
- a finite interval past the calendar (``10**15`` seconds) loaded, and then
  ``next_run_at`` raised OverflowError: the main window's tick every minute
  and the Scheduler window (its "Next run" column);
- ``"last_run_at": "...Z"`` (a time zone, as ISO 8601 is often written)
  made ``due_jobs`` compare it with the naive local time axross uses:
  TypeError on every tick;
- ``"enabled": "false"`` read as enabled (``bool("false")``) - a job the
  user switched off ran.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.scheduler import Job, JobStore, due_jobs, next_run_at  # noqa: E402

NOW = datetime(2026, 6, 1, 12, 0, 0)


def _row(**kw) -> dict:
    row = {"job_id": "j1", "name": "nightly", "kind": "script", "target": "m.py",
           "interval_s": 3600, "enabled": True, "last_run_at": "2026-06-01T10:00:00",
           "last_ok": True, "last_detail": "", "consecutive_failures": 0, "details": {}}
    row.update(kw)
    return row


def _store(tmp_path: Path, *rows: dict) -> JobStore:
    path = tmp_path / "jobs.json"
    # allow_nan: Infinity is what a hand edit (or json.dumps of inf) writes
    path.write_text(json.dumps(list(rows), allow_nan=True), encoding="utf-8")
    return JobStore(path)


# -- happy ----------------------------------------------------------------------------------

def test_happy_a_valid_row_still_loads_and_is_due_when_its_interval_passed(tmp_path):
    jobs = _store(tmp_path, _row()).load()
    assert [j.job_id for j in jobs] == ["j1"]
    assert jobs[0].enabled is True
    assert [j.job_id for j in due_jobs(jobs, now=NOW)] == ["j1"]


def test_happy_a_disabled_row_stays_disabled(tmp_path):
    jobs = _store(tmp_path, _row(enabled=False)).load()
    assert jobs[0].enabled is False
    assert due_jobs(jobs, now=NOW) == []


# -- sad ------------------------------------------------------------------------------------

@pytest.mark.parametrize("field", ["interval_s", "consecutive_failures"])
@pytest.mark.parametrize("value", [float("inf"), -float("inf"), float("nan")])
def test_sad_a_non_finite_number_drops_only_its_row(tmp_path, field, value):
    store = _store(tmp_path, _row(**{field: value}), _row(job_id="j2"))
    assert [j.job_id for j in store.load()] == ["j2"]


@pytest.mark.parametrize("value", ["false", "no", "0", 1, [], {"on": True}, None])
def test_sad_an_enabled_that_is_not_a_bool_never_runs_the_job(tmp_path, value):
    jobs = _store(tmp_path, _row(enabled=value)).load()
    assert [j.job_id for j in jobs] == ["j1"]
    assert jobs[0].enabled is False
    assert due_jobs(jobs, now=NOW) == []


def test_sad_a_missing_enabled_keeps_the_old_default_on(tmp_path):
    row = _row()
    del row["enabled"]
    jobs = _store(tmp_path, row).load()
    assert jobs[0].enabled is True


# -- edge -----------------------------------------------------------------------------------

@pytest.mark.parametrize("interval", [10**15, 2**63, 10**30])
def test_edge_an_interval_past_the_calendar_is_never_due_and_never_raises(tmp_path, interval):
    jobs = _store(tmp_path, _row(interval_s=interval)).load()
    assert [j.job_id for j in jobs] == ["j1"]
    assert next_run_at(jobs[0], now=NOW) is None
    assert due_jobs(jobs, now=NOW) == []


@pytest.mark.parametrize("stamp", ["2026-06-01T10:00:00Z", "2026-06-01T10:00:00+02:00",
                                   "2026-06-01T08:00:00-05:00"])
def test_edge_a_last_run_with_a_time_zone_is_compared_in_local_time(tmp_path, stamp):
    jobs = _store(tmp_path, _row(last_run_at=stamp)).load()
    assert jobs[0].last_run_at.tzinfo is None
    expected = datetime.fromisoformat(stamp).astimezone().replace(tzinfo=None)
    assert jobs[0].last_run_at == expected
    when = next_run_at(jobs[0], now=NOW)
    assert when == expected + timedelta(hours=1)
    due_jobs(jobs, now=NOW)  # comparable with the naive local "now"


def test_edge_a_job_that_last_ran_at_the_end_of_the_calendar_is_not_due():
    job = Job("j", "n", "script", "t", 60, last_run_at=datetime.max)
    assert next_run_at(job, now=NOW) is None


def test_edge_a_save_after_a_dropped_row_round_trips_the_rest(tmp_path):
    store = _store(tmp_path, _row(interval_s=float("inf")), _row(job_id="j2"))
    store.save(store.load())
    assert [j.job_id for j in store.load()] == ["j2"]


# -- e2e ------------------------------------------------------------------------------------

def test_e2e_the_scheduler_window_opens_on_a_hand_edited_store(tmp_path):
    pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
    from PyQt6.QtWidgets import QApplication

    from ui.scheduler_dialog import SchedulerDialog

    app = QApplication.instance() or QApplication([])
    store = _store(tmp_path,
                   _row(job_id="far", name="far", interval_s=10**15),
                   _row(job_id="inf", name="inf", interval_s=float("inf")),
                   _row(job_id="tz", name="tz", last_run_at="2026-06-01T10:00:00Z"),
                   _row(job_id="off", name="off", enabled="false"))
    dlg = SchedulerDialog(store)
    try:
        dlg.show()
        app.processEvents()
        names = [dlg._table.item(r, 0).text() for r in range(dlg._table.rowCount())]
        assert names == ["far", "tz", "off"]
        status = {dlg._table.item(r, 0).text(): dlg._table.item(r, 4).text()
                  for r in range(dlg._table.rowCount())}
        assert status["off"] == "disabled"
    finally:
        dlg.close()
        dlg.deleteLater()
        app.processEvents()
