#!/usr/bin/env python3
"""The scheduler window and what it tells the user.

A schedule the user cannot inspect is a schedule they stop trusting.
The list therefore always shows when each job last ran and whether it
worked — a job silently disabled after ten failures must be visible as
disabled, with the reason, rather than just quietly stopping.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.scheduler import Job, JobStore  # noqa: E402
from ui.scheduler_dialog import SchedulerDialog, format_interval, job_row  # noqa: E402

APP = QApplication.instance() or QApplication([])

T0 = datetime(2026, 6, 1, 12, 0, 0)


def _job(**kw) -> Job:
    kw.setdefault("job_id", "j1")
    kw.setdefault("name", "nightly mirror")
    kw.setdefault("kind", "script")
    kw.setdefault("target", "mirror.py")
    kw.setdefault("interval_s", 3600)
    return Job(**kw)


# --------------------------------------------------------------------------
# format_interval
# --------------------------------------------------------------------------


def test_happy_intervals_read_as_english():
    assert format_interval(60) == "every 1 min"
    assert format_interval(3600) == "every 1 h"
    assert format_interval(86400) == "every 1 day"


def test_edge_odd_intervals_fall_back_to_the_largest_whole_unit():
    assert "min" in format_interval(90)
    assert "h" in format_interval(7200)


def test_edge_seconds_survive_as_seconds():
    assert format_interval(30) == "every 30 s"


# --------------------------------------------------------------------------
# job_row
# --------------------------------------------------------------------------


def test_happy_a_never_run_job_says_so_rather_than_showing_a_blank():
    cells = job_row(_job(last_run_at=None))
    assert cells["Last run"] == "never"
    assert cells["Status"] == "waiting"


def test_happy_a_successful_run_is_shown_with_its_detail():
    cells = job_row(_job(last_run_at=T0, last_ok=True, last_detail="12 files"))
    assert "2026-06-01" in cells["Last run"]
    assert cells["Status"] == "ok"
    assert cells["Detail"] == "12 files"


def test_sad_a_failed_run_is_shown_as_failed():
    cells = job_row(_job(last_run_at=T0, last_ok=False, last_detail="host down"))
    assert cells["Status"] == "failed"
    assert cells["Detail"] == "host down"


def test_sad_a_disabled_job_is_visibly_disabled_not_just_absent():
    """A job that disabled itself after repeated failure has to be
    visible as such — otherwise it looks like it is still scheduled."""
    cells = job_row(_job(enabled=False, last_ok=False, last_detail="disabled after 10"))
    assert cells["Status"] == "disabled"
    assert "disabled" in cells["Detail"]


def test_edge_a_running_job_reports_running():
    assert job_row(_job(running=True))["Status"] == "running"


# --------------------------------------------------------------------------
# The dialog
# --------------------------------------------------------------------------


@pytest.fixture()
def dialog(tmp_path):
    made: list = []

    def factory(jobs=()):
        store = JobStore(tmp_path / "jobs.json")
        store.save(list(jobs))
        dlg = SchedulerDialog(store)
        dlg.show()
        APP.processEvents()
        made.append(dlg)
        return dlg

    yield factory
    for dlg in made:
        dlg.close()
        dlg.deleteLater()
    APP.processEvents()


def test_happy_dialog_lists_stored_jobs(dialog):
    dlg = dialog([_job(job_id="a", name="one"), _job(job_id="b", name="two")])
    assert dlg.displayed_names() == ["one", "two"]


def test_happy_removing_a_job_persists(dialog):
    dlg = dialog([_job(job_id="a", name="one"), _job(job_id="b", name="two")])
    dlg.remove_job("a")
    assert dlg.displayed_names() == ["two"]
    assert [j.job_id for j in dlg.store.load()] == ["b"]


def test_happy_toggling_enabled_persists(dialog):
    dlg = dialog([_job(job_id="a")])
    dlg.set_enabled("a", False)
    assert dlg.store.load()[0].enabled is False


def test_happy_adding_a_job_persists(dialog):
    dlg = dialog([])
    dlg.add_job(name="hourly", kind="script", target="du.py", interval_s=3600)
    assert dlg.displayed_names() == ["hourly"]
    assert dlg.store.load()[0].interval_s == 3600


def test_sad_adding_a_job_with_a_zero_interval_is_refused(dialog):
    dlg = dialog([])
    with pytest.raises(ValueError):
        dlg.add_job(name="bad", kind="script", target="x.py", interval_s=0)
    assert dlg.displayed_names() == []


def test_edge_empty_scheduler_says_so(dialog):
    assert "no jobs" in dialog([]).status_text().lower()


def test_edge_dialog_survives_a_corrupt_store(tmp_path):
    path = tmp_path / "jobs.json"
    path.write_text("{{{ not json")
    dlg = SchedulerDialog(JobStore(path))
    dlg.show()
    APP.processEvents()
    try:
        assert dlg.displayed_names() == []
    finally:
        dlg.close()
        dlg.deleteLater()
        APP.processEvents()


def test_happy_next_run_column_shows_when_the_job_is_next_due(dialog):
    dlg = dialog([_job(last_run_at=datetime.now() - timedelta(hours=2))])
    assert dlg.displayed_rows()[0]["Next run"]
