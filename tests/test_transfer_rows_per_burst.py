"""The Transfers dock draws a burst of job updates once, not per update.

Measured on 2026-11-02 (scripts/pane_bench.py transfer_many: 2000 small
files): the queue sent 10 000 job updates, each one a dataChanged of its
row that the column fitter measured the row for - 1.4 s of the 2 s GUI
time. The dock collects the updated jobs and gives their rows to the model
together, at most every 50 ms, as one dataChanged per run of adjacent rows
(GUI time -23 to -33 %, the longest stall 290-310 ms instead of 360-500 ms
in paired runs).
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.transfer_manager import TransferManager  # noqa: E402
from core.transfer_worker import TransferDirection, TransferJob, TransferStatus  # noqa: E402
from models.transfer_model import TransferModel  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _job(n: int) -> TransferJob:
    job = TransferJob(source_path=f"/s/{n}", dest_path=f"/d/{n}",
                      direction=TransferDirection.DOWNLOAD, total_bytes=1, filename=f"f{n}")
    job.status = TransferStatus.PENDING
    return job


def _changes(model) -> list:
    seen: list = []
    model.dataChanged.connect(lambda tl, br, *_: seen.append((tl.row(), br.row())))
    return seen


def test_happy_one_change_per_run_of_adjacent_rows():
    model = TransferModel()
    jobs = [_job(n) for n in range(10)]
    for job in jobs:
        model.add_job(job)
    seen = _changes(model)
    model.update_jobs([jobs[n].job_id for n in (7, 1, 2, 3, 8, 5)] + ["gone"])
    assert seen == [(1, 3), (5, 5), (7, 8)]


@pytest.fixture
def dock():
    from ui.transfer_dock import TransferDock

    manager = TransferManager()
    d = TransferDock(manager)
    yield d
    manager.shutdown()
    d.deleteLater()


def test_happy_a_burst_of_updates_is_drawn_once(dock):
    jobs = [_job(n) for n in range(200)]
    for job in jobs:
        dock._on_job_added(job)
    seen = _changes(dock._model)
    activity: list = []
    dock.activity.connect(lambda: activity.append(1))
    for _round in range(5):  # pending, active, progress, progress, done
        for job in jobs:
            job.status = TransferStatus.ACTIVE
            dock._on_job_updated(job.job_id)
    assert seen == []  # nothing yet: collected
    dock._flush_updated_rows()
    assert seen == [(0, 199)] and activity == [1]


def test_happy_the_rows_go_out_by_themselves(dock):
    job = _job(1)
    dock._on_job_added(job)
    seen = _changes(dock._model)
    dock._on_job_updated(job.job_id)
    assert dock._rows_timer.isActive()
    end = time.monotonic() + 2
    while not seen and time.monotonic() < end:
        APP.processEvents()
    assert seen == [(0, 0)]


def test_edge_an_update_of_a_job_removed_meanwhile_draws_nothing(dock):
    job = _job(1)
    dock._on_job_added(job)
    dock._on_job_updated(job.job_id)
    dock._model.remove_jobs([job.job_id])
    seen = _changes(dock._model)
    dock._flush_updated_rows()
    assert seen == []
