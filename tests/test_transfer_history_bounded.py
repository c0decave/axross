"""The transfer list keeps a bounded history of finished jobs.

Before: every job stayed in ``TransferManager._jobs`` (and in the dock's
model) until "Clear Finished" - a copy of a million files kept a million
TransferJob objects, each with its backends, events and strings, and the
dock walked all of them on every progress burst. Now the oldest finished
jobs (done) are dropped once more than ``MAX_DONE_KEPT`` are kept; failed
and cancelled ones stay, they are what Retry Failed works on.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

PyQt6 = pytest.importorskip("PyQt6")
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import transfer_manager as TM  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.transfer_worker import TransferJob, TransferStatus  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _wait(cond, timeout=20.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.005)
    return False


@pytest.fixture
def manager():
    mgr = TM.TransferManager(max_parallel=1)
    yield mgr
    mgr.shutdown()


def _finished(mgr, n, status=TransferStatus.DONE, total=10):
    """*n* jobs registered and finished as the worker would report them."""
    jobs = []
    for i in range(n):
        job = TransferJob(source_path=f"/s/{i}", dest_path=f"/d/{i}", total_bytes=total,
                          filename=f"f{i}")
        with mock.patch.object(mgr._worker, "enqueue"):
            mgr._commit(job)
        mgr._on_job_started(job.job_id)
        if status == TransferStatus.DONE:
            job.transferred_bytes = total
            mgr._on_job_finished(job.job_id)
        else:
            job.status = status
            mgr._on_job_error(job.job_id, "boom")
        jobs.append(job)
    return jobs


# -- happy ------------------------------------------------------------------------------


def test_happy_the_oldest_done_jobs_go_beyond_the_limit(manager, monkeypatch):
    monkeypatch.setattr(TM, "MAX_DONE_KEPT", 5)
    monkeypatch.setattr(TM, "TRIM_SLACK", 2)
    trimmed: list[str] = []
    manager.jobs_trimmed.connect(trimmed.extend)
    jobs = _finished(manager, 20)
    kept = manager.all_jobs()
    assert 5 <= len(kept) <= 7
    assert kept == jobs[-len(kept):]  # the newest stay, in order
    assert set(trimmed) == {j.job_id for j in jobs[:-len(kept)]}
    assert all(manager.get_job(jid) is None for jid in trimmed)


def test_happy_under_the_limit_nothing_goes(manager):
    trimmed: list[str] = []
    manager.jobs_trimmed.connect(trimmed.extend)
    _finished(manager, 50)
    assert len(manager.all_jobs()) == 50 and trimmed == []


def test_happy_e2e_a_large_local_copy_keeps_a_bounded_list_and_copies_everything(
        tmp_path, monkeypatch):
    from ui.transfer_dock import TransferDock

    monkeypatch.setattr(TM, "MAX_DONE_KEPT", 10)
    monkeypatch.setattr(TM, "TRIM_SLACK", 5)
    src, dst = tmp_path / "src", tmp_path / "dst"
    src.mkdir()
    dst.mkdir()
    for i in range(60):
        (src / f"f{i:03d}.txt").write_text("x" * (i + 1))
    mgr = TM.TransferManager(max_parallel=2)
    dock = TransferDock(mgr)
    try:
        fs = LocalFS()
        done = []
        mgr.all_finished.connect(lambda: done.append(1))
        mgr.transfer_files(fs, fs, [str(p) for p in sorted(src.iterdir())], str(dst))
        assert _wait(lambda: done and not any(
            j.status in (TransferStatus.PENDING, TransferStatus.ACTIVE) for j in mgr.all_jobs()))
        APP.processEvents()
        assert sorted(p.name for p in dst.iterdir()) == sorted(p.name for p in src.iterdir())
        assert len(mgr.all_jobs()) <= 15
        assert dock._model.rowCount() == len(mgr.all_jobs())
        rows = [dock._model.get_job(r).job_id for r in range(dock._model.rowCount())]
        assert rows == [j.job_id for j in mgr.all_jobs()]
        dock._update_overall()
        assert dock._overall_progress.format() == "Done"
    finally:
        mgr.shutdown()
        dock.deleteLater()


# -- sad --------------------------------------------------------------------------------


def test_sad_failed_and_cancelled_jobs_are_never_dropped(manager, monkeypatch):
    monkeypatch.setattr(TM, "MAX_DONE_KEPT", 3)
    monkeypatch.setattr(TM, "TRIM_SLACK", 0)
    failed = _finished(manager, 4, status=TransferStatus.ERROR)
    cancelled = _finished(manager, 2, status=TransferStatus.CANCELLED)
    _finished(manager, 10)
    kept = {j.job_id for j in manager.all_jobs()}
    assert {j.job_id for j in failed + cancelled} <= kept
    assert sum(1 for j in manager.all_jobs() if j.status == TransferStatus.DONE) == 3


def test_sad_clear_finished_forgets_the_order_too(manager, monkeypatch):
    monkeypatch.setattr(TM, "MAX_DONE_KEPT", 3)
    monkeypatch.setattr(TM, "TRIM_SLACK", 0)
    _finished(manager, 3)
    manager.clear_finished()
    trimmed: list[str] = []
    manager.jobs_trimmed.connect(trimmed.extend)
    _finished(manager, 3)
    assert trimmed == [] and len(manager.all_jobs()) == 3


# -- edge -------------------------------------------------------------------------------


def test_edge_a_retried_done_job_is_not_trimmed_twice(manager, monkeypatch):
    """A job id leaves the order once, even when its status was rewritten."""
    monkeypatch.setattr(TM, "MAX_DONE_KEPT", 2)
    monkeypatch.setattr(TM, "TRIM_SLACK", 0)
    trimmed: list[str] = []
    manager.jobs_trimmed.connect(trimmed.extend)
    jobs = _finished(manager, 6)
    assert len(trimmed) == len(set(trimmed)) == 4
    assert manager.all_jobs() == jobs[-2:]


def test_edge_the_dock_drops_the_rows_and_the_bar_does_not_fall_back(manager, monkeypatch):
    """Regression for 0.14.142: finished jobs of the batch count in full -
    dropping them from the list must not drop them from the bar."""
    from ui.transfer_dock import TransferDock

    monkeypatch.setattr(TM, "MAX_DONE_KEPT", 4)
    monkeypatch.setattr(TM, "TRIM_SLACK", 0)
    dock = TransferDock(manager)
    try:
        running = TransferJob(source_path="/s/r", dest_path="/d/r", total_bytes=100, filename="r")
        with mock.patch.object(manager._worker, "enqueue"):
            manager._commit(running)
        manager._on_job_started(running.job_id)
        _finished(manager, 10, total=100)  # 1000 of 1100 bytes
        APP.processEvents()
        assert dock._model.rowCount() == len(manager.all_jobs()) == 5
        dock._update_overall()
        assert dock._overall_progress.value() == 90  # 1000 / 1100, not 400 / 500
    finally:
        dock.deleteLater()


def test_edge_a_manager_without_the_signal_still_works_with_the_dock():
    from PyQt6.QtCore import QObject, pyqtSignal

    from ui.transfer_dock import TransferDock

    class Old(QObject):
        job_added = pyqtSignal(object)
        job_updated = pyqtSignal(str)
        job_finished = pyqtSignal(str)
        job_error = pyqtSignal(str, str)

        def all_jobs(self):
            return []

    dock = TransferDock(Old())
    dock.deleteLater()


def test_edge_the_model_removes_scattered_rows():
    from models.transfer_model import TransferModel

    model = TransferModel()
    jobs = [TransferJob(source_path=f"/s/{i}", dest_path="/d", filename=f"f{i}") for i in range(8)]
    for job in jobs:
        model.add_job(job)
    removed = []
    model.rowsAboutToBeRemoved.connect(lambda _p, a, b: removed.append((a, b)))
    model.remove_jobs([jobs[i].job_id for i in (0, 1, 4, 7)] + ["unknown"])
    assert [model.get_job(r) for r in range(model.rowCount())] == [jobs[i] for i in (2, 3, 5, 6)]
    assert sorted(removed) == [(0, 1), (4, 4), (7, 7)]  # ranges, not a reset
    model.update_job(jobs[5].job_id)  # the index map follows the rows
    assert model._job_index[jobs[5].job_id] == 2


def test_edge_a_walk_that_fails_half_way_hands_back_what_it_queued(tmp_path):
    """Found by a review: a background walk that raised half way still
    queued what it had built, but told on_done there were no jobs - an
    undo said "nothing was queued" while part of it ran. on_done gets the
    queued jobs now, on_error the reason."""
    (tmp_path / "a.txt").write_text("a")
    dst = tmp_path / "dst"
    dst.mkdir()
    mgr = TM.TransferManager(max_parallel=1)
    real = mgr.transfer_files

    def half_way(source_backend, dest_backend, source_paths, dest_dir, *args, **kwargs):
        real(source_backend, dest_backend, [str(tmp_path / "a.txt")], dest_dir)
        raise OSError("connection lost")  # the link went while walking on

    mgr.transfer_files = half_way
    got: dict = {}
    try:
        fs = LocalFS()
        mgr.transfer_files_in_background(
            fs, fs, [str(tmp_path / "a.txt"), "/elsewhere"], str(dst),
            on_done=lambda jobs: got.setdefault("jobs", list(jobs)),
            on_error=lambda exc: got.setdefault("error", exc))
        assert _wait(lambda: "jobs" in got and "error" in got)
    finally:
        mgr.shutdown()
    assert str(got["error"]) == "connection lost"
    assert [j.filename for j in got["jobs"]] == ["a.txt"]
