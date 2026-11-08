"""A big walk's jobs are registered on the GUI thread in slices.

Measured before (5 000 local 4 KiB files, Transfers dock shown): the walk's
jobs were registered in one call on the GUI thread - a job_added, a dock
row and a queue entry each - and the window stood still for 0.4 s. Now
_commit_walk registers about WALK_COMMIT_SLICE_S worth per event-loop turn.

What must not change: the jobs are registered (and run) in walk order,
the walk counts as running until its last job is in (busy, unfinished),
all_finished comes once, no job starts before the last slice is in (an
on_done still sees every job before any has ended), and Cancel
All between two slices queues nothing more and closes the journal entries
of what it did not queue.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import transfer_manager as TM  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.transfer_worker import TransferDirection, TransferStatus  # noqa: E402

APP = QApplication.instance() or QApplication([])
FILES = 300


def _tree(tmp_path) -> Path:
    src = tmp_path / "src" / "many"
    src.mkdir(parents=True)
    for i in range(FILES):
        (src / f"f{i:04d}.bin").write_bytes(b"x" * 16)
    (tmp_path / "out").mkdir()
    return src


def _pump(until, timeout=60.0):
    deadline = time.monotonic() + timeout
    while not until() and time.monotonic() < deadline:
        APP.processEvents()
        time.sleep(0.002)
    assert until(), "timed out"


@pytest.fixture
def manager(monkeypatch):
    # Every 16 jobs is a slice.
    monkeypatch.setattr(TM, "WALK_COMMIT_SLICE_S", 0.0)
    tm = TM.TransferManager(max_parallel=1)
    yield tm
    tm.shutdown()


def test_happy_jobs_come_in_walk_order_and_all_finished_once(tmp_path, manager):
    src = _tree(tmp_path)
    added, finished, done = [], [], []
    manager.job_added.connect(lambda job: added.append(job.filename))
    manager.all_finished.connect(lambda: finished.append(len(added)))
    manager.transfer_files_in_background(LocalFS(), LocalFS(), [str(src)],
                                         str(tmp_path / "out"), TransferDirection.UPLOAD,
                                         on_done=done.append)
    _pump(lambda: done and manager.unfinished() == 0)
    assert [len(jobs) for jobs in done] == [FILES]
    assert added == [job.filename for job in done[0]]  # the walk's order
    assert finished == [FILES]  # once, with every job registered
    assert len(list((tmp_path / "out" / "many").iterdir())) == FILES


def test_happy_the_walk_counts_as_running_until_its_last_slice(tmp_path, manager):
    src = _tree(tmp_path)
    seen = []

    def on_added(_job):
        if len(seen) < FILES:
            seen.append((manager.busy(manager._walks[0][0]) if manager._walks else False,
                         manager.unfinished() > 0))

    manager.job_added.connect(on_added)
    done = []
    manager.transfer_files_in_background(LocalFS(), LocalFS(), [str(src)],
                                         str(tmp_path / "out"), TransferDirection.UPLOAD,
                                         on_done=done.append)
    _pump(lambda: done)
    assert len(seen) == FILES
    assert all(busy and unfinished for busy, unfinished in seen)
    _pump(lambda: manager.unfinished() == 0)


def test_sad_cancel_all_between_slices_queues_no_more(tmp_path, manager):
    src = _tree(tmp_path)
    added, done = [], []

    def on_added(job):
        added.append(job)
        if len(added) == 16:
            manager.cancel_all()

    manager.job_added.connect(on_added)
    manager.transfer_files_in_background(LocalFS(), LocalFS(), [str(src)],
                                         str(tmp_path / "out"), TransferDirection.UPLOAD,
                                         on_done=done.append)
    _pump(lambda: done and manager.unfinished() == 0)
    assert len(added) == 16
    assert done == [[]]
    assert all(j.status in (TransferStatus.CANCELLED, TransferStatus.DONE) for j in added)


def test_edge_no_job_runs_before_the_walk_is_registered_and_on_done_ran(tmp_path, manager):
    """The workers get the jobs only with the last slice: a caller's on_done
    (main_window tracks the tags of moved files there) still sees every job
    before any has started or ended - as when they were registered at once."""
    src = _tree(tmp_path)
    seen_at_done = []
    started = []
    manager.job_updated.connect(lambda job_id: started.append(job_id))
    slices = []
    real = manager._commit_walk

    def spy(payload, start):
        slices.append(start)
        return real(payload, start)

    manager._commit_walk = spy

    def on_done(jobs):
        seen_at_done.append((len(jobs), len(started),
                             {j.status for j in jobs}))

    manager.transfer_files_in_background(LocalFS(), LocalFS(), [str(src)],
                                         str(tmp_path / "out"), TransferDirection.UPLOAD,
                                         on_done=on_done)
    _pump(lambda: seen_at_done and manager.unfinished() == 0)
    assert len(slices) > 2  # it did take several turns
    assert seen_at_done == [(FILES, 0, {TransferStatus.PENDING})]
