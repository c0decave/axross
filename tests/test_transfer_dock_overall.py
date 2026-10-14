"""Transfer dock: the overall progress is recomputed once per burst of job
signals, not once per signal.

Measured before: every job_added / job_updated walked all jobs twice; a
10 000-file copy spent ~14 s of GUI time in ``_update_overall`` while
enqueueing alone.
"""

from __future__ import annotations

import os
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PyQt6.QtCore import QObject, pyqtSignal
    from PyQt6.QtWidgets import QApplication
except ImportError:  # pragma: no cover
    QApplication = None


def _wait(app, cond, timeout=3.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        app.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return False


@unittest.skipIf(QApplication is None, "PyQt6 not installed")
class OverallProgressTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from core.transfer_worker import TransferJob, TransferStatus
        from ui.transfer_dock import TransferDock

        self.Job, self.Status = TransferJob, TransferStatus

        class FakeManager(QObject):
            job_added = pyqtSignal(object)
            job_updated = pyqtSignal(str)
            job_finished = pyqtSignal(str)
            job_error = pyqtSignal(str, str)

            def __init__(self) -> None:
                super().__init__()
                self.jobs = {}

            def all_jobs(self):
                return list(self.jobs.values())

        self.mgr = FakeManager()
        self.dock = TransferDock(self.mgr)
        self.addCleanup(self.dock.deleteLater)

    def add(self, n: int, *, total=100, done=0, status=None):
        jobs = []
        for _ in range(n):
            job = self.Job(total_bytes=total, transferred_bytes=done)
            job.status = status or self.Status.ACTIVE
            self.mgr.jobs[job.job_id] = job
            self.mgr.job_added.emit(job)
            jobs.append(job)
        return jobs

    def bar(self):
        return self.dock._overall_progress

    def test_happy_progress_matches_the_jobs(self) -> None:
        jobs = self.add(4)
        jobs[0].transferred_bytes = 100
        jobs[1].transferred_bytes = 100
        self.mgr.job_updated.emit(jobs[1].job_id)
        self.assertTrue(_wait(self.app, lambda: self.bar().value() == 50))
        self.assertEqual(self.bar().format(), "%p%")

    def test_happy_all_finished_shows_done(self) -> None:
        jobs = self.add(3)
        for j in jobs:
            j.status = self.Status.DONE
            self.mgr.job_finished.emit(j.job_id)
        self.assertTrue(_wait(self.app, lambda: self.bar().format() == "Done"))
        self.assertEqual(self.bar().value(), 0)

    def test_sad_an_error_still_updates(self) -> None:
        (job,) = self.add(1)
        job.status = self.Status.ERROR
        self.mgr.job_error.emit(job.job_id, "boom")
        self.assertTrue(_wait(self.app, lambda: self.bar().format() == "Done"))

    def test_edge_a_burst_of_signals_recomputes_once(self) -> None:
        # _update_overall walks all_jobs(); count those walks.
        walks = []
        real = self.mgr.all_jobs
        with mock.patch.object(self.mgr, "all_jobs", side_effect=lambda: walks.append(1) or real()):
            self.add(500)
            self.assertEqual(len(walks), 0)  # not once per signal
            self.assertTrue(_wait(self.app, lambda: len(walks) >= 1))
            time_after = len(walks)
        self.assertEqual(time_after, 1)

    def test_edge_no_jobs_is_zero(self) -> None:
        self.dock._update_overall()
        self.assertEqual((self.bar().value(), self.bar().format()), (0, "%p%"))


if __name__ == "__main__":
    unittest.main()
