"""The Transfers dock's overall bar says how many jobs failed, not "Done".

Review round 3: a copy of three files onto a full disk failed all three;
the overall bar said "Done" (0 %), the window's status bar nothing.
``TransferDock._update_overall`` showed "Done" whenever nothing ran any
more, however the jobs had ended.

Now a batch with failed or cancelled jobs ends on "N failed" /
"N cancelled" in the theme's error colour (the tooltip points at Retry
Failed), and keeps saying so until the next batch or Clear Finished;
"Done" only when every job of the batch ended well.
"""

from __future__ import annotations

import os
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PyQt6.QtCore import QObject, pyqtSignal
    from PyQt6.QtWidgets import QApplication
except ImportError:  # pragma: no cover
    QApplication = None


@unittest.skipIf(QApplication is None, "PyQt6 not installed")
class FailedBatchBarTest(unittest.TestCase):
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

            def clear_finished(self):
                self.jobs.clear()

        self.mgr = FakeManager()
        self.dock = TransferDock(self.mgr)
        self.addCleanup(self.dock.deleteLater)

    def add(self, n: int):
        jobs = []
        for _ in range(n):
            job = self.Job(total_bytes=100)
            job.status = self.Status.ACTIVE
            self.mgr.jobs[job.job_id] = job
            self.mgr.job_added.emit(job)
            jobs.append(job)
        self.settle()
        return jobs

    def end(self, job, status) -> None:
        job.status = status
        if status is self.Status.DONE:
            job.transferred_bytes = job.total_bytes
            self.mgr.job_finished.emit(job.job_id)
        else:
            self.mgr.job_error.emit(job.job_id, "No space left on device")
        self.settle()

    def settle(self) -> None:
        end = time.time() + 0.2
        while time.time() < end:
            self.app.processEvents()
            time.sleep(0.01)

    def bar(self):
        return self.dock._overall_progress

    def test_sad_a_batch_that_failed_entirely_says_so(self) -> None:
        for job in self.add(3):
            self.end(job, self.Status.ERROR)
        self.assertEqual(self.bar().format(), "3 failed")
        self.assertTrue(self.bar().property("endedBadly"))
        self.assertIn("color", self.bar().styleSheet())
        self.assertIn("Retry Failed", self.bar().toolTip())

    def test_happy_a_retry_that_succeeds_ends_on_done(self) -> None:
        [job] = self.add(1)
        self.end(job, self.Status.ERROR)
        self.assertEqual(self.bar().format(), "1 failed")
        job.retried = True
        [again] = self.add(1)
        self.end(again, self.Status.DONE)
        self.assertEqual(self.bar().format(), "Done")
        self.assertFalse(self.bar().property("endedBadly"))
        self.assertEqual(self.bar().styleSheet(), "")

    def test_edge_failed_and_cancelled_are_counted_and_stay_shown(self) -> None:
        a, b, c = self.add(3)
        self.end(a, self.Status.ERROR)
        self.end(b, self.Status.CANCELLED)
        self.end(c, self.Status.DONE)
        self.assertEqual(self.bar().format(), "1 failed, 1 cancelled")
        self.mgr.job_updated.emit(c.job_id)  # a late signal recomputes the bar
        self.settle()
        self.assertEqual(self.bar().format(), "1 failed, 1 cancelled")
        self.dock._clear_finished()
        self.assertFalse(self.bar().property("endedBadly"))


if __name__ == "__main__":
    unittest.main()
