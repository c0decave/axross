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

    def test_sad_a_finished_job_does_not_send_the_bar_back(self) -> None:
        """Feedback: check that the % at the bottom is right. It counted
        only running and waiting jobs: with three equal files, the first
        one finishing took the bar from 33 % back to 0 %."""
        jobs = self.add(3, status=self.Status.PENDING)
        jobs[0].status = self.Status.ACTIVE
        jobs[0].transferred_bytes = 100
        self.dock._update_overall()
        self.assertEqual(self.bar().value(), 33)
        jobs[0].status = self.Status.DONE
        jobs[1].status = self.Status.ACTIVE
        self.dock._update_overall()
        self.assertEqual(self.bar().value(), 33)
        jobs[1].transferred_bytes = 50
        self.dock._update_overall()
        self.assertEqual(self.bar().value(), 50)

    def test_edge_a_failed_job_counts_what_it_moved(self) -> None:
        jobs = self.add(2, status=self.Status.ACTIVE)
        jobs[0].status = self.Status.ERROR
        jobs[0].transferred_bytes = 0
        jobs[1].transferred_bytes = 50
        self.dock._update_overall()
        self.assertEqual(self.bar().value(), 50)  # 50 of the 100 still to come

    def test_edge_a_new_batch_starts_at_zero(self) -> None:
        (old,) = self.add(1)
        old.status = self.Status.DONE
        self.dock._update_overall()
        self.assertEqual(self.bar().format(), "Done")
        (new,) = self.add(1)
        self.dock._update_overall()
        self.assertEqual(self.bar().value(), 0)  # the old job is not this batch

    def test_happy_the_bar_says_how_long_is_left(self) -> None:
        jobs = self.add(2, total=1000)
        jobs[0].transferred_bytes = 500
        jobs[0].speed = 100.0
        jobs[1].speed = 50.0
        self.dock._update_overall()
        # 1500 bytes left at 150 B/s
        self.assertEqual(self.bar().format(), "%p% · 10s left")

    def test_happy_show_current_selects_the_running_job(self) -> None:
        jobs = self.add(30, status=self.Status.DONE)
        jobs[25].status = self.Status.ACTIVE
        self.assertTrue(self.dock.show_current())
        rows = self.dock._table.selectionModel().selectedRows()
        self.assertEqual([r.row() for r in rows], [25])
        for j in jobs:
            j.status = self.Status.DONE
        self.assertFalse(self.dock.show_current())

    def test_happy_a_click_on_the_overall_bar_shows_the_running_job(self) -> None:
        from PyQt6.QtCore import Qt
        from PyQt6.QtTest import QTest

        jobs = self.add(30, status=self.Status.DONE)
        jobs[12].status = self.Status.ACTIVE
        QTest.mouseClick(self.bar(), Qt.MouseButton.LeftButton)
        rows = self.dock._table.selectionModel().selectedRows()
        self.assertEqual([r.row() for r in rows], [12])
        self.assertIn("show the transfer running now", self.bar().toolTip())

    def test_edge_the_bottom_row_is_no_wider_for_it(self) -> None:
        """No extra button: the dock's minimum width is the bottom row's,
        and a wider dock reaches under the right dock column."""
        from PyQt6.QtWidgets import QPushButton

        labels = sorted(b.text() for b in self.dock.findChildren(QPushButton))
        self.assertEqual(labels, ["Cancel All", "Clear Finished", "Retry Failed"])

    def test_edge_the_eta_tooltip_keeps_the_click_hint(self) -> None:
        jobs = self.add(1, total=1000)
        jobs[0].speed = 100.0
        self.dock._update_overall()
        tip = self.bar().toolTip()
        self.assertIn("left at the current speed", tip)
        self.assertIn("show the transfer running now", tip)


if __name__ == "__main__":
    unittest.main()
