"""A failed transfer is retried once, not once per press of Retry Failed.

Measured before: ``retry_job`` queued a new job and left the failed one
in the list with its ERROR status. "Retry Failed" walks every job in
ERROR or CANCELLED, so a second press retried the same failure again -
the file was copied twice (overwrite mode), or the second copy failed on
the first one's file ("already exists"), and a second press on a failed
move queued a move of a source the first retry had already removed.

Now the failed job remembers that it was retried and ``retry_job``
refuses it a second time; its retry, if that fails too, can be retried.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.local_fs import LocalFS  # noqa: E402
from core.transfer_worker import TransferStatus  # noqa: E402


class _FailWrites(LocalFS):
    """The first *fails* writes raise EIO; counts every open_write."""

    def __init__(self, fails: int) -> None:
        self.fails = fails
        self.writes = 0

    def open_write(self, path, append=False):
        self.writes += 1
        if self.fails:
            self.fails -= 1
            raise OSError(5, "I/O error", path)
        return super().open_write(path, append)


class RetryOnceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from core.transfer_manager import TransferManager

        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.src = self.tmp / "src"
        self.dst = self.tmp / "dst"
        self.src.mkdir()
        self.dst.mkdir()
        (self.src / "x.txt").write_bytes(b"data")
        self.mgr = TransferManager()
        self.addCleanup(self.mgr.shutdown)

    def wait(self, jobs) -> None:
        end = time.monotonic() + 10
        while any(j.status in (TransferStatus.PENDING, TransferStatus.ACTIVE) for j in jobs):
            self.app.processEvents()
            if time.monotonic() > end:
                self.fail(f"jobs did not finish: {[j.status for j in jobs]}")
            time.sleep(0.005)
        for _ in range(5):
            self.app.processEvents()

    def _failed_copy(self, dest_fs):
        [job] = self.mgr.transfer_files(LocalFS(), dest_fs, [str(self.src / "x.txt")],
                                        str(self.dst))
        self.wait([job])
        self.assertEqual(job.status, TransferStatus.ERROR)
        return job

    def test_happy_retry_failed_pressed_twice_copies_once(self) -> None:
        """e2e: the real dock's Retry Failed button, pressed twice."""
        from PyQt6.QtCore import Qt
        from PyQt6.QtTest import QTest

        from ui.transfer_dock import TransferDock

        dock = TransferDock(self.mgr)
        self.addCleanup(dock.deleteLater)
        dest_fs = _FailWrites(fails=1)
        self._failed_copy(dest_fs)
        QTest.mouseClick(dock._btn_retry, Qt.MouseButton.LeftButton)
        self.wait(self.mgr.all_jobs())
        QTest.mouseClick(dock._btn_retry, Qt.MouseButton.LeftButton)
        self.wait(self.mgr.all_jobs())
        statuses = [j.status for j in self.mgr.all_jobs()]
        self.assertEqual(statuses, [TransferStatus.ERROR, TransferStatus.DONE])
        self.assertEqual(dest_fs.writes, 2)  # the failed write and one retry
        self.assertEqual(dock._model.rowCount(), 2)
        self.assertEqual((self.dst / "x.txt").read_bytes(), b"data")

    def test_sad_a_second_retry_of_the_same_job_is_refused(self) -> None:
        job = self._failed_copy(_FailWrites(fails=1))
        first = self.mgr.retry_job(job.job_id)
        self.assertIsNotNone(first)
        self.assertTrue(job.retried)
        self.assertIsNone(self.mgr.retry_job(job.job_id))
        self.wait([first])
        self.assertIsNone(self.mgr.retry_job(job.job_id))  # also once the retry is done

    def test_edge_a_retry_that_fails_again_can_itself_be_retried(self) -> None:
        job = self._failed_copy(_FailWrites(fails=2))
        first = self.mgr.retry_job(job.job_id)
        self.wait([first])
        self.assertEqual(first.status, TransferStatus.ERROR)
        self.assertFalse(first.retried)
        second = self.mgr.retry_job(first.job_id)
        self.assertIsNotNone(second)
        self.wait([second])
        self.assertEqual(second.status, TransferStatus.DONE)
        self.assertEqual((self.dst / "x.txt").read_bytes(), b"data")

    def test_edge_a_failed_move_retried_twice_moves_once_without_a_new_error(self) -> None:
        dest_fs = _FailWrites(fails=1)
        [job] = self.mgr.transfer_files(LocalFS(), dest_fs, [str(self.src / "x.txt")],
                                        str(self.dst), move=True)
        self.wait([job])
        self.assertIsNotNone(self.mgr.retry_job(job.job_id))
        self.assertIsNone(self.mgr.retry_job(job.job_id))
        self.wait(self.mgr.all_jobs())
        self.assertEqual([j.status for j in self.mgr.all_jobs()],
                         [TransferStatus.ERROR, TransferStatus.DONE])
        self.assertFalse((self.src / "x.txt").exists())
        self.assertEqual((self.dst / "x.txt").read_bytes(), b"data")


if __name__ == "__main__":
    unittest.main()
