"""A job that wrote nothing is not shown as "done" in the transfer list.

Reported: with "Overwrite if newer", a destination that turned out to be at
least as new as the source ended the job without writing a byte, and a move
kept its source (``TransferWorker`` sets ``job.skipped``). The transfer list
still showed that row as "Done" / "done", so the user read a move that never
happened as finished. ``job.skipped`` was read nowhere in the UI.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from core.transfer_worker import TransferJob, TransferStatus  # noqa: E402
from models.transfer_model import COL_PROGRESS, COL_STATUS, TransferModel  # noqa: E402

_DISPLAY = Qt.ItemDataRole.DisplayRole
_BAR = Qt.ItemDataRole.UserRole


def _row(job: TransferJob) -> tuple:
    model = TransferModel()
    model.add_job(job)
    return (
        model.data(model.index(0, COL_PROGRESS), _DISPLAY),
        model.data(model.index(0, COL_STATUS), _DISPLAY),
        model.data(model.index(0, COL_PROGRESS), _BAR),
    )


class SkippedRowModelTest(unittest.TestCase):
    def test_happy_a_finished_job_still_reads_done(self) -> None:
        job = TransferJob(total_bytes=10, transferred_bytes=10, status=TransferStatus.DONE)
        self.assertEqual(_row(job), ("Done", "done", 100.0))

    def test_sad_a_skipped_job_reads_skipped(self) -> None:
        job = TransferJob(total_bytes=10, status=TransferStatus.DONE, skipped=True)
        progress, status, bar = _row(job)
        self.assertEqual((progress, status), ("Skipped", "skipped"))
        # No bar: the delegate then draws the text instead of "0%".
        self.assertIsNone(bar)

    def test_edge_a_failed_job_keeps_its_error_status(self) -> None:
        job = TransferJob(total_bytes=10, transferred_bytes=4, status=TransferStatus.ERROR)
        self.assertEqual(_row(job), ("40%", "error", 40.0))


class SkippedRowEngineTest(unittest.TestCase):
    """The row as the real worker leaves it after a "newer" refusal."""

    @classmethod
    def setUpClass(cls) -> None:
        from PyQt6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from core.transfer_manager import TransferManager

        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / "src").mkdir()
        (self.tmp / "dst").mkdir()
        self.mgr = TransferManager()
        self.addCleanup(self.mgr.shutdown)

    def _move_if_newer(self, src_mtime: float, dst_mtime: float) -> TransferJob:
        src, dst = self.tmp / "src" / "f", self.tmp / "dst" / "f"
        src.write_bytes(b"source")
        dst.write_bytes(b"dest")
        os.utime(src, (src_mtime, src_mtime))
        os.utime(dst, (dst_mtime, dst_mtime))
        job = self.mgr.transfer_file(
            LocalFS(), LocalFS(), str(src), str(dst), move=True, if_exists="newer"
        )
        deadline = time.monotonic() + 10
        while job.status in (TransferStatus.PENDING, TransferStatus.ACTIVE):
            self.app.processEvents()
            self.assertLess(time.monotonic(), deadline, "job did not finish")
            time.sleep(0.01)
        self.app.processEvents()
        return job

    def test_sad_a_move_kept_by_newer_is_listed_as_skipped(self) -> None:
        job = self._move_if_newer(1_000_000, 2_000_000)
        self.assertTrue((self.tmp / "src" / "f").exists())
        self.assertEqual((self.tmp / "dst" / "f").read_bytes(), b"dest")
        self.assertEqual(_row(job)[:2], ("Skipped", "skipped"))

    def test_happy_a_move_that_replaced_an_older_file_is_done(self) -> None:
        job = self._move_if_newer(2_000_000, 1_000_000)
        self.assertFalse((self.tmp / "src" / "f").exists())
        self.assertEqual((self.tmp / "dst" / "f").read_bytes(), b"source")
        self.assertEqual(_row(job)[:2], ("Done", "done"))


if __name__ == "__main__":
    unittest.main()
