"""A finished job's size reaches the GUI before the job counts as done.

Seen as a flaky ``test_transfer_done_bytes`` under load (2026-10-22):
``(53, 53) != (5000, 5000)`` for a copied symlink. The worker corrects the
job's size to the bytes written (a symlink is listed with the length of
its target path, a source may grow) on the shared job object, but the
GUI thread's ``TransferManager._on_progress`` still applies progress
signals queued earlier, carrying the listing's size, and overwrites it.
The corrected size reached the GUI only with the final progress signal,
emitted AFTER the status turned DONE - so anyone reading the job between
the two (the dock, a test, ``all_finished`` handlers) saw the stale size.

Now the worker emits the written size as soon as it is known, before
verification and before the status changes: every stale signal is queued
ahead of it, and the job is DONE only after the GUI has been told.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.local_fs import LocalFS  # noqa: E402
from core.transfer_worker import TransferJob, TransferStatus, TransferWorker  # noqa: E402


class FinalSizeBeforeDoneTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / "dst").mkdir()

    def _run(self, name: str, listed_size: int, **kw):
        """Run one job synchronously; every progress signal is recorded
        with the job's status at the moment it was emitted."""
        fs = LocalFS()
        job = TransferJob(source_path=str(self.tmp / name), dest_path=str(self.tmp / "dst" / name),
                          filename=name, total_bytes=listed_size, use_temp_file=True, **kw)
        job.source_backend = job.dest_backend = fs
        worker = TransferWorker()
        seen: list[tuple[int, int, TransferStatus]] = []
        worker.progress.connect(lambda _jid, done, total: seen.append((done, total, job.status)))
        worker._process_job(job)
        return job, seen

    def test_happy_a_regular_file_reports_its_size_while_still_active(self) -> None:
        (self.tmp / "f.bin").write_bytes(b"x" * 3000)
        job, seen = self._run("f.bin", 3000)
        self.assertEqual(job.status, TransferStatus.DONE)
        self.assertIn((3000, 3000, TransferStatus.ACTIVE), seen)

    def test_sad_a_symlink_listed_with_its_path_length_reports_the_bytes_written(self) -> None:
        (self.tmp / "real.bin").write_bytes(b"R" * 5000)
        os.symlink(self.tmp / "real.bin", self.tmp / "link.bin")
        listed = os.lstat(self.tmp / "link.bin").st_size
        job, seen = self._run("link.bin", listed)
        self.assertEqual(job.status, TransferStatus.DONE)
        self.assertIn((5000, 5000, TransferStatus.ACTIVE), seen)
        # Nothing after it carries the listed size again.
        after = seen[seen.index((5000, 5000, TransferStatus.ACTIVE)):]
        self.assertTrue(all((d, t) == (5000, 5000) for d, t, _s in after), seen)

    def test_edge_an_empty_file_reports_zero_of_zero_before_done(self) -> None:
        (self.tmp / "empty").write_bytes(b"")
        job, seen = self._run("empty", 0)
        self.assertEqual(job.status, TransferStatus.DONE)
        self.assertIn((0, 0, TransferStatus.ACTIVE), seen)

    def test_edge_a_failed_job_reports_no_final_size(self) -> None:
        job, seen = self._run("missing.bin", 10)
        self.assertEqual(job.status, TransferStatus.ERROR)
        self.assertEqual(seen, [])


if __name__ == "__main__":
    unittest.main()
