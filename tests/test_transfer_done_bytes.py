"""A finished job reports the bytes it actually wrote.

Reported: copying a symbolic link to a 5000-byte file wrote 5000 bytes but
the transfer list, the final progress signal and the operation journal said
53 - the length of the link's target path. The job's size came from the
listing (``lstat``: a link is its own entry) and the worker's last progress
signal repeated that size as "done" instead of the count it had written.
The same happened for any source that changed size after it was listed.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.local_fs import LocalFS  # noqa: E402
from core.transfer_worker import TransferStatus  # noqa: E402


class _NoSpace(LocalFS):
    """A destination that fails the first write (disk full)."""

    def open_write(self, path, append=False):
        handle = super().open_write(path, append)

        def write(_data):
            raise OSError(28, "No space left on device")

        handle.write = write
        return handle


class DoneBytesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from PyQt6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from core.transfer_manager import TransferManager

        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.src = self.tmp / "src"
        self.dst = self.tmp / "dst"
        self.src.mkdir()
        self.dst.mkdir()
        self.journal = self.tmp / "operations.jsonl"
        env = mock.patch.dict(os.environ, {"AXROSS_OPERATION_JOURNAL": str(self.journal)})
        env.start()
        self.addCleanup(env.stop)
        self.mgr = TransferManager()
        self.addCleanup(self.mgr.shutdown)
        self.progress: list[tuple] = []
        self.mgr._worker.progress.connect(lambda *args: self.progress.append(args))

    def _wait(self, jobs) -> None:
        deadline = time.monotonic() + 10
        while any(j.status in (TransferStatus.PENDING, TransferStatus.ACTIVE) for j in jobs):
            self.app.processEvents()
            self.assertLess(time.monotonic(), deadline, "transfer did not finish")
            time.sleep(0.01)
        for _ in range(3):
            self.app.processEvents()

    def _finish_event(self, job) -> dict:
        rows = [json.loads(line) for line in self.journal.read_text().splitlines()]
        [row] = [r for r in rows
                 if r["operation_id"] == job.operation_id and r["phase"] == "finish"]
        return row

    def _copy(self, name: str, dest=None, **kw):
        jobs = self.mgr.transfer_files(
            LocalFS(), dest or LocalFS(), [str(self.src / name)], str(self.dst), **kw
        )
        self._wait(jobs)
        return jobs

    def test_happy_a_regular_file_reports_its_size(self) -> None:
        (self.src / "f.bin").write_bytes(b"x" * 3000)
        [job] = self._copy("f.bin")
        self.assertEqual(job.status, TransferStatus.DONE)
        self.assertEqual((job.total_bytes, job.transferred_bytes), (3000, 3000))
        self.assertEqual(self.progress[-1][1:], (3000, 3000))

    def test_sad_a_symlinked_file_reports_the_bytes_written(self) -> None:
        (self.src / "real.bin").write_bytes(b"R" * 5000)
        os.symlink(self.src / "real.bin", self.src / "link.bin")
        [job] = self._copy("link.bin")
        self.assertEqual(job.status, TransferStatus.DONE)
        self.assertEqual((self.dst / "link.bin").stat().st_size, 5000)
        self.assertEqual((job.total_bytes, job.transferred_bytes), (5000, 5000))
        self.assertEqual(self.progress[-1][1:], (5000, 5000))
        finish = self._finish_event(job)
        self.assertEqual((finish["bytes_total"], finish["bytes_done"]), (5000, 5000))

    def test_sad_a_failed_job_does_not_claim_its_size(self) -> None:
        (self.src / "f.bin").write_bytes(b"x" * 3000)
        [job] = self._copy("f.bin", dest=_NoSpace())
        self.assertEqual(job.status, TransferStatus.ERROR)
        self.assertEqual(job.total_bytes, 3000)
        self.assertEqual(job.transferred_bytes, 0)
        self.assertFalse((self.dst / "f.bin").exists())

    def test_edge_a_source_that_grew_after_listing_reports_its_new_size(self) -> None:
        (self.src / "grow.log").write_bytes(b"y" * 7000)
        job = self.mgr.transfer_file(
            LocalFS(), LocalFS(), str(self.src / "grow.log"), str(self.dst / "grow.log"),
            size=100,  # what an older listing said
        )
        self._wait([job])
        self.assertEqual((self.dst / "grow.log").stat().st_size, 7000)
        self.assertEqual((job.total_bytes, job.transferred_bytes), (7000, 7000))

    def test_edge_an_empty_file_reports_zero(self) -> None:
        (self.src / "empty").write_bytes(b"")
        [job] = self._copy("empty")
        self.assertEqual(job.status, TransferStatus.DONE)
        self.assertEqual((job.total_bytes, job.transferred_bytes), (0, 0))


if __name__ == "__main__":
    unittest.main()
