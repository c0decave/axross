"""A resumed transfer never splices a stale partial onto the wrong offset.

Measured before: the worker seeked the source to the partial's size and
only THEN noticed that the partial was larger than the file and restarted
"from zero" -- with the source still seeked past its end. The restart read
nothing, an empty file was finalized as the destination, and a move then
deleted the source. A retry also resumed against the size the failed job
had recorded, so a source rewritten smaller since then produced the old
partial as "the file".
"""

from __future__ import annotations

import os
import random
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import transfer_worker as TW  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


class _NoChecksumFS(LocalFS):
    """Most cross-protocol pairs have no comparable native hash, so the
    post-transfer integrity check is skipped -- the worker alone must be
    right."""

    def checksum(self, path, algorithm="sha256"):
        return ""


class _NoStatFS(_NoChecksumFS):
    def stat(self, path):
        raise OSError("stat not supported")


class ResumeOffsetTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.src = self.tmp / "src.bin"
        self.dst = self.tmp / "dst.bin"
        self.partial = self.tmp / ".dst.bin.part-old"
        self.worker = TW.TransferWorker()

    def run_job(self, source_fs=None, **kw) -> TW.TransferJob:
        if self.partial.exists():
            # Named as written from the source as it is now: the offset
            # checks below the version check are what these tests are about.
            fp = TW.source_fingerprint(LocalFS().stat(str(self.src)))
            versioned = self.tmp / TW.partial_name("dst.bin", "1a2b3c4d", fp)
            self.partial.rename(versioned)
            self.partial = versioned
        fs = _NoChecksumFS()
        job = TW.TransferJob(
            source_path=str(self.src),
            dest_path=str(self.dst),
            filename="src.bin",
            source_backend=source_fs or fs,
            dest_backend=fs,
            resume=True,
            temp_path=str(self.partial),
            **kw,
        )
        self.worker._process_job(job)
        return job

    def test_happy_a_matching_partial_still_resumes(self) -> None:
        data = random.Random(1).randbytes(300_000)
        self.src.write_bytes(data)
        self.partial.write_bytes(data[:100_000])
        job = self.run_job(total_bytes=len(data))
        self.assertEqual(job.status, TW.TransferStatus.DONE)
        self.assertEqual(self.dst.read_bytes(), data)

    def test_sad_an_oversized_partial_restarts_from_byte_zero(self) -> None:
        data = b"A" * 10
        self.src.write_bytes(data)
        self.partial.write_bytes(b"B" * 20)
        job = self.run_job(total_bytes=len(data))
        self.assertEqual(job.status, TW.TransferStatus.DONE)
        self.assertEqual(self.dst.read_bytes(), data)
        self.assertFalse(self.partial.exists())

    def test_sad_an_oversized_partial_in_a_move_keeps_the_data(self) -> None:
        data = b"payload-" * 4
        self.src.write_bytes(data)
        self.partial.write_bytes(b"x" * 100)
        job = self.run_job(total_bytes=len(data), move=True)
        self.assertEqual(job.status, TW.TransferStatus.DONE)
        self.assertFalse(self.src.exists())
        self.assertEqual(self.dst.read_bytes(), data)

    def test_sad_a_stale_size_from_a_shrunk_source_does_not_resume(self) -> None:
        """The failed job recorded 30 bytes; the source is 10 bytes now and
        the partial holds 20 bytes of the old content."""
        data = b"N" * 10
        self.src.write_bytes(data)
        self.partial.write_bytes(b"O" * 20)
        job = self.run_job(total_bytes=30)
        self.assertEqual(job.status, TW.TransferStatus.DONE)
        self.assertEqual(self.dst.read_bytes(), data)
        self.assertEqual(job.total_bytes, 10)

    def test_edge_a_source_now_empty_gives_an_empty_file(self) -> None:
        self.src.write_bytes(b"")
        self.partial.write_bytes(b"old")
        job = self.run_job(total_bytes=30)
        self.assertEqual(job.status, TW.TransferStatus.DONE)
        self.assertEqual(self.dst.read_bytes(), b"")

    def test_edge_without_stat_the_recorded_size_still_guards(self) -> None:
        data = b"S" * 10
        self.src.write_bytes(data)
        self.partial.write_bytes(b"T" * 20)
        job = self.run_job(source_fs=_NoStatFS(), total_bytes=len(data))
        self.assertEqual(job.status, TW.TransferStatus.DONE)
        self.assertEqual(self.dst.read_bytes(), data)

    def test_edge_a_complete_partial_is_finalized(self) -> None:
        data = b"C" * 64
        self.src.write_bytes(data)
        self.partial.write_bytes(data)
        job = self.run_job(total_bytes=len(data))
        self.assertEqual(job.status, TW.TransferStatus.DONE)
        self.assertEqual(self.dst.read_bytes(), data)


class RetryEndToEndTest(unittest.TestCase):
    """Through TransferManager.retry_job and the real worker thread."""

    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from core.transfer_manager import TransferManager

        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.mgr = TransferManager()
        self.addCleanup(self.mgr.shutdown)

    def _wait(self, job) -> None:
        deadline = time.monotonic() + 10
        while job.status in (TW.TransferStatus.PENDING, TW.TransferStatus.ACTIVE):
            self.app.processEvents()
            if time.monotonic() > deadline:
                self.fail("transfer did not finish")
            time.sleep(0.01)

    def test_sad_retrying_a_move_after_the_source_shrank(self) -> None:
        src = self.tmp / "report.bin"
        dst = self.tmp / "out" / "report.bin"
        dst.parent.mkdir()
        src.write_bytes(b"new" * 4)
        failed = TW.TransferJob(
            source_path=str(src),
            dest_path=str(dst),
            total_bytes=300,
            filename="report.bin",
            move=True,
            source_backend=_NoChecksumFS(),
            dest_backend=_NoChecksumFS(),
        )
        failed.status = TW.TransferStatus.ERROR
        failed.temp_path = str(dst.parent / ".report.bin.part-old")
        Path(failed.temp_path).write_bytes(b"old" * 50)
        self.mgr._jobs[failed.job_id] = failed

        retry = self.mgr.retry_job(failed.job_id)
        assert retry is not None
        self._wait(retry)

        self.assertEqual(retry.status, TW.TransferStatus.DONE, retry.error_message)
        self.assertEqual(dst.read_bytes(), b"new" * 4)
        self.assertFalse(src.exists())


if __name__ == "__main__":
    unittest.main()
