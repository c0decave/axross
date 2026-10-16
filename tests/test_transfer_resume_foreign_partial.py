"""A resume only appends to a partial that holds THIS source's bytes.

Measured before: the auto-resume probe adopts any ``.<name>.part-*`` next
to the destination, matched by file name alone, and the worker appended
the source from the partial's size on. Downloading ``backup.tar`` from
host A, cancelling, and later downloading a different ``backup.tar`` from
host B into the same folder produced A's head spliced onto B's tail -- and
with no comparable native checksum on the two sides nothing noticed. A
same-size partial was even finalized as the file without reading a byte.
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

KIB = 1024


class _NoChecksumFS(LocalFS):
    def checksum(self, path, algorithm="sha256"):
        return ""


class _CountingFS(_NoChecksumFS):
    def __init__(self) -> None:
        super().__init__()
        self.bytes_read = 0

    def open_read(self, path):
        fh = super().open_read(path)
        fs = self

        class _H:
            def read(self, n=-1):
                data = fh.read(n)
                fs.bytes_read += len(data)
                return data

            def seek(self, *a):
                return fh.seek(*a)

            def close(self):
                fh.close()

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                fh.close()

        return _H()


class _UnreadablePartialFS(_NoChecksumFS):
    """A destination that can write and rename but not read back."""

    def open_read(self, path):
        if ".part-" in os.path.basename(path):
            raise OSError("read not permitted")
        return super().open_read(path)


class WorkerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.src = self.tmp / "src.bin"
        self.dst = self.tmp / "dst.bin"
        self.partial = self.tmp / ".dst.bin.part-old"

    def run_job(self, src_fs=None, dst_fs=None) -> TW.TransferJob:
        job = TW.TransferJob(
            source_path=str(self.src),
            dest_path=str(self.dst),
            total_bytes=self.src.stat().st_size,
            filename="src.bin",
            source_backend=src_fs or _NoChecksumFS(),
            dest_backend=dst_fs or _NoChecksumFS(),
            resume=True,
            temp_path=str(self.partial),
        )
        TW.TransferWorker()._process_job(job)
        return job

    def test_happy_a_genuine_partial_resumes_without_rereading_it(self) -> None:
        data = random.Random(3).randbytes(3 * 1024 * KIB)
        self.src.write_bytes(data)
        self.partial.write_bytes(data[: 2 * 1024 * KIB])
        fs = _CountingFS()
        job = self.run_job(src_fs=fs)
        self.assertEqual(job.status, TW.TransferStatus.DONE)
        self.assertEqual(self.dst.read_bytes(), data)
        # The remaining MiB plus at most two small verification samples.
        self.assertLess(fs.bytes_read, 1024 * KIB + 256 * KIB)

    def test_sad_a_partial_of_another_file_is_not_continued(self) -> None:
        new = random.Random(4).randbytes(600 * KIB)
        self.src.write_bytes(new)
        self.partial.write_bytes(random.Random(5).randbytes(250 * KIB))
        job = self.run_job()
        self.assertEqual(job.status, TW.TransferStatus.DONE)
        self.assertEqual(self.dst.read_bytes(), new)

    def test_sad_a_same_size_foreign_partial_is_not_finalized(self) -> None:
        self.src.write_bytes(b"N" * 5000)
        self.partial.write_bytes(b"O" * 5000)
        job = self.run_job()
        self.assertEqual(job.status, TW.TransferStatus.DONE)
        self.assertEqual(self.dst.read_bytes(), b"N" * 5000)

    def test_edge_a_difference_only_in_the_middle_of_a_small_partial(self) -> None:
        data = bytearray(b"z" * (100 * KIB))
        self.src.write_bytes(bytes(data))
        stale = bytearray(data[: 90 * KIB])
        stale[45 * KIB] = ord("!")
        self.partial.write_bytes(bytes(stale))
        self.run_job()
        self.assertEqual(self.dst.read_bytes(), bytes(data))

    def test_edge_an_unverifiable_partial_restarts(self) -> None:
        data = b"fresh" * 1000
        self.src.write_bytes(data)
        self.partial.write_bytes(b"stale" * 300)
        job = self.run_job(dst_fs=_UnreadablePartialFS())
        self.assertEqual(job.status, TW.TransferStatus.DONE)
        self.assertEqual(self.dst.read_bytes(), data)


class AutoResumeEndToEndTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def test_sad_a_cancelled_download_of_a_namesake_is_not_spliced_in(self) -> None:
        from core.transfer_manager import TransferManager

        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "host_b").mkdir()
        (tmp / "downloads").mkdir()
        new = random.Random(6).randbytes(700 * KIB)
        (tmp / "host_b" / "backup.tar").write_bytes(new)
        # Left behind by a cancelled download of host A's backup.tar.
        (tmp / "downloads" / ".backup.tar.part-1a2b3c4d").write_bytes(
            random.Random(7).randbytes(300 * KIB)
        )

        mgr = TransferManager()
        self.addCleanup(mgr.shutdown)
        jobs = mgr.transfer_files(
            _NoChecksumFS(), _NoChecksumFS(), [str(tmp / "host_b" / "backup.tar")],
            str(tmp / "downloads"),
        )
        self.assertTrue(jobs[0].resume)  # the probe adopted the partial
        deadline = time.monotonic() + 10
        while jobs[0].status in (TW.TransferStatus.PENDING, TW.TransferStatus.ACTIVE):
            self.app.processEvents()
            if time.monotonic() > deadline:
                self.fail("transfer did not finish")
            time.sleep(0.01)
        self.assertEqual(jobs[0].status, TW.TransferStatus.DONE, jobs[0].error_message)
        self.assertEqual((tmp / "downloads" / "backup.tar").read_bytes(), new)


if __name__ == "__main__":
    unittest.main()
