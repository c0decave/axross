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
        # Name the partial as written from the source as it is now, so the
        # content check below the version check is what decides.
        fp = TW.source_fingerprint(LocalFS().stat(str(self.src)))
        versioned = self.tmp / TW.partial_name("dst.bin", "1a2b3c4d", fp)
        self.partial.rename(versioned)
        self.partial = versioned
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


class _NoMtimeFS(_NoChecksumFS):
    def stat(self, path):
        import dataclasses

        return dataclasses.replace(super().stat(path), modified=None)


class SourceVersionTest(unittest.TestCase):
    """A partial records which version of the source it was written from.

    Measured before: a 4 MiB source copied to a destination without a
    native checksum (SMB) was cancelled after 2 MiB, then changed in the
    middle. The next copy adopted the partial by name, compared only its
    first and last 64 KiB, appended the new tail and reported DONE: the
    destination held the old middle; a move then deleted the source.
    """

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.src = self.tmp / "src.bin"
        self.dst = self.tmp / "dst.bin"

    def _partial_for(self, fingerprint: str) -> Path:
        return self.tmp / TW.partial_name("dst.bin", "1a2b3c4d", fingerprint)

    def _fingerprint(self) -> str:
        return TW.source_fingerprint(LocalFS().stat(str(self.src)))

    def run_job(self, partial: Path, src_fs=None, move=False) -> TW.TransferJob:
        job = TW.TransferJob(
            source_path=str(self.src), dest_path=str(self.dst),
            total_bytes=self.src.stat().st_size, filename="src.bin",
            source_backend=src_fs or _NoChecksumFS(), dest_backend=_NoChecksumFS(),
            resume=True, temp_path=str(partial), move=move,
        )
        TW.TransferWorker()._process_job(job)
        return job

    def test_sad_a_partial_of_an_older_version_is_not_spliced(self) -> None:
        old = random.Random(11).randbytes(4 * 1024 * KIB)
        self.src.write_bytes(old)
        os.utime(self.src, ns=(1_700_000_000_000_000_000, 1_700_000_000_000_000_000))
        partial = self._partial_for(self._fingerprint())
        partial.write_bytes(old[: 2 * 1024 * KIB])
        new = bytearray(old)
        new[1024 * KIB: 1024 * KIB + 4096] = b"\xaa" * 4096  # inside the copied part
        self.src.write_bytes(bytes(new))
        job = self.run_job(partial, move=True)
        self.assertEqual(job.status, TW.TransferStatus.DONE, job.error_message)
        self.assertEqual(self.dst.read_bytes(), bytes(new))
        self.assertEqual(sorted(os.listdir(self.tmp)), ["dst.bin"])

    def test_happy_a_partial_of_the_unchanged_source_resumes(self) -> None:
        data = random.Random(12).randbytes(3 * 1024 * KIB)
        self.src.write_bytes(data)
        partial = self._partial_for(self._fingerprint())
        partial.write_bytes(data[: 2 * 1024 * KIB])
        fs = _CountingFS()
        job = self.run_job(partial, src_fs=fs)
        self.assertEqual(job.status, TW.TransferStatus.DONE, job.error_message)
        self.assertEqual(self.dst.read_bytes(), data)
        self.assertLess(fs.bytes_read, 1024 * KIB + 256 * KIB)

    def test_edge_a_partial_without_a_recorded_version_restarts(self) -> None:
        data = random.Random(13).randbytes(3 * 1024 * KIB)
        self.src.write_bytes(data)
        partial = self.tmp / ".dst.bin.part-1a2b3c4d"  # named before versions were recorded
        partial.write_bytes(data[: 2 * 1024 * KIB])
        fs = _CountingFS()
        job = self.run_job(partial, src_fs=fs)
        self.assertEqual(job.status, TW.TransferStatus.DONE, job.error_message)
        self.assertEqual(self.dst.read_bytes(), data)
        self.assertGreaterEqual(fs.bytes_read, len(data))
        self.assertEqual(sorted(os.listdir(self.tmp)), ["dst.bin", "src.bin"])

    def test_edge_a_source_without_a_modification_time_never_resumes(self) -> None:
        data = random.Random(14).randbytes(1024 * KIB)
        self.src.write_bytes(data)
        partial = self._partial_for(self._fingerprint())
        partial.write_bytes(b"X" * (512 * KIB))  # head and tail would not even match
        job = self.run_job(partial, src_fs=_NoMtimeFS())
        self.assertEqual(job.status, TW.TransferStatus.DONE, job.error_message)
        self.assertEqual(self.dst.read_bytes(), data)

    def test_edge_partial_names_record_and_read_back_the_fingerprint(self) -> None:
        name = TW.partial_name("a-b.txt", "0123abcd", "deadbeef")
        self.assertEqual(name, ".a-b.txt.part-0123abcd-deadbeef")
        self.assertEqual(TW.partial_fingerprint(name, "a-b.txt"), "deadbeef")
        self.assertEqual(TW.partial_fingerprint(".a-b.txt.part-0123abcd", "a-b.txt"), "")
        self.assertEqual(TW.partial_fingerprint(".a-b.txt.part-old", "a-b.txt"), "")
        self.assertEqual(TW.partial_fingerprint(".other.part-0-deadbeef", "a-b.txt"), "")


class AutoResumeVersionEndToEndTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def _wait(self, jobs) -> None:
        deadline = time.monotonic() + 20
        while any(j.status in (TW.TransferStatus.PENDING, TW.TransferStatus.ACTIVE)
                  for j in jobs):
            self.app.processEvents()
            if time.monotonic() > deadline:
                self.fail("transfer did not finish")
            time.sleep(0.01)

    def test_sad_a_source_changed_since_the_cancelled_copy_is_copied_whole(self) -> None:
        from core.transfer_manager import TransferManager

        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "src").mkdir()
        (tmp / "share").mkdir()
        src = tmp / "src" / "disk.img"
        old = random.Random(15).randbytes(4 * 1024 * KIB)
        src.write_bytes(old)
        os.utime(src, ns=(1_700_000_000_000_000_000, 1_700_000_000_000_000_000))
        fp = TW.source_fingerprint(LocalFS().stat(str(src)))
        (tmp / "share" / TW.partial_name("disk.img", "1a2b3c4d", fp)).write_bytes(
            old[: 2 * 1024 * KIB]
        )
        new = bytearray(old)
        new[1024 * KIB: 1024 * KIB + 4096] = b"\xaa" * 4096
        src.write_bytes(bytes(new))

        mgr = TransferManager()
        self.addCleanup(mgr.shutdown)
        jobs = mgr.transfer_files(_NoChecksumFS(), _NoChecksumFS(), [str(src)],
                                  str(tmp / "share"), move=True)
        self._wait(jobs)
        self.assertEqual(jobs[0].status, TW.TransferStatus.DONE, jobs[0].error_message)
        self.assertEqual((tmp / "share" / "disk.img").read_bytes(), bytes(new))
        self.assertEqual(os.listdir(tmp / "share"), ["disk.img"])

    def test_happy_the_probe_prefers_the_partial_of_the_current_version(self) -> None:
        from core.transfer_manager import TransferManager

        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "out").mkdir()
        src = tmp / "f.bin"
        data = random.Random(16).randbytes(1024 * KIB)
        src.write_bytes(data)
        fp = TW.source_fingerprint(LocalFS().stat(str(src)))
        (tmp / "out" / TW.partial_name("f.bin", "00000000", "0badf00d")).write_bytes(b"s" * 9)
        good = tmp / "out" / TW.partial_name("f.bin", "11111111", fp)
        good.write_bytes(data[:300 * KIB])
        mgr = TransferManager()
        self.addCleanup(mgr.shutdown)
        jobs = mgr.transfer_files(_NoChecksumFS(), _NoChecksumFS(), [str(src)], str(tmp / "out"))
        self.assertEqual(jobs[0].temp_path, str(good))
        self._wait(jobs)
        self.assertEqual((tmp / "out" / "f.bin").read_bytes(), data)


if __name__ == "__main__":
    unittest.main()
