"""A direct-write transfer that cannot back up the destination leaves it alone.

Measured before: ``_do_transfer_direct`` took the rollback snapshot of an
existing destination INSIDE its ``try``. When that read-back failed (an
FTP "incoming" folder that allows STOR and DELE but refuses RETR, a
dropped connection mid-download), ``destination_existed`` was still
``False``, so the rollback treated the destination as a partial file
the transfer had created and removed it. The transfer reported an error
and the file it was asked to replace was gone.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import transfer_worker as TW  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


class _NoChecksumFS(LocalFS):
    def checksum(self, path, algorithm="sha256"):
        return ""


class _WriteOnlyDest(_NoChecksumFS):
    """Lists, writes and deletes, but refuses to read *unreadable*."""

    def __init__(self, unreadable: str) -> None:
        super().__init__()
        self.unreadable = unreadable
        self.removed: list[str] = []

    def open_read(self, path):
        if path == self.unreadable:
            raise PermissionError(f"550 {path}: read access denied")
        return super().open_read(path)

    def remove(self, path, recursive=False):
        self.removed.append(path)
        super().remove(path, recursive=recursive)


class _ProbeFailsDest(_WriteOnlyDest):
    def exists(self, path):
        if path == self.unreadable:
            raise OSError("421 connection lost")
        return super().exists(path)


class _FailingSource(_NoChecksumFS):
    def open_read(self, path):
        handle = super().open_read(path)

        class _Broken:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                handle.close()
                return False

            def read(self, n=-1):
                raise OSError("426 transfer aborted")

        return _Broken()


class DirectDestinationKeptTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.src = self.tmp / "src.bin"
        self.dst = self.tmp / "dst.bin"
        self.src.write_bytes(b"new" * 1000)
        self.dst.write_bytes(b"old" * 1000)
        self.worker = TW.TransferWorker()

    def run_job(self, dest, source=None) -> TW.TransferJob:
        job = TW.TransferJob(
            source_path=str(self.src),
            dest_path=str(self.dst),
            filename="src.bin",
            total_bytes=3000,
            source_backend=source or _NoChecksumFS(),
            dest_backend=dest,
            use_temp_file=False,
        )
        self.worker._process_job(job)
        return job

    def test_happy_a_direct_overwrite_still_replaces_the_destination(self) -> None:
        job = self.run_job(_NoChecksumFS())
        self.assertEqual(job.status, TW.TransferStatus.DONE, job.error_message)
        self.assertEqual(self.dst.read_bytes(), b"new" * 1000)

    def test_sad_an_unreadable_destination_is_not_deleted(self) -> None:
        dest = _WriteOnlyDest(str(self.dst))
        job = self.run_job(dest)
        self.assertEqual(job.status, TW.TransferStatus.ERROR)
        self.assertEqual(dest.removed, [])
        self.assertEqual(self.dst.read_bytes(), b"old" * 1000)

    def test_sad_a_failed_existence_probe_deletes_nothing(self) -> None:
        dest = _ProbeFailsDest(str(self.dst))
        job = self.run_job(dest)
        self.assertEqual(job.status, TW.TransferStatus.ERROR)
        self.assertEqual(dest.removed, [])
        self.assertEqual(self.dst.read_bytes(), b"old" * 1000)

    def test_edge_a_failure_after_the_snapshot_still_restores_the_old_bytes(self) -> None:
        job = self.run_job(_NoChecksumFS(), source=_FailingSource())
        self.assertEqual(job.status, TW.TransferStatus.ERROR)
        self.assertEqual(self.dst.read_bytes(), b"old" * 1000)

    def test_edge_a_failure_with_no_prior_destination_removes_the_partial(self) -> None:
        self.dst.unlink()
        job = self.run_job(_NoChecksumFS(), source=_FailingSource())
        self.assertEqual(job.status, TW.TransferStatus.ERROR)
        self.assertFalse(self.dst.exists())


if __name__ == "__main__":
    unittest.main()
