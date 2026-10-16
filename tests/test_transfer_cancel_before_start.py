"""A job cancelled while still queued never touches either side.

Measured before: the worker ran a queued job whose cancel was already
requested. On a direct-write destination it downloaded the old file as a
snapshot, opened the source, opened the destination for writing (a
truncating open on a direct writer), only then saw the cancel, and wrote
the snapshot back over the destination to undo itself. A job the user
had called off rewrote the file it was meant to leave alone, and a
failure in that rewrite would have lost it.
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


class _RecordingFS(LocalFS):
    def __init__(self) -> None:
        super().__init__()
        self.calls: list[tuple[str, str]] = []

    def checksum(self, path, algorithm="sha256"):
        return ""

    def open_read(self, path):
        self.calls.append(("open_read", path))
        return super().open_read(path)

    def open_write(self, path, append=False):
        self.calls.append(("open_write", path))
        return super().open_write(path, append=append)

    def remove(self, path, recursive=False):
        self.calls.append(("remove", path))
        super().remove(path, recursive=recursive)


class CancelBeforeStartTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.src = self.tmp / "src.bin"
        self.dst = self.tmp / "dst.bin"
        self.src.write_bytes(b"new" * 100)
        self.dst.write_bytes(b"old" * 100)
        self.worker = TW.TransferWorker()

    def make_job(self, *, use_temp_file: bool, move: bool = False):
        source, dest = _RecordingFS(), _RecordingFS()
        job = TW.TransferJob(
            source_path=str(self.src),
            dest_path=str(self.dst),
            filename="src.bin",
            total_bytes=300,
            source_backend=source,
            dest_backend=dest,
            use_temp_file=use_temp_file,
            move=move,
        )
        return job, source, dest

    def test_happy_an_uncancelled_job_still_runs(self) -> None:
        job, _source, _dest = self.make_job(use_temp_file=False)
        self.worker._process_job(job)
        self.assertEqual(job.status, TW.TransferStatus.DONE, job.error_message)
        self.assertEqual(self.dst.read_bytes(), b"new" * 100)

    def test_sad_a_cancelled_direct_job_never_opens_the_destination(self) -> None:
        job, source, dest = self.make_job(use_temp_file=False)
        job.cancel_event.set()
        self.worker._process_job(job)
        self.assertEqual(job.status, TW.TransferStatus.CANCELLED)
        self.assertEqual(dest.calls, [])
        self.assertEqual(source.calls, [])
        self.assertEqual(self.dst.read_bytes(), b"old" * 100)

    def test_sad_a_cancelled_temp_job_leaves_no_partial(self) -> None:
        job, source, dest = self.make_job(use_temp_file=True)
        job.cancel_event.set()
        self.worker._process_job(job)
        self.assertEqual(job.status, TW.TransferStatus.CANCELLED)
        self.assertEqual(dest.calls, [])
        self.assertEqual(sorted(p.name for p in self.tmp.iterdir()), ["dst.bin", "src.bin"])

    def test_edge_a_cancelled_move_keeps_the_source(self) -> None:
        job, source, _dest = self.make_job(use_temp_file=False, move=True)
        job.cancel_event.set()
        self.worker._process_job(job)
        self.assertEqual(job.status, TW.TransferStatus.CANCELLED)
        self.assertNotIn(("remove", str(self.src)), source.calls)
        self.assertEqual(self.src.read_bytes(), b"new" * 100)


if __name__ == "__main__":
    unittest.main()
