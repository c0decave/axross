"""Transfers move data in 1 MiB steps.

With 64 KiB steps every protocol that does one synchronous request per
read/write call (SMB through smbclient, ...) paid one round trip per
64 KiB: 1 024 round trips for 64 MiB instead of 64.
"""

from __future__ import annotations

import os
import random
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import transfer_worker as TW  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


class _CountingFS(LocalFS):
    def __init__(self) -> None:
        super().__init__()
        self.reads: list[int] = []

    def open_read(self, path):
        fh = super().open_read(path)
        reads = self.reads

        class _Counting:
            def __init__(self, inner) -> None:
                self._inner = inner

            def read(self, n=-1):
                reads.append(n)
                return self._inner.read(n)

            def seek(self, *a):
                return self._inner.seek(*a)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self._inner.close()

            def close(self):
                self._inner.close()

        return _Counting(fh)


class ChunkTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.data = random.Random(8).randbytes(4 * 1024 * 1024 + 777)
        self.src = self.tmp / "src.bin"
        self.src.write_bytes(self.data)
        self.fs = _CountingFS()
        self.worker = TW.TransferWorker()

    def run_job(self, **kw) -> TW.TransferJob:
        job = TW.TransferJob(
            source_path=str(self.src),
            dest_path=str(self.tmp / "dst.bin"),
            total_bytes=len(self.data),
            filename="src.bin",
            source_backend=self.fs,
            dest_backend=LocalFS(),
            **kw,
        )
        self.worker._process_job(job)
        return job

    def test_happy_a_4_mib_file_takes_five_reads(self) -> None:
        job = self.run_job()
        self.assertEqual(job.status, TW.TransferStatus.DONE)
        self.assertEqual((self.tmp / "dst.bin").read_bytes(), self.data)
        self.assertEqual(self.fs.reads, [TW.CHUNK_SIZE] * 6)  # 5 with data + EOF
        self.assertEqual(TW.CHUNK_SIZE, 1024 * 1024)

    def test_happy_direct_write_path(self) -> None:
        job = self.run_job(use_temp_file=False)
        self.assertEqual(job.status, TW.TransferStatus.DONE)
        self.assertEqual((self.tmp / "dst.bin").read_bytes(), self.data)

    def test_edge_resume_from_an_odd_offset(self) -> None:
        partial = self.tmp / ".dst.bin.part-x"
        partial.write_bytes(self.data[:123457])
        job = self.run_job(resume=True, temp_path=str(partial))
        self.assertEqual(job.status, TW.TransferStatus.DONE)
        self.assertEqual((self.tmp / "dst.bin").read_bytes(), self.data)

    def test_edge_empty_file(self) -> None:
        self.src.write_bytes(b"")
        self.data = b""
        job = self.run_job()
        self.assertEqual(job.status, TW.TransferStatus.DONE)
        self.assertEqual((self.tmp / "dst.bin").read_bytes(), b"")


if __name__ == "__main__":
    unittest.main()
