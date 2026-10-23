"""A copy that runs out of space does not leave its partial file behind.

Measured before: a transfer that failed part-way kept its hidden partial
(``.<name>.part-<job>-<fingerprint>``) for a later resume - also when it
failed BECAUSE the destination was full. The partial is what fills it:
a 3 MiB file into a 2.5 MiB RAM workspace failed at its cap and left a
2 MiB hidden partial, after which a 1 MiB copy into the (visibly empty)
workspace failed too; on a disk, ENOSPC left a hidden file holding the
space the user then could not find. Resuming needs that space as well.

Now an out-of-space failure (ENOSPC, EDQUOT, EFBIG, a RamFS cap, also
wrapped in another OSError) removes the partial; any other failure keeps
it for the resume, as before.
"""

from __future__ import annotations

import errno
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
from core.ram_fs import RamFsSession  # noqa: E402
from core.transfer_worker import TransferStatus  # noqa: E402

MiB = 1024 * 1024


class _FailAfter(LocalFS):
    """Writes fail with *exc* once *limit* bytes were written to a file."""

    def __init__(self, exc: BaseException, limit: int = MiB) -> None:
        self.exc = exc
        self.limit = limit

    def open_write(self, path, append=False):
        handle = super().open_write(path, append)
        outer = self

        class _Writer:
            written = 0

            def write(self, data):
                if self.written >= outer.limit:
                    raise outer.exc
                self.written += len(data)
                return handle.write(data)

            def close(self):
                handle.close()

        return _Writer()


class OutOfSpacePartialTest(unittest.TestCase):
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
        (self.src / "big.bin").write_bytes(os.urandom(3 * MiB))
        (self.src / "small.bin").write_bytes(b"s" * MiB)
        self.mgr = TransferManager()
        self.addCleanup(self.mgr.shutdown)

    def wait(self, jobs) -> None:
        end = time.monotonic() + 20
        while any(j.status in (TransferStatus.PENDING, TransferStatus.ACTIVE) for j in jobs):
            self.app.processEvents()
            if time.monotonic() > end:
                self.fail("transfer did not finish")
            time.sleep(0.005)
        for _ in range(5):
            self.app.processEvents()

    def _copy(self, dest_fs, name: str, dest_dir: str):
        jobs = self.mgr.transfer_files(LocalFS(), dest_fs, [str(self.src / name)], dest_dir)
        self.wait(jobs)
        return jobs[0]

    def _left_in_dst(self) -> list[str]:
        return sorted(os.listdir(self.dst))

    def test_happy_a_full_ram_workspace_keeps_no_partial_and_takes_the_next_file(self) -> None:
        """e2e: the real dock and a real RAM workspace."""
        from ui.transfer_dock import TransferDock

        dock = TransferDock(self.mgr)
        self.addCleanup(dock.deleteLater)
        ram = RamFsSession(max_bytes=2 * MiB + MiB // 2, system_reserve_bytes=0)
        big = self._copy(ram, "big.bin", "/")
        self.assertEqual(big.status, TransferStatus.ERROR)
        self.assertIn("cap", big.error_message)
        self.assertEqual(ram.list_dir("/"), [])
        self.assertEqual(ram.size_bytes, 0)
        small = self._copy(ram, "small.bin", "/")
        self.assertEqual(small.status, TransferStatus.DONE, small.error_message)
        self.assertEqual([i.name for i in ram.list_dir("/")], ["small.bin"])
        self.assertEqual(dock._model.rowCount(), 2)

    def test_sad_enospc_on_a_disk_removes_the_partial(self) -> None:
        full = _FailAfter(OSError(errno.ENOSPC, "No space left on device"))
        job = self._copy(full, "big.bin", str(self.dst))
        self.assertEqual(job.status, TransferStatus.ERROR)
        self.assertIn("No space left", job.error_message)
        self.assertEqual(self._left_in_dst(), [])

    def test_edge_quota_too_large_and_wrapped_errors_count_as_out_of_space(self) -> None:
        wrapped = OSError("Cannot write /x: backend said so")
        wrapped.__cause__ = OSError(errno.ENOSPC, "disk full")
        for exc in (OSError(errno.EDQUOT, "Disk quota exceeded"),
                    OSError(errno.EFBIG, "File too large"),
                    wrapped):
            with self.subTest(exc=exc):
                job = self._copy(_FailAfter(exc), "big.bin", str(self.dst))
                self.assertEqual(job.status, TransferStatus.ERROR)
                self.assertEqual(self._left_in_dst(), [])

    def test_edge_an_smb_disk_full_or_quota_answer_counts_too(self) -> None:
        """smbprotocol raises its own exceptions (no OSError, no errno) and
        carries the NT status: STATUS_DISK_FULL, STATUS_QUOTA_EXCEEDED."""

        class _SmbResponse(Exception):
            def __init__(self, status: int) -> None:
                super().__init__(f"status {status:#x}")
                self.status = status

        for status in (0xC000007F, 0xC0000044):
            with self.subTest(status=hex(status)):
                job = self._copy(_FailAfter(_SmbResponse(status)), "big.bin", str(self.dst))
                self.assertEqual(job.status, TransferStatus.ERROR)
                self.assertEqual(self._left_in_dst(), [])
        # Another NT status (access denied) is no space problem: kept.
        job = self._copy(_FailAfter(_SmbResponse(0xC0000022)), "big.bin", str(self.dst))
        self.assertEqual(len(self._left_in_dst()), 1)

    def test_edge_another_failure_still_keeps_the_partial_for_a_resume(self) -> None:
        flaky = _FailAfter(OSError(errno.EIO, "Input/output error"))
        job = self._copy(flaky, "big.bin", str(self.dst))
        self.assertEqual(job.status, TransferStatus.ERROR)
        [partial] = self._left_in_dst()
        self.assertTrue(partial.startswith(".big.bin.part-"), partial)
        job.dest_backend = LocalFS()  # the disk is back
        retry = self.mgr.retry_job(job.job_id)
        self.wait([retry])
        self.assertEqual(retry.status, TransferStatus.DONE, retry.error_message)
        self.assertEqual((self.dst / "big.bin").read_bytes(), (self.src / "big.bin").read_bytes())

    def test_edge_a_resumed_partial_is_removed_when_the_resume_runs_out_of_space(self) -> None:
        flaky = _FailAfter(OSError(errno.EIO, "Input/output error"))
        job = self._copy(flaky, "big.bin", str(self.dst))
        self.assertEqual(len(self._left_in_dst()), 1)
        job.dest_backend = _FailAfter(OSError(errno.ENOSPC, "No space left on device"),
                                      limit=0)
        retry = self.mgr.retry_job(job.job_id)
        self.wait([retry])
        self.assertEqual(retry.status, TransferStatus.ERROR)
        self.assertEqual(self._left_in_dst(), [])


if __name__ == "__main__":
    unittest.main()
