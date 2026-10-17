"""A named pipe in a copied folder no longer blocks the transfer worker.

Measured before: F5 of a folder holding a FIFO opened it with a blocking
``open(path, "rb")``; with no writer the only transfer worker waited
forever. "Cancel All" could not interrupt it and every later transfer
stayed "pending". LocalFS.open_read now refuses anything that is not a
regular file without blocking, and the job reports why.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.local_fs import LocalFS  # noqa: E402
from core.transfer_worker import TransferStatus  # noqa: E402

HAS_FIFO = hasattr(os, "mkfifo")


def _call_with_deadline(fn, seconds=5.0):
    """(result, exception); fails the caller if *fn* is still blocked."""
    box: dict = {}

    def run():
        try:
            box["result"] = fn()
        except BaseException as exc:  # noqa: BLE001 - handed to the test
            box["exc"] = exc

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(seconds)
    if t.is_alive():
        raise AssertionError("call still blocked after %.0f s" % seconds)
    return box.get("result"), box.get("exc")


class OpenReadTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_happy_a_regular_file_reads_and_seeks(self) -> None:
        p = self.tmp / "f.bin"
        p.write_bytes(b"0123456789")
        with LocalFS().open_read(str(p)) as fh:
            fh.seek(4)
            self.assertEqual(fh.read(3), b"456")

    @unittest.skipUnless(HAS_FIFO, "needs os.mkfifo")
    def test_sad_a_fifo_is_refused_without_blocking(self) -> None:
        fifo = self.tmp / "m.fifo"
        os.mkfifo(fifo)
        _result, exc = _call_with_deadline(lambda: LocalFS().open_read(str(fifo)))
        self.assertIsInstance(exc, OSError)
        self.assertIn("not a regular file", str(exc))

    def test_edge_a_folder_is_refused(self) -> None:
        _result, exc = _call_with_deadline(lambda: LocalFS().open_read(str(self.tmp)))
        self.assertIsInstance(exc, IsADirectoryError)

    def test_edge_a_symlink_to_a_regular_file_still_reads(self) -> None:
        (self.tmp / "t.txt").write_bytes(b"target")
        os.symlink(self.tmp / "t.txt", self.tmp / "l.txt")
        with LocalFS().open_read(str(self.tmp / "l.txt")) as fh:
            self.assertEqual(fh.read(), b"target")


@unittest.skipUnless(HAS_FIFO, "needs os.mkfifo")
class FolderCopyTest(unittest.TestCase):
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
        self.addCleanup(self._unblock_and_shutdown)

    def _unblock_and_shutdown(self) -> None:
        # Should a regression block the worker again, a writer releases it
        # so the suite does not hang in shutdown.
        for fifo in self.tmp.rglob("*.fifo"):
            try:
                os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
            except OSError:
                pass
        self.mgr.shutdown()

    def _wait(self, jobs, seconds=10) -> None:
        deadline = time.monotonic() + seconds
        while any(j.status in (TransferStatus.PENDING, TransferStatus.ACTIVE) for j in jobs):
            self.app.processEvents()
            if time.monotonic() > deadline:
                self.fail("transfer did not finish: %r" % [(j.filename, j.status) for j in jobs])
            time.sleep(0.01)

    def test_sad_a_fifo_in_a_folder_fails_alone_and_the_rest_is_copied(self) -> None:
        src = self.tmp / "proj"
        src.mkdir()
        (src / "a.txt").write_bytes(b"a")
        os.mkfifo(src / "m.fifo")
        (src / "z.txt").write_bytes(b"z")
        (self.tmp / "dst").mkdir()
        jobs = self.mgr.transfer_files(LocalFS(), LocalFS(), [str(src)], str(self.tmp / "dst"))
        self._wait(jobs)
        by_name = {j.filename: j for j in jobs}
        self.assertEqual(by_name["a.txt"].status, TransferStatus.DONE)
        self.assertEqual(by_name["z.txt"].status, TransferStatus.DONE)
        self.assertEqual(by_name["m.fifo"].status, TransferStatus.ERROR)
        self.assertIn("not a regular file", by_name["m.fifo"].error_message)
        self.assertEqual(sorted(os.listdir(self.tmp / "dst" / "proj")), ["a.txt", "z.txt"])

        later = self.tmp / "later.txt"
        later.write_bytes(b"l")
        more = self.mgr.transfer_files(LocalFS(), LocalFS(), [str(later)], str(self.tmp / "dst"))
        self._wait(more)
        self.assertEqual(more[0].status, TransferStatus.DONE)

    def test_edge_a_moved_folder_keeps_its_fifo(self) -> None:
        src = self.tmp / "proj"
        src.mkdir()
        os.mkfifo(src / "m.fifo")
        (src / "a.txt").write_bytes(b"a")
        (self.tmp / "dst").mkdir()
        jobs = self.mgr.transfer_files(LocalFS(), LocalFS(), [str(src)], str(self.tmp / "dst"),
                                       move=True)
        self._wait(jobs)
        self.assertTrue((src / "m.fifo").exists())
        self.assertEqual((self.tmp / "dst" / "proj" / "a.txt").read_bytes(), b"a")


if __name__ == "__main__":
    unittest.main()
