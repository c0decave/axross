"""A moved folder whose failed file is retried successfully is removed too.

Measured before: moving ``tree/`` with one file that could not be moved
(its source could not be removed, the copy failed, ...) kept ``tree/`` -
correct, it still held that file. The cleanup list was cleared all the
same, so after "Retry Failed" moved the file, the emptied ``tree/`` stayed
behind for good and the move looked like a copy of the folder.

Now the cleanup remembers the folders it had to keep, and retrying a
failed move job puts the ones above its source back on the cleanup list.
"""

from __future__ import annotations

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
from core.transfer_worker import TransferStatus  # noqa: E402


class _RefuseRemove(LocalFS):
    """Removing a file named *name* fails the first *times* times."""

    def __init__(self, name: str, times: int = 1) -> None:
        self.name_to_refuse = name
        self.times = times

    def remove(self, path, recursive=False):
        if os.path.basename(path) == self.name_to_refuse and self.times:
            self.times -= 1
            raise PermissionError(13, "Permission denied", path)
        return super().remove(path, recursive)


class MoveRetryCleanupTest(unittest.TestCase):
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
        self.mgr = TransferManager()
        self.addCleanup(self.mgr.shutdown)

    def _write(self, rel: str, data: bytes = b"x") -> None:
        path = self.src / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def wait(self) -> None:
        end = time.monotonic() + 10
        while any(j.status in (TransferStatus.PENDING, TransferStatus.ACTIVE)
                  for j in self.mgr.all_jobs()):
            self.app.processEvents()
            if time.monotonic() > end:
                self.fail("jobs did not finish")
            time.sleep(0.005)
        for _ in range(5):
            self.app.processEvents()

    def _move(self, fs, name: str, move: bool = True):
        jobs = self.mgr.transfer_files(fs, LocalFS(), [str(self.src / name)], str(self.dst),
                                       move=move)
        self.wait()
        return jobs

    def _retry_failed(self) -> list:
        failed = [j for j in self.mgr.all_jobs() if j.status == TransferStatus.ERROR]
        new = [self.mgr.retry_job(j.job_id) for j in failed]
        self.wait()
        return [j for j in new if j is not None]

    def test_happy_retry_failed_in_the_dock_removes_the_emptied_folders(self) -> None:
        """e2e: the real dock's Retry Failed button after a partly failed move."""
        from PyQt6.QtCore import Qt
        from PyQt6.QtTest import QTest

        from ui.transfer_dock import TransferDock

        dock = TransferDock(self.mgr)
        self.addCleanup(dock.deleteLater)
        self._write("tree/a.txt", b"a")
        self._write("tree/sub/b.txt", b"b")
        jobs = self._move(_RefuseRemove("b.txt"), "tree")
        self.assertEqual(sorted(j.status.name for j in jobs), ["DONE", "ERROR"])
        self.assertTrue((self.src / "tree" / "sub" / "b.txt").exists())
        QTest.mouseClick(dock._btn_retry, Qt.MouseButton.LeftButton)
        self.wait()
        self.assertFalse((self.src / "tree").exists())
        self.assertEqual((self.dst / "tree" / "sub" / "b.txt").read_bytes(), b"b")
        self.assertEqual((self.dst / "tree" / "a.txt").read_bytes(), b"a")

    def test_sad_a_retry_that_fails_again_keeps_the_folder_until_one_succeeds(self) -> None:
        self._write("tree/a.txt")
        self._write("tree/b.txt")
        self._move(_RefuseRemove("b.txt", times=2), "tree")
        [again] = self._retry_failed()
        self.assertEqual(again.status, TransferStatus.ERROR)
        self.assertTrue((self.src / "tree" / "b.txt").exists())
        [done] = self._retry_failed()
        self.assertEqual(done.status, TransferStatus.DONE)
        self.assertFalse((self.src / "tree").exists())

    def test_edge_two_failed_files_in_one_folder_both_retried(self) -> None:
        self._write("tree/a.txt")
        self._write("tree/b.txt")
        self._write("tree/c.txt")

        class _RefuseTwo(LocalFS):
            refused: set = set()

            def remove(self, path, recursive=False):
                name = os.path.basename(path)
                if name in ("b.txt", "c.txt") and name not in self.refused:
                    self.refused.add(name)
                    raise PermissionError(13, "Permission denied", path)
                return super().remove(path, recursive)

        self._move(_RefuseTwo(), "tree")
        self.assertEqual(len(self._retry_failed()), 2)
        self.assertFalse((self.src / "tree").exists())
        self.assertEqual(self.mgr._kept_move_dirs, [])  # nothing left to remember

    def test_edge_a_retried_copy_removes_no_folder(self) -> None:
        self._write("tree/a.txt")

        class _FailWriteOnce(LocalFS):
            fails = 1

            def open_write(self, path, append=False):
                if _FailWriteOnce.fails:
                    _FailWriteOnce.fails -= 1
                    raise OSError(5, "I/O error", path)
                return super().open_write(path, append)

        jobs = self.mgr.transfer_files(LocalFS(), _FailWriteOnce(), [str(self.src / "tree")],
                                       str(self.dst))
        self.wait()
        self.assertEqual([j.status for j in jobs], [TransferStatus.ERROR])
        [retry] = self._retry_failed()
        self.assertEqual(retry.status, TransferStatus.DONE)
        self.assertTrue((self.src / "tree" / "a.txt").exists())

    def test_edge_clear_finished_forgets_the_kept_folders(self) -> None:
        self._write("tree/a.txt")
        self._write("tree/b.txt")
        self._move(_RefuseRemove("b.txt"), "tree")
        self.mgr.clear_finished()
        # The user moves the last file out by hand; a later, unrelated
        # move must not remove a folder of a transfer nobody can retry.
        os.remove(self.src / "tree" / "b.txt")
        self._write("other.txt")
        self._move(LocalFS(), "other.txt")
        self.assertTrue((self.src / "tree").is_dir())


if __name__ == "__main__":
    unittest.main()
