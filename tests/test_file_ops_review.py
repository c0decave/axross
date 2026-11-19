"""File operations review (2026-11-19): copy, move, rename, delete end to end.

Each class names what was measured before its fix.
"""

from __future__ import annotations

import os
import shutil
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.local_fs import LocalFS  # noqa: E402
from core.transfer_worker import TransferStatus  # noqa: E402


class _Manager(unittest.TestCase):
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
        self.manager = TransferManager()
        self.addCleanup(self.manager.shutdown)

    def run_jobs(self, paths, *, move: bool = False, backend=None) -> list:
        backend = backend or LocalFS()
        jobs = self.manager.transfer_files(
            LocalFS(), backend, [str(p) for p in paths], str(self.dst), move=move)
        end = time.time() + 20
        while time.time() < end:
            self.app.processEvents()
            if all(j.status not in (TransferStatus.PENDING, TransferStatus.ACTIVE)
                   for j in jobs):
                break
            time.sleep(0.01)
        return jobs


class PrivateFolderStaysPrivateTest(_Manager):
    """Measured before: a copy kept each file's mode (a 0600 key stayed
    0600), but every folder it made got the default mode - a 0700 folder
    arrived as 0755, and the 0644 files in it, readable only to the owner
    through the private folder before, were readable to everyone there.
    Now a folder made by a copy or move gets no group/other right its
    source folder lacks (the owner keeps full rights, as the copy needs)."""

    def test_sad_a_private_folder_and_its_private_subfolder_stay_private(self) -> None:
        folder = self.src / "private"
        (folder / "inner").mkdir(parents=True)
        (folder / "inner" / "notes.txt").write_text("mine")
        (folder / "top.txt").write_text("top")
        os.chmod(folder / "inner", 0o700)
        os.chmod(folder, 0o750)
        for move in (False, True):
            with self.subTest(move=move):
                shutil.rmtree(self.dst / "private", ignore_errors=True)
                jobs = self.run_jobs([folder], move=move)
                self.assertTrue(all(j.status == TransferStatus.DONE for j in jobs),
                                [(j.status, j.error_message) for j in jobs])
                copied = self.dst / "private"
                self.assertEqual((copied / "inner" / "notes.txt").read_text(), "mine")
                self.assertEqual(stat.S_IMODE(os.stat(copied).st_mode) & 0o077, 0o050)
                self.assertEqual(stat.S_IMODE(os.stat(copied / "inner").st_mode) & 0o077, 0)
                self.assertEqual(stat.S_IMODE(os.stat(copied).st_mode) & 0o700, 0o700)
                if move:
                    self.assertFalse(folder.exists())

    def test_edge_a_read_only_folder_still_receives_its_files(self) -> None:
        folder = self.src / "ro"
        folder.mkdir()
        (folder / "a.txt").write_text("a")
        os.chmod(folder, 0o555)
        self.addCleanup(os.chmod, folder, 0o755)
        jobs = self.run_jobs([folder])
        self.assertTrue(all(j.status == TransferStatus.DONE for j in jobs),
                        [(j.status, j.error_message) for j in jobs])
        self.assertEqual((self.dst / "ro" / "a.txt").read_text(), "a")

    def test_happy_an_ordinary_folder_is_not_touched(self) -> None:
        folder = self.src / "plain"
        folder.mkdir()
        (folder / "a.txt").write_text("a")
        os.chmod(folder, 0o755)
        calls = []
        backend = LocalFS()
        real = backend.chmod
        backend.chmod = lambda p, m: (calls.append((p, m)), real(p, m))[1]
        self.run_jobs([folder], backend=backend)
        self.assertEqual([c for c in calls if c[0] == str(self.dst / "plain")], [])
        self.assertEqual((self.dst / "plain" / "a.txt").read_text(), "a")


def _window_harness():
    from test_transfer_conflict_window import _Window

    return _Window


class FolderIntoItselfAskedFirstTest(_window_harness()):
    """Measured before: F5 / F6 / drag & drop of a folder into a folder
    below it queued the job, which failed as "0 copied, 1 failed" with the
    reason only in the transfer row (Paste said why at once and queued
    nothing). Now every route refuses it before anything is checked or
    queued and says why, as Paste does."""

    def setUp(self) -> None:
        super().setUp()
        self.addCleanup(lambda: setattr(self.win, "_quit_with_transfers", True))
        (self.a / "d" / "sub").mkdir(parents=True)
        (self.a / "d" / "f.txt").write_text("f")
        (self.a / "other.txt").write_text("o")
        self.right.navigate(str(self.a / "d" / "sub"))
        self.assertTrue(self.wait_for(
            lambda: self.right.current_path == str(self.a / "d" / "sub")))

    def check(self, run, word: str) -> None:
        from unittest import mock

        self.answer()
        with mock.patch("ui.main_window.QMessageBox.warning") as warn:
            run()
            self.settle()
        self.assertEqual(self.win._transfer_manager.all_jobs(), [])
        warn.assert_called_once()
        self.assertIn(word, warn.call_args[0][2])
        self.assertIn("into itself", warn.call_args[0][2])
        self.assertEqual(sorted(os.listdir(self.a / "d" / "sub")), [])
        self.assertEqual((self.a / "d" / "f.txt").read_text(), "f")
        self.assertTrue((self.a / "other.txt").exists())

    def test_sad_f5_says_why_and_copies_nothing(self) -> None:
        self.check(lambda: self.copy("d", "other.txt"), "copied")

    def test_sad_f6_says_why_and_moves_nothing(self) -> None:
        self.check(lambda: self.move("d", "other.txt"), "moved")

    def test_sad_a_drop_onto_its_own_folder_says_why(self) -> None:
        self.check(lambda: self.win._on_drop_transfer(
            [str(self.a / "d")], self.left, str(id(self.left)), True, str(self.a / "d")),
            "moved")


class CopyThroughLinkedFolderTest(_window_harness()):
    """Measured before: with the target pane in a symlink to the source
    folder (``b/alias -> a``), F5 asked "Overwrite f.txt?" for the file
    itself and ended "0 copied, 1 failed". The folder check compared the
    link itself, not the folder it leads to. Now it is the same folder."""

    def test_sad_f5_into_a_link_to_the_same_folder_copies_nothing_and_says_so(self) -> None:
        self.addCleanup(lambda: setattr(self.win, "_quit_with_transfers", True))
        (self.a / "f.txt").write_text("mine")
        os.symlink(self.a, self.b / "alias")
        self.right.navigate(str(self.b / "alias"))
        self.assertTrue(self.wait_for(lambda: self.right.current_path == str(self.b / "alias")))
        self.answer()
        self.copy("f.txt")
        self.assertEqual(self.asked, [])
        self.assertEqual(self.win._transfer_manager.all_jobs(), [])
        self.assertEqual((self.a / "f.txt").read_text(), "mine")
        self.assertIn("same folder", self.win.statusBar().currentMessage())


if __name__ == "__main__":
    unittest.main()


class FullDiskPartialNotClaimedTest(unittest.TestCase):
    """Measured before: a move into a folder whose disk filled up removed
    its partial file (as the handbook says), yet the status bar ended "1
    moved, 1 failed – partly transferred files are kept for Retry Failed;
    Clear Finished deletes them". partial_kept now leaves out what the
    worker removed: a full destination, a source a resume cannot read from
    an offset."""

    def job(self, error):
        import errno

        from core.transfer_worker import TransferJob

        return TransferJob(
            source_path="/src/big", dest_path="/dst/big", total_bytes=10,
            transferred_bytes=5, status=TransferStatus.ERROR,
            error=error, error_message=str(error), source_backend=LocalFS(),
            dest_backend=LocalFS(), temp_path="/dst/.big.part-1-2", use_temp_file=True,
        ) if error is not None else None

    def test_sad_a_full_disk_keeps_no_partial(self) -> None:
        import errno

        from core.transfer_manager import TransferManager

        full = self.job(OSError(errno.ENOSPC, "No space left on device"))
        self.assertEqual(TransferManager.partial_kept(full), "")

    def test_happy_another_failure_keeps_it_for_retry(self) -> None:
        from core.transfer_manager import TransferManager

        dropped = self.job(OSError("connection dropped"))
        self.assertEqual(TransferManager.partial_kept(dropped), "/dst/.big.part-1-2")
