"""Moving a folder removes the emptied source folders, nested ones included.

Seen live (SFTP -> WebDAV, 2026-10-15): moving ``tree/`` with ``tree/sub/``
moved every file but left ``tree`` behind. ``_transfer_directory`` records
a folder after its subfolders (post-order: sub, tree), and
``_cleanup_move_dirs`` walked that list reversed - the parent first, while
its subfolder still existed, so the parent was "not empty, keeping".
A move of folders that hold no file at all queued no job, so the cleanup
never ran and the "move" was a copy.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.local_fs import LocalFS  # noqa: E402
from core.transfer_worker import TransferStatus  # noqa: E402


class MoveFolderCleanupTest(unittest.TestCase):
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
        self.finished = 0
        self.mgr.all_finished.connect(self._on_all_finished)

    def _on_all_finished(self) -> None:
        self.finished += 1

    def _move(self, name: str):
        jobs = self.mgr.transfer_files(LocalFS(), LocalFS(), [str(self.src / name)],
                                       str(self.dst), move=True)
        deadline = time.monotonic() + 10
        # all_finished fires after the last job's slot ran the cleanup; a
        # move without a single file job has nothing to wait for.
        while jobs and not self.finished:
            self.app.processEvents()
            if time.monotonic() > deadline:
                self.fail(f"move did not finish: {[j.status for j in jobs]}")
            time.sleep(0.01)
        self.app.processEvents()
        return jobs

    def _write(self, rel: str, data: bytes = b"x") -> None:
        path = self.src / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def test_happy_a_nested_tree_is_moved_and_every_source_folder_removed(self) -> None:
        self._write("tree/top.txt", b"top")
        self._write("tree/sub/deep.txt", b"deep")
        jobs = self._move("tree")
        self.assertEqual({j.status for j in jobs}, {TransferStatus.DONE})
        self.assertEqual((self.dst / "tree" / "sub" / "deep.txt").read_bytes(), b"deep")
        self.assertEqual((self.dst / "tree" / "top.txt").read_bytes(), b"top")
        self.assertEqual(os.listdir(self.src), [])

    def test_sad_a_folder_that_still_holds_a_file_is_kept(self) -> None:
        self._write("tree/sub/deep.txt")
        self._write("tree/keep.txt")
        os.chmod(self.src / "tree" / "keep.txt", 0)
        self.addCleanup(os.chmod, self.src / "tree" / "keep.txt", 0o600)
        if os.access(self.src / "tree" / "keep.txt", os.R_OK):
            self.skipTest("running as root: an unreadable file cannot be simulated")
        jobs = self._move("tree")
        self.assertIn(TransferStatus.ERROR, {j.status for j in jobs})
        # The unreadable file stays, so its folder does; the emptied subfolder goes.
        self.assertTrue((self.src / "tree" / "keep.txt").exists())
        self.assertFalse((self.src / "tree" / "sub").exists())

    def test_edge_deep_nesting_and_empty_subfolders(self) -> None:
        self._write("tree/a/b/c/deep.txt", b"deep")
        (self.src / "tree" / "a" / "empty").mkdir()
        (self.src / "tree" / "z-empty").mkdir()
        jobs = self._move("tree")
        self.assertEqual({j.status for j in jobs}, {TransferStatus.DONE})
        self.assertEqual((self.dst / "tree" / "a" / "b" / "c" / "deep.txt").read_bytes(), b"deep")
        self.assertTrue((self.dst / "tree" / "a" / "empty").is_dir())
        self.assertTrue((self.dst / "tree" / "z-empty").is_dir())
        self.assertEqual(os.listdir(self.src), [])

    def test_edge_moving_folders_without_any_file_moves_them(self) -> None:
        (self.src / "tree" / "sub").mkdir(parents=True)
        jobs = self._move("tree")
        self.assertEqual(jobs, [])
        self.assertTrue((self.dst / "tree" / "sub").is_dir())
        self.assertEqual(os.listdir(self.src), [])


if __name__ == "__main__":
    unittest.main()
