"""A folder copy or move never follows a symlinked folder inside it.

Measured before: ``TransferManager._transfer_directory`` recursed into
every entry the listing marked ``is_dir`` -- and SMB lists a symlink to a
folder with ``is_dir=True, is_link=True`` (the stat follows the link). A
MOVE of folder ``A`` holding ``A/L -> B`` (``B`` outside ``A``) moved
``B``'s files out of ``B``; a link to an ancestor recursed until the
stack or the path length gave out.

Such an entry is not descended into. A link inside the copied folder is
made again as a link with the same target (a move moves the link); the
folder it points to is left alone. A link selected on its own is still
refused with a reason. The conflict scan does not descend into it either.
"""

from __future__ import annotations

import dataclasses
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


class _SmbLikeFS(LocalFS):
    """LocalFS with smb_client.list_dir's link contract: a symlinked
    folder is listed with the target's ``is_dir`` and ``is_link=True``."""

    def list_dir(self, path):
        out = []
        for item in super().list_dir(path):
            full = os.path.join(path, item.name)
            if item.is_link and os.path.isdir(full):
                item = dataclasses.replace(item, is_dir=True, is_link=True)
            out.append(item)
        return out


@unittest.skipUnless(os.name == "posix", "POSIX symlinks")
class FolderSymlinkTransferTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from PyQt6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from core.transfer_manager import TransferManager

        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.a = self.tmp / "share" / "A"
        self.b = self.tmp / "share" / "B_other_team"
        self.dst = self.tmp / "dst"
        for d in (self.a, self.b, self.dst):
            d.mkdir(parents=True)
        (self.a / "mine.txt").write_text("mine")
        (self.b / "theirs.txt").write_text("theirs")
        os.symlink(self.b, self.a / "L")
        self.fs = _SmbLikeFS()
        self.mgr = TransferManager()
        self.addCleanup(self.mgr.shutdown)
        self.finished = 0
        self.mgr.all_finished.connect(self._on_all_finished)

    def _on_all_finished(self) -> None:
        self.finished += 1

    def _run(self, move: bool):
        jobs = self.mgr.transfer_files(
            self.fs, LocalFS(), [str(self.a)], str(self.dst), move=move
        )
        deadline = time.monotonic() + 10
        while not self.finished:
            self.app.processEvents()
            if time.monotonic() > deadline:
                self.fail(f"transfer did not finish: {[j.status for j in jobs]}")
            time.sleep(0.01)
        self.app.processEvents()
        return jobs

    def test_happy_a_move_leaves_the_linked_folder_alone(self) -> None:
        jobs = self._run(move=True)
        self.assertEqual(sorted(os.listdir(self.b)), ["theirs.txt"])
        self.assertEqual((self.dst / "A" / "mine.txt").read_text(), "mine")
        self.assertFalse((self.a / "mine.txt").exists())
        # The link moved as the link: same target, nothing copied through it.
        self.assertTrue(os.path.islink(self.dst / "A" / "L"))
        self.assertEqual(os.readlink(self.dst / "A" / "L"), str(self.b))
        self.assertFalse(os.path.lexists(self.a / "L"))
        self.assertEqual([j for j in jobs if j.status is not TransferStatus.DONE], [])

    def test_happy_a_copy_does_not_copy_the_linked_folder(self) -> None:
        jobs = self._run(move=False)
        self.assertEqual((self.dst / "A" / "mine.txt").read_text(), "mine")
        self.assertTrue(os.path.islink(self.dst / "A" / "L"))
        self.assertEqual(os.readlink(self.dst / "A" / "L"), str(self.b))
        self.assertTrue(os.path.islink(self.a / "L"))
        self.assertEqual(
            sorted(Path(j.source_path).name for j in jobs), ["L", "mine.txt"]
        )

    def test_sad_a_link_to_an_ancestor_does_not_recurse(self) -> None:
        os.symlink(self.a, self.a / "loop")
        jobs = self._run(move=False)
        self.assertEqual(
            sorted(Path(j.source_path).name for j in jobs), ["L", "loop", "mine.txt"]
        )
        self.assertEqual(sorted(os.listdir(self.dst / "A")), ["L", "loop", "mine.txt"])
        self.assertTrue(os.path.islink(self.dst / "A" / "loop"))

    def test_edge_a_symlinked_file_is_copied_as_the_link(self) -> None:
        os.symlink(self.b / "theirs.txt", self.a / "file-link")
        self._run(move=False)
        self.assertTrue(os.path.islink(self.dst / "A" / "file-link"))
        self.assertEqual(os.readlink(self.dst / "A" / "file-link"), str(self.b / "theirs.txt"))

    def test_edge_the_conflict_scan_does_not_descend_into_the_link(self) -> None:
        from core.transfer_conflicts import scan_conflicts

        (self.dst / "A" / "L").mkdir(parents=True)
        (self.dst / "A" / "L" / "theirs.txt").write_text("dest")
        (self.dst / "A" / "mine.txt").write_text("dest")
        scan = scan_conflicts(self.fs, LocalFS(), [str(self.a)], str(self.dst))
        self.assertEqual(sorted(c.name for c in scan.conflicts), ["mine.txt"])


@unittest.skipUnless(os.name == "posix", "POSIX symlinks")
class LocalFolderSymlinkTransferTest(FolderSymlinkTransferTest):
    """The same on this machine's disk, where LocalFS lists a link to a
    folder with ``is_dir=False``.

    Measured before (review round 8): the refusal above never fired for
    LocalFS: a link to a folder ended with a raw "[Errno 21] Is a
    directory", a dangling link with "No such file or directory"."""

    def setUp(self) -> None:
        super().setUp()
        self.fs = LocalFS()

    def _copy(self, paths, move=False):
        jobs = self.mgr.transfer_files(self.fs, LocalFS(), [str(p) for p in paths],
                                       str(self.dst), move=move)
        deadline = time.monotonic() + 10
        while self.mgr.unfinished():
            self.app.processEvents()
            if time.monotonic() > deadline:
                self.fail(f"transfer did not finish: {[j.status for j in jobs]}")
            time.sleep(0.01)
        return {Path(j.source_path).name: j for j in jobs}

    def test_sad_links_in_a_folder_are_copied_as_links(self) -> None:
        os.symlink("/nonexistent/x", self.a / "dangling")
        os.symlink("..", self.a / "loop")
        jobs = self._copy([self.a])
        for job in jobs.values():
            self.assertEqual(job.status, TransferStatus.DONE, job.error_message)
        self.assertEqual(os.readlink(self.dst / "A" / "dangling"), "/nonexistent/x")
        self.assertEqual(os.readlink(self.dst / "A" / "loop"), "..")
        self.assertEqual(sorted(os.listdir(self.dst / "A")), ["L", "dangling", "loop", "mine.txt"])

    def test_sad_selected_links_are_skipped_with_a_clear_reason(self) -> None:
        os.symlink("/nonexistent/x", self.a / "dangling")
        jobs = self._copy([self.a / "L", self.a / "dangling"])
        self.assertIn("symbolic link to a folder: not followed", jobs["L"].error_message)
        self.assertIn("dangling symbolic link", jobs["dangling"].error_message)
        self.assertEqual(os.listdir(self.dst), [])

    def test_edge_a_selected_link_moved_is_refused_the_same_way(self) -> None:
        jobs = self._copy([self.a / "L"], move=True)
        self.assertIn("symbolic link to a folder: not followed", jobs["L"].error_message)
        self.assertTrue(os.path.islink(self.a / "L"))
        self.assertEqual(sorted(os.listdir(self.b)), ["theirs.txt"])
        self.assertEqual(os.listdir(self.dst), [])

    def test_edge_the_conflict_scan_does_not_descend_into_the_link(self) -> None:
        from core.transfer_conflicts import scan_conflicts

        (self.dst / "A" / "L").mkdir(parents=True)
        (self.dst / "A" / "L" / "theirs.txt").write_text("dest")
        scan = scan_conflicts(self.fs, LocalFS(), [str(self.a)], str(self.dst))
        self.assertNotIn("theirs.txt", [c.name for c in scan.conflicts])


if __name__ == "__main__":
    unittest.main()
