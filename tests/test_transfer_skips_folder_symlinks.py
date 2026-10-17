"""A folder copy or move never follows a symlinked folder inside it.

Measured before: ``TransferManager._transfer_directory`` recursed into
every entry the listing marked ``is_dir`` -- and SMB lists a symlink to a
folder with ``is_dir=True, is_link=True`` (the stat follows the link). A
MOVE of folder ``A`` holding ``A/L -> B`` (``B`` outside ``A``) moved
``B``'s files out of ``B``; a link to an ancestor recursed until the
stack or the path length gave out.

Now such an entry is not descended into: it shows as a refused job in the
transfer list, the link stays in the source (so a moved folder that holds
it is kept), and the folder it points to is left alone. The conflict scan
does not descend into it either.
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
        self.assertFalse((self.dst / "A" / "L").exists())
        self.assertTrue(os.path.islink(self.a / "L"), "the link was removed")
        refused = [j for j in jobs if j.status is TransferStatus.ERROR]
        self.assertEqual([Path(j.source_path).name for j in refused], ["L"])
        self.assertIn("symbolic link", refused[0].error_message)

    def test_happy_a_copy_does_not_copy_the_linked_folder(self) -> None:
        jobs = self._run(move=False)
        self.assertEqual((self.dst / "A" / "mine.txt").read_text(), "mine")
        self.assertFalse((self.dst / "A" / "L").exists())
        self.assertEqual(
            sorted(Path(j.source_path).name for j in jobs), ["L", "mine.txt"]
        )

    def test_sad_a_link_to_an_ancestor_does_not_recurse(self) -> None:
        os.symlink(self.a, self.a / "loop")
        jobs = self._run(move=False)
        self.assertEqual(
            sorted(Path(j.source_path).name for j in jobs), ["L", "loop", "mine.txt"]
        )
        self.assertEqual(sorted(os.listdir(self.dst / "A")), ["mine.txt"])

    def test_edge_a_symlinked_file_is_still_copied(self) -> None:
        os.symlink(self.b / "theirs.txt", self.a / "file-link")
        self._run(move=False)
        self.assertEqual((self.dst / "A" / "file-link").read_text(), "theirs")

    def test_edge_the_conflict_scan_does_not_descend_into_the_link(self) -> None:
        from core.transfer_conflicts import scan_conflicts

        (self.dst / "A" / "L").mkdir(parents=True)
        (self.dst / "A" / "L" / "theirs.txt").write_text("dest")
        (self.dst / "A" / "mine.txt").write_text("dest")
        scan = scan_conflicts(self.fs, LocalFS(), [str(self.a)], str(self.dst))
        self.assertEqual(sorted(c.name for c in scan.conflicts), ["mine.txt"])


if __name__ == "__main__":
    unittest.main()
