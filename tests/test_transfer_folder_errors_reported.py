"""What a folder copy leaves out shows up in the transfer list.

Measured before: F5 of a folder holding an unreadable subfolder created
the subfolder empty at the destination, copied the rest and reported
nothing - TransferManager.directory_error had no receiver in the GUI.
Each folder that cannot be listed or created is now a failed row (a job
that never runs), like a refused symlinked folder already was.
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


class _Base(unittest.TestCase):
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
        self.addCleanup(self.mgr.shutdown)
        self.added: list = []
        self.errors: list[tuple[str, str]] = []
        self.dir_errors: list[tuple[str, str]] = []
        self.mgr.job_added.connect(self.added.append)
        self.mgr.job_error.connect(lambda jid, msg: self.errors.append((jid, msg)))
        self.mgr.directory_error.connect(lambda p, msg: self.dir_errors.append((p, msg)))
        (self.tmp / "dst").mkdir()

    def _wait(self, jobs) -> None:
        deadline = time.monotonic() + 10
        while any(j.status in (TransferStatus.PENDING, TransferStatus.ACTIVE) for j in jobs):
            self.app.processEvents()
            if time.monotonic() > deadline:
                self.fail("transfer did not finish")
            time.sleep(0.01)
        self.app.processEvents()


@unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root reads every folder")
class UnreadableFolderTest(_Base):
    def setUp(self) -> None:
        super().setUp()
        self.src = self.tmp / "photos"
        (self.src / "2024").mkdir(parents=True)
        (self.src / "a.jpg").write_bytes(b"a")
        (self.src / "2024" / "b.jpg").write_bytes(b"b")
        os.chmod(self.src / "2024", 0)
        self.addCleanup(os.chmod, self.src / "2024", 0o755)

    def test_sad_an_unreadable_subfolder_is_a_failed_row(self) -> None:
        jobs = self.mgr.transfer_files(LocalFS(), LocalFS(), [str(self.src)],
                                       str(self.tmp / "dst"))
        self._wait(jobs)
        failed = [j for j in jobs if j.status == TransferStatus.ERROR]
        self.assertEqual([j.source_path for j in failed], [str(self.src / "2024")])
        self.assertIn("cannot read the folder", failed[0].error_message)
        self.assertIn(failed[0], self.added)
        self.assertIn(failed[0].job_id, [e[0] for e in self.errors])
        self.assertEqual([p for p, _ in self.dir_errors], [str(self.src / "2024")])
        done = [j.filename for j in jobs if j.status == TransferStatus.DONE]
        self.assertEqual(done, ["a.jpg"])

    def test_edge_a_move_keeps_the_folder_it_could_not_read(self) -> None:
        jobs = self.mgr.transfer_files(LocalFS(), LocalFS(), [str(self.src)],
                                       str(self.tmp / "dst"), move=True)
        self._wait(jobs)
        os.chmod(self.src / "2024", 0o755)
        self.assertEqual((self.src / "2024" / "b.jpg").read_bytes(), b"b")
        self.assertFalse((self.src / "a.jpg").exists())


class UncreatableFolderTest(_Base):
    def test_sad_a_destination_folder_that_cannot_be_made_is_a_failed_row(self) -> None:
        src = self.tmp / "docs"
        (src / "sub").mkdir(parents=True)
        (src / "sub" / "f.txt").write_bytes(b"f")
        (self.tmp / "dst" / "docs").mkdir()
        (self.tmp / "dst" / "docs" / "sub").write_bytes(b"a file where the folder goes")
        jobs = self.mgr.transfer_files(LocalFS(), LocalFS(), [str(src)], str(self.tmp / "dst"))
        self._wait(jobs)
        self.assertEqual([j.status for j in jobs], [TransferStatus.ERROR])
        self.assertEqual(jobs[0].dest_path, str(self.tmp / "dst" / "docs" / "sub"))
        self.assertIn("cannot create the folder", jobs[0].error_message)

    def test_happy_a_readable_tree_has_no_failed_row(self) -> None:
        src = self.tmp / "docs"
        (src / "sub").mkdir(parents=True)
        (src / "sub" / "f.txt").write_bytes(b"f")
        jobs = self.mgr.transfer_files(LocalFS(), LocalFS(), [str(src)], str(self.tmp / "dst"))
        self._wait(jobs)
        self.assertEqual([j.status for j in jobs], [TransferStatus.DONE])
        self.assertEqual(self.errors, [])


if __name__ == "__main__":
    unittest.main()
