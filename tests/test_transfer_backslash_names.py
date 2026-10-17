"""A backslash is an ordinary character in a POSIX file name.

Measured before: ``C:\\Users\\me\\notes.txt`` (legal on Linux/macOS)
was dropped from a folder copy with a log line only; selected alone, F5
sent nothing. The name check refused a backslash everywhere because on a
backend with backslash paths it is a separator. It is now allowed where
the backend treats it literally (LocalFS on POSIX) and still refused
everywhere else; whatever is still left out shows up as a failed row.
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
from core.path_policy import BackendPathPolicy, safe_join  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402
from core.remote_name import RemoteNameError, validate_remote_name  # noqa: E402
from core.transfer_worker import TransferStatus  # noqa: E402

POSIX = os.sep == "/"
NAME = "C:\\Users\\me\\notes.txt"


class _BackslashSession:
    """A backend whose paths use backslashes (WinRM, LocalFS on Windows)."""

    def separator(self) -> str:
        return "\\"


class PolicyTest(unittest.TestCase):
    @unittest.skipUnless(POSIX, "POSIX file names")
    def test_happy_localfs_joins_a_name_with_a_backslash(self) -> None:
        self.assertEqual(safe_join(LocalFS(), "/d", NAME), "/d/" + NAME)

    def test_sad_a_backslash_backend_still_refuses_it(self) -> None:
        with self.assertRaises(ValueError):
            safe_join(_BackslashSession(), "C:\\d", "..\\..\\x")

    def test_sad_a_remote_slash_backend_still_refuses_it(self) -> None:
        """A server may treat it as a separator (SMB, a Windows SFTP server)."""
        with self.assertRaises(ValueError):
            safe_join(RamFsSession(), "/d", "..\\x")

    def test_edge_the_plain_validator_is_unchanged(self) -> None:
        with self.assertRaises(RemoteNameError):
            validate_remote_name(NAME)
        validate_remote_name(NAME, allow_backslash=True)
        with self.assertRaises(RemoteNameError):
            validate_remote_name("a/b", allow_backslash=True)
        with self.assertRaises(RemoteNameError):
            validate_remote_name("..", allow_backslash=True)

    @unittest.skipUnless(POSIX, "POSIX file names")
    def test_edge_control_characters_stay_refused_on_localfs(self) -> None:
        with self.assertRaises(ValueError):
            BackendPathPolicy.for_backend(LocalFS()).validate_leaf("bad\x1bname")


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
        self.src = self.tmp / "docs"
        self.src.mkdir()
        (self.tmp / "dst").mkdir()
        (self.src / "plan.txt").write_bytes(b"p")

    def _wait(self, jobs) -> None:
        deadline = time.monotonic() + 10
        while any(j.status in (TransferStatus.PENDING, TransferStatus.ACTIVE) for j in jobs):
            self.app.processEvents()
            if time.monotonic() > deadline:
                self.fail("transfer did not finish")
            time.sleep(0.01)


@unittest.skipUnless(POSIX, "POSIX file names")
class FolderCopyTest(_Base):
    def test_happy_a_folder_copy_includes_a_backslash_name(self) -> None:
        from core.transfer_conflicts import ConflictPlan, scan_conflicts

        (self.src / NAME).write_bytes(b"n")
        fs = LocalFS()
        plan = ConflictPlan(fs, scan_conflicts(fs, fs, [str(self.src)], str(self.tmp / "dst")))
        jobs = self.mgr.transfer_files(fs, fs, [str(self.src)], str(self.tmp / "dst"),
                                       conflict_plan=plan)
        self._wait(jobs)
        self.assertEqual(sorted(os.listdir(self.tmp / "dst" / "docs")), [NAME, "plan.txt"])

    def test_happy_a_selected_backslash_name_is_copied(self) -> None:
        (self.src / NAME).write_bytes(b"n")
        jobs = self.mgr.transfer_files(LocalFS(), LocalFS(), [str(self.src / NAME)],
                                       str(self.tmp / "dst"))
        self._wait(jobs)
        self.assertEqual((self.tmp / "dst" / NAME).read_bytes(), b"n")

    def test_sad_a_name_still_refused_is_a_failed_row_not_a_silent_gap(self) -> None:
        (self.src / "bad\x1bname").write_bytes(b"b")
        jobs = self.mgr.transfer_files(LocalFS(), LocalFS(), [str(self.src)],
                                       str(self.tmp / "dst"))
        self._wait(jobs)
        failed = [j for j in jobs if j.status == TransferStatus.ERROR]
        self.assertEqual(len(failed), 1)
        self.assertIn("not copied", failed[0].error_message)
        self.assertEqual(failed[0].dest_path, "")
        self.assertIsNone(self.mgr.retry_job(failed[0].job_id))
        self.assertEqual(os.listdir(self.tmp / "dst" / "docs"), ["plan.txt"])

    def test_edge_a_refused_top_level_name_is_a_failed_row(self) -> None:
        (self.src / "bad\x1bname").write_bytes(b"b")
        jobs = self.mgr.transfer_files(LocalFS(), LocalFS(), [str(self.src / "bad\x1bname")],
                                       str(self.tmp / "dst"))
        self._wait(jobs)
        self.assertEqual([j.status for j in jobs], [TransferStatus.ERROR])
        self.assertEqual(os.listdir(self.tmp / "dst"), [])


@unittest.skipUnless(POSIX, "POSIX file names")
class PaneSelectionTest(_Base):
    def test_happy_the_pane_sends_a_selected_backslash_name(self) -> None:
        from ui.file_pane import FilePaneWidget

        (self.src / NAME).write_bytes(b"n")
        pane = FilePaneWidget(LocalFS())
        self.addCleanup(pane.shutdown)
        pane.navigate(str(self.src))
        pane._table.selectAll()
        self.assertEqual(sorted(os.path.basename(p) for p in pane.selected_items()),
                         [NAME, "plan.txt"])

    def test_sad_the_pane_says_when_it_leaves_a_selected_name_out(self) -> None:
        from ui.file_pane import FilePaneWidget

        (self.src / "bad\x1bname").write_bytes(b"b")
        pane = FilePaneWidget(LocalFS())
        self.addCleanup(pane.shutdown)
        pane.navigate(str(self.src))
        pane._table.selectAll()
        self.assertEqual([os.path.basename(p) for p in pane.selected_items()], ["plan.txt"])
        self.assertIn("left out", pane._status.text())


if __name__ == "__main__":
    unittest.main()
