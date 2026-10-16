"""Calculate Size runs off the UI thread: the window never stands still.

It walked the whole tree recursively in the UI thread, so a large folder
froze the application until the walk ended. Now the walk is a background
job (ui.scan_job.ScanJob over core.tree_size): the action returns at once,
the status line shows the progress, Cancel stops it, and the result comes
as a message when the walk is done.
"""

from __future__ import annotations

import os
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from tests.test_pane_stale_targets import _Base  # noqa: E402


class DirSizeInBackgroundTest(_Base):
    def wait(self, predicate, timeout=5.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            self.app.processEvents()
            if predicate():
                return True
            time.sleep(0.005)
        return False

    def test_happy_the_action_returns_at_once_and_reports_when_done(self) -> None:
        self.select("b")
        gate = self.fs.hold(str(self.root / "b"))
        with mock.patch("ui.file_pane.QMessageBox.information") as info:
            start = time.time()
            self.pane._calculate_dir_size()
            self.assertLess(time.time() - start, 0.5)  # the walk is still blocked
            self.app.processEvents()
            self.assertTrue(self.pane._size_job.running)
            info.assert_not_called()
            gate.set()
            self.assertTrue(self.wait(lambda: info.called))
        self.assertEqual(info.call_args[0][2], "b: 6 B")
        self.assertFalse(self.pane._cancel_size_btn.isVisible())

    def test_sad_cancel_stops_the_walk_and_shows_no_result(self) -> None:
        self.select("b")
        gate = self.fs.hold(str(self.root / "b"))
        with mock.patch("ui.file_pane.QMessageBox.information") as info:
            self.pane._calculate_dir_size()
            self.app.processEvents()
            self.assertTrue(self.pane._cancel_size_btn.isVisible())
            self.pane._cancel_size_btn.click()
            gate.set()
            self.assertTrue(self.wait(lambda: not self.pane._size_job.running))
            self.app.processEvents()
            info.assert_not_called()
        self.assertIn("cancelled", self.pane._status.text().lower())

    def test_edge_closing_the_pane_drops_a_running_walk(self) -> None:
        self.select("b")
        gate = self.fs.hold(str(self.root / "b"))
        with mock.patch("ui.file_pane.QMessageBox.information") as info:
            self.pane._calculate_dir_size()
            self.pane.shutdown()
            gate.set()
            time.sleep(0.2)
            for _ in range(20):
                self.app.processEvents()
            info.assert_not_called()

    def test_edge_unreadable_folders_are_named_in_the_result(self) -> None:
        self.select("b")
        self.fs.fail[str(self.root / "b")] = PermissionError(13, "Permission denied")
        with mock.patch("ui.file_pane.QMessageBox.information") as info:
            self.pane._calculate_dir_size()
            self.assertTrue(self.wait(lambda: info.called))
        self.assertIn("1 folder could not be read", info.call_args[0][2])


if __name__ == "__main__":
    unittest.main()
