"""Calculate Size runs off the UI thread: the window never stands still.

It walked the whole tree recursively in the UI thread, so a large folder
froze the application until the walk ended. Now the walk is a background
job (ui.scan_job.ScanJob over core.tree_size): the action returns at once,
the status line shows the progress, Cancel stops it, and the result comes
as a table (ui.dir_size_dialog) when the walk is done.
"""

from __future__ import annotations

import os
import sys
import time
import unittest
from pathlib import Path

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

    def dialog(self):
        return getattr(self.pane, "_size_dialog", None)

    def test_happy_the_action_returns_at_once_and_reports_when_done(self) -> None:
        self.select("b")
        gate = self.fs.hold(str(self.root / "b"))
        start = time.time()
        self.pane._calculate_dir_size()
        self.assertLess(time.time() - start, 0.5)  # the walk is still blocked
        self.app.processEvents()
        self.assertTrue(self.pane._size_job.running)
        self.assertIsNone(self.dialog())
        gate.set()
        self.assertTrue(self.wait(lambda: self.dialog() is not None))
        self.assertEqual(self.dialog().displayed_rows()[0][:2], ("b", "6 B"))
        self.dialog().close()
        self.assertFalse(self.pane._cancel_size_btn.isVisible())

    def test_sad_cancel_stops_the_walk_and_shows_no_result(self) -> None:
        self.select("b")
        gate = self.fs.hold(str(self.root / "b"))
        self.pane._calculate_dir_size()
        self.app.processEvents()
        self.assertTrue(self.pane._cancel_size_btn.isVisible())
        self.pane._cancel_size_btn.click()
        gate.set()
        self.assertTrue(self.wait(lambda: not self.pane._size_job.running))
        self.app.processEvents()
        self.assertIsNone(self.dialog())
        self.assertIn("cancelled", self.pane._status.text().lower())

    def test_edge_closing_the_pane_drops_a_running_walk(self) -> None:
        self.select("b")
        gate = self.fs.hold(str(self.root / "b"))
        self.pane._calculate_dir_size()
        self.pane.shutdown()
        gate.set()
        time.sleep(0.2)
        for _ in range(20):
            self.app.processEvents()
        self.assertIsNone(self.dialog())

    def test_edge_unreadable_folders_are_named_in_the_result(self) -> None:
        self.select("b")
        self.fs.fail[str(self.root / "b")] = PermissionError(13, "Permission denied")
        self.pane._calculate_dir_size()
        self.assertTrue(self.wait(lambda: self.dialog() is not None))
        self.assertIn("1 folder could not be read", self.dialog().displayed_rows()[0][5])
        self.dialog().close()


    def test_happy_e2e_hidden_entries_count_although_the_pane_hides_them(self) -> None:
        """Operator item 30: "wenn dir calc size machen rechnen wir dann auch
        hidden files mit ein?" - yes. The pane hides dotfiles (Show Hidden
        Files off), the right-click entry still counts every one of them, like du."""
        (self.root / "b" / ".hidden").write_bytes(b"x" * 100)
        (self.root / "b" / ".dot").mkdir()
        (self.root / "b" / ".dot" / "inner.bin").write_bytes(b"x" * 1000)
        self.pane.set_show_hidden(False)
        self.pane.refresh()
        self.assertTrue(self.settle())
        self.select("b")
        menu = self.pane._build_context_menu()
        entry = next(a for a in menu.actions() if a.property("axCommand") == "calculate-size")
        entry.trigger()
        self.assertTrue(self.wait(lambda: self.dialog() is not None))
        name, size, files, folders = self.dialog().displayed_rows()[0][:4]
        self.assertEqual((name, files, folders), ("b", "3", "1"))  # .dot is the folder inside
        self.assertEqual(self.dialog().model.rows()[0].bytes, 6 + 100 + 1000)
        self.dialog().close()


if __name__ == "__main__":
    unittest.main()
