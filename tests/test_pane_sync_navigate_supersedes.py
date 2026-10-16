"""A synchronous navigate() supersedes a background load still running.

Seen as a flaky test: a new pane started its first listing in the
background, the test then called navigate(b) and saw b — until the late
background result arrived and the pane showed the old folder again, with
nothing in it named like b's files. navigate_async() already dropped a
superseded load's result; navigate() did not.
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

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


class SyncNavigateSupersedesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from core.local_fs import LocalFS

        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.slow = self.tmp / "slow"
        self.fast = self.tmp / "fast"
        self.slow.mkdir()
        self.fast.mkdir()
        (self.slow / "old.txt").write_text("x")
        (self.fast / "new.txt").write_text("y")
        self.gate = threading.Event()
        self.addCleanup(self.gate.set)
        slow = str(self.slow)
        gate = self.gate

        class GatedFS(LocalFS):
            def list_dir(self, path):
                if path == slow:
                    gate.wait(10)
                return super().list_dir(path)

        self.backend = GatedFS()

    def pump(self, seconds: float) -> None:
        end = time.time() + seconds
        while time.time() < end:
            self.app.processEvents()
            time.sleep(0.01)

    def names(self, pane) -> set[str]:
        proxy = pane._table.model()
        return {proxy.index(r, 0).data() for r in range(proxy.rowCount())}

    def make_pane(self):
        from ui.file_pane import FilePaneWidget

        pane = FilePaneWidget(self.backend)
        self.addCleanup(pane.deleteLater)
        pane.navigate(str(self.fast))
        return pane

    def test_happy_a_late_background_result_does_not_replace_navigate(self) -> None:
        pane = self.make_pane()
        pane.navigate_async(str(self.slow))
        pane.navigate(str(self.fast))
        self.gate.set()
        self.pump(0.8)
        self.assertEqual(pane.current_path, str(self.fast))
        self.assertIn("new.txt", self.names(pane))
        self.assertNotIn("old.txt", self.names(pane))
        self.assertFalse(pane.is_loading)

    def test_sad_a_failed_navigate_still_drops_the_background_load(self) -> None:
        pane = self.make_pane()
        pane.navigate_async(str(self.slow))
        pane.navigate(str(self.tmp / "missing"))
        self.gate.set()
        self.pump(0.8)
        self.assertEqual(pane.current_path, str(self.fast))
        self.assertNotIn("old.txt", self.names(pane))

    def test_edge_navigate_without_a_running_load_is_unchanged(self) -> None:
        pane = self.make_pane()
        self.gate.set()
        pane.navigate(str(self.slow))
        self.assertEqual(pane.current_path, str(self.slow))
        self.assertIn("old.txt", self.names(pane))


if __name__ == "__main__":
    unittest.main()
