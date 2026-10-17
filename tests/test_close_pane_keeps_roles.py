"""Closing a pane that is neither source nor target leaves both roles alone.

``_close_pane`` ended with
``_set_active_pane(self._panes[0])`` whatever pane was closed. With panes
A, B, C, C active (source) and B the target, closing A made B the source
and C the target - F5 / F6 then copied and moved the other way round.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


class ClosePaneRolesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from ui import main_window as MW

        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home, ignore_errors=True)
        with mock.patch("pathlib.Path.home", return_value=Path(home)):
            self.win = MW.MainWindow()
        self.addCleanup(self.win.deleteLater)
        self.addCleanup(self.win.close)
        self.win._add_local_pane()
        self.win._add_local_pane()
        self.a, self.b, self.c = self.win._panes
        self.win._set_active_pane(self.b)
        self.win._set_active_pane(self.c)  # C is the source, B the target

    def test_happy_closing_an_uninvolved_pane_keeps_source_and_target(self) -> None:
        self.win._close_pane(self.a)
        self.assertIs(self.win._active_pane, self.c)
        self.assertIs(self.win._target_pane, self.b)

    def test_sad_closing_the_source_picks_a_new_source_that_is_not_the_target(self) -> None:
        self.win._close_pane(self.c)
        self.assertIn(self.win._active_pane, (self.a, self.b))
        self.assertIsNotNone(self.win._target_pane)
        self.assertIsNot(self.win._active_pane, self.win._target_pane)

    def test_edge_closing_the_target_keeps_the_source_and_finds_a_new_target(self) -> None:
        self.win._close_pane(self.b)
        self.assertIs(self.win._active_pane, self.c)
        self.assertIs(self.win._target_pane, self.a)


if __name__ == "__main__":
    unittest.main()
