"""Pane role / header styles are only re-applied when they change.

Measured before: every click (pane_focused) re-applied three stylesheets to
every pane, ~10 ms per click with two panes, growing with the pane count.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


class StyleCacheTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from core.local_fs import LocalFS
        from ui.file_pane import FilePaneWidget

        with mock.patch.object(FilePaneWidget, "navigate", lambda *a, **k: None):
            self.pane = FilePaneWidget(LocalFS())
        self.addCleanup(self.pane.deleteLater)

    def test_happy_the_same_role_twice_sets_the_sheet_once(self) -> None:
        self.pane.set_pane_role("source", "dark")
        with mock.patch.object(type(self.pane._border_frame), "setStyleSheet") as css:
            self.pane.set_pane_role("source", "dark")
        css.assert_not_called()

    def test_happy_a_role_change_still_applies(self) -> None:
        self.pane.set_pane_role("source", "dark")
        self.pane.set_pane_role("target", "dark")
        self.assertIn("#58a55c", self.pane._border_frame.styleSheet())
        self.assertIn("#58a55c", self.pane._role_label.styleSheet())
        self.assertEqual(self.pane._role_label.text(), "TARGET")

    def test_edge_a_theme_change_updates_the_header(self) -> None:
        self.pane.update_header_color("default")
        before = self.pane._header_label.styleSheet()
        self.pane.update_header_color("dark")
        self.assertNotEqual(self.pane._header_label.styleSheet(), before)
        self.pane.update_header_color("default")
        self.assertEqual(self.pane._header_label.styleSheet(), before)

    def test_edge_no_role_hides_the_badge(self) -> None:
        self.pane.set_pane_role("source", "dark")
        self.pane.set_pane_role("", "dark")
        self.assertTrue(self.pane._role_label.isHidden())
        self.assertIn("#555555", self.pane._border_frame.styleSheet())


if __name__ == "__main__":
    unittest.main()
