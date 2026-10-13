"""Hovering a file in the pane shows its complete name in a box."""
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

LONG = "a_really_long_report_name_that_does_not_fit_into_the_name_column_2026-10-13_final_v7.tar.gz"


class HoverNameTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from core.local_fs import LocalFS
        from ui import column_prefs as CP
        from ui.file_pane import FilePaneWidget

        self.root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        (self.root / LONG).write_text("x")
        (self.root / "<b>bold<u>.txt").write_text("x")
        (self.root / "dir").mkdir()
        patcher = mock.patch.object(CP, "DEFAULT_PATH", self.root / "cols.json")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.pane = FilePaneWidget(LocalFS())
        self.addCleanup(self.pane.deleteLater)
        self.pane.resize(700, 400)
        self.pane.show()
        self.pane.navigate(str(self.root))
        self.app.processEvents()

    def _index(self, name: str, col: int = 0):
        proxy = self.pane._proxy
        for r in range(proxy.rowCount()):
            if proxy.data(proxy.index(r, 0)) == name:
                return proxy.index(r, col)
        self.fail(f"{name!r} not listed")

    def _tip(self, index):
        from PyQt6.QtCore import Qt

        return self.pane._proxy.data(index, Qt.ItemDataRole.ToolTipRole)

    def test_name_cell_has_a_tooltip_with_the_complete_name(self) -> None:
        tip = self._tip(self._index(LONG))
        self.assertIn(LONG, tip)

    def test_directories_get_one_too(self) -> None:
        self.assertIn("dir", self._tip(self._index("dir")))

    def test_other_columns_do_not_repeat_it(self) -> None:
        self.assertIsNone(self._tip(self._index(LONG, 1)))

    def test_markup_in_a_name_is_shown_literally(self) -> None:
        tip = self._tip(self._index("<b>bold<u>.txt"))
        self.assertNotIn("<b>", tip)
        self.assertIn("&lt;b&gt;bold&lt;u&gt;.txt", tip)

    def test_the_parent_entry_has_no_tooltip(self) -> None:
        proxy = self.pane._proxy
        for r in range(proxy.rowCount()):
            if proxy.data(proxy.index(r, 0)) == "..":
                self.assertIsNone(self._tip(proxy.index(r, 0)))

    def test_hovering_the_row_pops_the_box_up(self) -> None:
        from PyQt6.QtCore import QEvent, QPoint
        from PyQt6.QtGui import QHelpEvent
        from PyQt6.QtWidgets import QApplication, QToolTip

        table = self.pane._table
        pos = table.visualRect(self._index(LONG)).center()
        QToolTip.hideText()
        event = QHelpEvent(QEvent.Type.ToolTip, pos, table.viewport().mapToGlobal(pos))
        QApplication.sendEvent(table.viewport(), event)
        self.app.processEvents()
        self.assertIn(LONG, QToolTip.text())
        _ = QPoint


if __name__ == "__main__":
    unittest.main()
