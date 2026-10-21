"""A column the user drags wider stays wider - also while a long file name
does not fit. Reported: the columns of a pane could not be resized by
dragging. With a name longer than the free width, the name took back the
"slack" of every other column, the one just dragged included, so a drag
snapped back at once."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from ui import column_prefs as CP  # noqa: E402

LONG = "holiday-photos-2026-summer-lake-and-mountains-and-a-very-long-tail.jpg"


class ColumnDragTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from PyQt6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication([])

    def _pane(self, names, width=760):
        from core.local_fs import LocalFS
        from models.file_item import FileItem
        from ui.file_pane import FilePaneWidget

        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        self.prefs = Path(d) / "column_prefs.json"
        patcher = mock.patch.object(CP, "DEFAULT_PATH", self.prefs)
        patcher.start()
        self.addCleanup(patcher.stop)
        pane = FilePaneWidget(LocalFS())
        self.addCleanup(pane.deleteLater)
        pane._model.set_items(
            [
                FileItem(name=n, size=12, modified=datetime(2026, 1, 1), owner="al", group="al")
                for n in names
            ]
        )
        pane.resize(width, 500)
        pane.show()
        self.app.processEvents()
        return pane

    def _widths(self, pane):
        h = pane._table.horizontalHeader()
        return [h.sectionSize(c) for c in range(pane._model.columnCount())]

    def _drag_divider(self, pane, col: int, dx: int) -> None:
        """Press on the divider right of *col*, move by *dx*, release."""
        from PyQt6.QtCore import QPoint, Qt
        from PyQt6.QtTest import QTest

        h = pane._table.horizontalHeader()
        x = h.sectionViewportPosition(col) + h.sectionSize(col) - 1
        y = h.height() // 2
        vp = h.viewport()
        QTest.mousePress(
            vp, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, QPoint(x, y)
        )
        for step in range(1, 6):
            QTest.mouseMove(vp, QPoint(x + dx * step // 5, y))
        QTest.mouseRelease(
            vp, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, QPoint(x + dx, y)
        )
        self.app.processEvents()

    def test_happy_dragging_a_column_wider_with_short_names(self) -> None:
        pane = self._pane(["a.txt"])
        before = self._widths(pane)
        self._drag_divider(pane, 4, 50)
        after = self._widths(pane)
        self.assertGreaterEqual(after[4], before[4] + 40, (before, after))
        self.assertEqual(sum(after), pane._table.viewport().width())

    def test_happy_dragging_a_column_wider_while_a_long_name_does_not_fit(self) -> None:
        pane = self._pane([LONG])
        before = self._widths(pane)
        self._drag_divider(pane, 4, 50)
        after = self._widths(pane)
        self.assertGreaterEqual(after[4], before[4] + 40, (before, after))
        self.assertEqual(sum(after), pane._table.viewport().width())
        saved = json.loads(self.prefs.read_text())["widths"]
        self.assertEqual(saved["4"], after[4])

    def test_sad_a_dragged_column_stays_when_the_listing_changes(self) -> None:
        from models.file_item import FileItem

        pane = self._pane([LONG])
        self._drag_divider(pane, 2, 40)
        dragged = self._widths(pane)[2]
        pane._model.set_items([FileItem(name=LONG + "x", size=1, modified=datetime(2026, 1, 1))])
        self.app.processEvents()
        self.app.processEvents()
        self.assertEqual(self._widths(pane)[2], dragged)

    def test_edge_dragging_narrower_still_works(self) -> None:
        pane = self._pane([LONG], width=1400)
        before = self._widths(pane)
        self._drag_divider(pane, 4, -30)
        after = self._widths(pane)
        self.assertLessEqual(after[4], before[4] - 20, (before, after))


if __name__ == "__main__":
    unittest.main()
