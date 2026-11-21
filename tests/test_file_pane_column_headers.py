"""The file pane's column headers: moving a column, dragging a divider,
double-clicking a divider - driven with the mouse on the real header.

Reported (again, after the order was first made persistent): the columns
could still not be moved correctly. Moving one in a pane worked, but every
pane kept its own copy of the column settings as they were when it opened
and wrote all of it back on its next change: resizing a column or hiding
one in the other pane put the old order (and the old widths, the old hidden
columns) back into the file, so the next start showed the columns where
they had been. The column chooser listed the columns in their old order.

Dragging the divider right of Name added up the steps of the drag: the
fit after each mouse move gave a long name its room back, and the next step
counted from there, so the next column grew by far more than the mouse
moved (80 px of mouse, 196 px of column) and a longer drag hid every other
column.

A double-click on a divider was Qt's resizeColumnToContents: it reads up to
1000 rows near the top through the model (ten roles each) and misses a long
entry further down; on the divider right of Name it shrank Name to its
names and gave the whole rest of the pane to the next column, which stayed
that wide.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from ui import column_prefs as CP  # noqa: E402

NAME, SIZE, MODIFIED, PERMISSIONS, OWNER = range(5)
LONG = "holiday-photos-2026-summer-lake-and-mountains-and-a-very-long-tail.jpg"


class _HeaderTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.prefs = self.dir / "column_prefs.json"
        patcher = mock.patch.object(CP, "DEFAULT_PATH", self.prefs)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _items(self, count: int = 20, owner_at: int | None = None, owner: str = "al"):
        from models.file_item import FileItem

        return [
            FileItem(
                name=f"file{i:06d}.txt",
                size=12 * i,
                modified=datetime(2026, 1, 1),
                owner=owner if i == owner_at else "al",
                group="al",
            )
            for i in range(count)
        ]

    def _pane(self, items=None, width: int = 1000):
        from core.local_fs import LocalFS
        from ui.file_pane import FilePaneWidget

        pane = FilePaneWidget(LocalFS())
        self.addCleanup(pane.deleteLater)
        pane._model.set_items(self._items() if items is None else items)
        pane.resize(width, 500)
        pane.show()
        self._settle()
        return pane

    def _settle(self) -> None:
        for _ in range(3):
            self.app.processEvents()

    @staticmethod
    def _header(pane):
        return pane._table.horizontalHeader()

    def _order(self, pane) -> list[int]:
        h = self._header(pane)
        return [h.logicalIndex(v) for v in range(h.count())]

    def _widths(self, pane) -> list[int]:
        h = self._header(pane)
        return [h.sectionSize(c) for c in range(h.count())]

    def _saved(self) -> dict:
        return json.loads(self.prefs.read_text(encoding="utf-8"))

    # -- the mouse on the header ------------------------------------------
    def _drag_section(self, pane, logical: int, to_x: int) -> None:
        """Press in the middle of *logical*'s header, drag to *to_x*, release."""
        from PyQt6.QtCore import QPoint, Qt
        from PyQt6.QtTest import QTest

        h = self._header(pane)
        vp = h.viewport()
        x0 = h.sectionViewportPosition(logical) + h.sectionSize(logical) // 2
        y = h.height() // 2
        QTest.mousePress(vp, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier,
                         QPoint(x0, y))
        for step in range(1, 11):
            QTest.mouseMove(vp, QPoint(x0 + (to_x - x0) * step // 10, y))
        QTest.mouseRelease(vp, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier,
                           QPoint(to_x, y))
        self._settle()

    def _move_before(self, pane, logical: int, target: int) -> None:
        """Drag *logical* onto the left edge of *target*: it lands before it."""
        h = self._header(pane)
        self._drag_section(pane, logical, h.sectionViewportPosition(target) + 4)

    def _handle_x(self, pane, logical: int) -> int:
        """The divider right of *logical*, on its last pixel."""
        h = self._header(pane)
        return h.sectionViewportPosition(logical) + h.sectionSize(logical) - 1

    def _drag_divider(self, pane, logical: int, dx: int) -> None:
        from PyQt6.QtCore import QPoint, Qt
        from PyQt6.QtTest import QTest

        h = self._header(pane)
        vp = h.viewport()
        x = self._handle_x(pane, logical)
        y = h.height() // 2
        QTest.mousePress(vp, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier,
                         QPoint(x, y))
        for step in range(1, 6):
            QTest.mouseMove(vp, QPoint(x + dx * step // 5, y))
        QTest.mouseRelease(vp, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier,
                           QPoint(x + dx, y))
        self._settle()

    def _double_click_divider(self, pane, logical: int) -> None:
        from PyQt6.QtCore import QPoint, Qt
        from PyQt6.QtTest import QTest

        h = self._header(pane)
        QTest.mouseDClick(h.viewport(), Qt.MouseButton.LeftButton,
                          Qt.KeyboardModifier.NoModifier,
                          QPoint(self._handle_x(pane, logical), h.height() // 2))
        self._settle()


class ColumnMoveTest(_HeaderTestBase):
    def test_a_column_moved_in_one_pane_keeps_its_place_when_the_other_pane_is_resized(self):
        left = self._pane()
        right = self._pane()
        self._move_before(left, OWNER, NAME)
        self.assertEqual(self._order(left), [OWNER, NAME, SIZE, MODIFIED, PERMISSIONS])
        # The other pane, opened before the move, changes a width.
        self._drag_divider(right, MODIFIED, 30)
        self.assertEqual(self._saved()["order"], [OWNER, NAME, SIZE, MODIFIED, PERMISSIONS])
        # The next start shows the moved column where the user put it.
        again = self._pane()
        self.assertEqual(self._order(again), [OWNER, NAME, SIZE, MODIFIED, PERMISSIONS])

    def test_moving_in_one_pane_keeps_a_column_hidden_in_the_other(self):
        left = self._pane()
        right = self._pane()
        right._toggle_column(PERMISSIONS, False)
        header = self._header(left)
        header.moveSection(header.visualIndex(SIZE), header.visualIndex(NAME))
        self._settle()
        saved = self._saved()
        self.assertEqual(saved["hidden"], [PERMISSIONS])
        self.assertEqual(saved["order"][:2], [SIZE, NAME])
        again = self._pane()
        self.assertTrue(again._table.isColumnHidden(PERMISSIONS))
        self.assertEqual(self._order(again)[:2], [SIZE, NAME])

    def test_the_column_chooser_lists_the_columns_as_they_stand(self):
        from PyQt6.QtCore import Qt

        pane = self._pane()
        self._move_before(pane, OWNER, NAME)
        self._move_before(pane, PERMISSIONS, SIZE)
        menu = pane._build_header_menu()
        self.addCleanup(menu.deleteLater)
        labels = [a.text() for a in menu.actions() if not a.isSeparator()]
        expected = [str(pane._model.headerData(c, Qt.Orientation.Horizontal))
                    for c in self._order(pane)]
        self.assertEqual(labels, expected)
        # Ticking an entry still hides the column it names.
        owner = next(a for a in menu.actions() if a.text() == expected[0])
        owner.setChecked(False)
        self._settle()
        self.assertTrue(pane._table.isColumnHidden(OWNER))
        self.assertFalse(pane._table.isColumnHidden(PERMISSIONS))

    # -- guards: what reads the columns after a move -----------------------
    def test_guard_sorting_by_a_moved_column_sorts_by_that_column(self):
        from PyQt6.QtCore import QPoint, Qt
        from PyQt6.QtTest import QTest

        pane = self._pane(self._items(5))
        self._move_before(pane, SIZE, NAME)
        h = self._header(pane)
        QTest.mouseClick(h.viewport(), Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier,
                         QPoint(h.sectionViewportPosition(SIZE) + h.sectionSize(SIZE) // 2,
                                h.height() // 2))
        self._settle()
        self.assertEqual(h.sortIndicatorSection(), SIZE)
        # A drag never sorts.
        self._move_before(pane, OWNER, SIZE)
        self.assertEqual(h.sortIndicatorSection(), SIZE)

    def test_guard_names_and_selection_still_come_from_the_name_column(self):
        pane = self._pane(self._items(5))
        self._move_before(pane, NAME, OWNER)  # Name now between Permissions and Owner
        self.assertNotEqual(self._header(pane).visualIndex(NAME), 0)
        table = pane._table
        row = 2
        rect = table.visualRect(pane._proxy.index(row, SIZE))
        from PyQt6.QtCore import Qt
        from PyQt6.QtTest import QTest

        QTest.mouseClick(table.viewport(), Qt.MouseButton.LeftButton,
                         Qt.KeyboardModifier.NoModifier, rect.center())
        self._settle()
        names = [Path(p).name for p in pane.selected_items()]
        self.assertEqual(names, [pane._proxy.index(row, NAME).data()])


class ColumnDividerTest(_HeaderTestBase):
    def test_a_dragged_width_survives_the_other_pane_and_a_restart(self):
        self.prefs.write_text(json.dumps(
            {"version": CP.VERSION, "widths": {str(MODIFIED): 160}, "hidden": [], "order": []}))
        left = self._pane()
        right = self._pane()
        self._drag_divider(left, MODIFIED, 40)
        dragged = self._widths(left)[MODIFIED]
        self.assertGreaterEqual(dragged, 195)
        # The other pane, holding Modified at 160 since it opened, changes Size.
        self._drag_divider(right, SIZE, 20)
        self.assertEqual(self._saved()["widths"][str(MODIFIED)], dragged)
        again = self._pane()
        self.assertEqual(self._widths(again)[MODIFIED], dragged)
        # ... and through a folder change.
        again._model.set_items(self._items(7))
        self._settle()
        self.assertEqual(self._widths(again)[MODIFIED], dragged)

    def test_the_name_divider_moves_the_next_column_by_the_mouse_way(self):
        from models.file_item import FileItem

        pane = self._pane([FileItem(name=LONG, size=1, modified=datetime(2026, 1, 1))])
        before = self._widths(pane)
        self._drag_divider(pane, NAME, -80)
        after = self._widths(pane)
        self.assertEqual(after[SIZE], before[SIZE] + 80, (before, after))
        self.assertEqual(after[NAME], before[NAME] - 80, (before, after))
        self.assertEqual(after[MODIFIED:], before[MODIFIED:])
        self.assertEqual(sum(after), pane._table.viewport().width())
        self.assertEqual(self._saved()["widths"][str(SIZE)], after[SIZE])

    def test_dragging_the_name_divider_far_left_never_hides_the_other_columns(self):
        from models.file_item import FileItem

        pane = self._pane([FileItem(name=LONG, size=1, modified=datetime(2026, 1, 1))])
        self._drag_divider(pane, NAME, -250)
        hidden = [c for c in range(5) if pane._table.isColumnHidden(c)]
        self.assertEqual(hidden, [])
        self.assertEqual(sum(self._widths(pane)), pane._table.viewport().width())

    def test_guard_dividers_of_moved_columns_still_drag(self):
        pane = self._pane()
        self._move_before(pane, OWNER, NAME)
        before = self._widths(pane)
        self._drag_divider(pane, OWNER, 40)
        after = self._widths(pane)
        self.assertGreaterEqual(after[OWNER], before[OWNER] + 35, (before, after))
        self.assertEqual(sum(after), pane._table.viewport().width())
        self.assertEqual(self._saved()["widths"][str(OWNER)], after[OWNER])


class ColumnDoubleClickFitTest(_HeaderTestBase):
    def test_double_click_fits_an_entry_far_down_a_big_folder(self):
        long_owner = "a-very-long-owner-name-from-a-directory-service"
        # Row 3000 in name order: past the 1000 rows Qt's fit reads.
        pane = self._pane(self._items(20000, owner_at=3000, owner=long_owner))
        index = pane._proxy.index(3000, OWNER)
        self.assertIn(long_owner, index.data())
        needed = pane._table.sizeHintForIndex(index).width()
        self._double_click_divider(pane, OWNER)
        self.assertGreaterEqual(self._widths(pane)[OWNER], needed)
        self.assertEqual(self._saved()["widths"][str(OWNER)], self._widths(pane)[OWNER])

    def test_double_click_reads_few_rows_of_a_huge_folder(self):
        from models.file_table_model import FileTableModel

        pane = self._pane(self._items(100000))
        asked = set()
        real = FileTableModel.item_data

        def counting(model, item, col, role):
            asked.add(item.name)
            return real(model, item, col, role)

        # Every cell the view measures is read through item_data (the
        # proxy's data() calls it directly).
        with mock.patch.object(FileTableModel, "item_data", counting):
            started = time.perf_counter()
            self._double_click_divider(pane, MODIFIED)
            took = time.perf_counter() - started
        # The visible rows and a few long ones - not a thousand rows.
        self.assertLess(len(asked), 200, len(asked))
        self.assertLess(took, 1.0)

    def test_double_click_on_the_name_divider_leaves_the_next_column_alone(self):
        pane = self._pane(width=1200)
        before = self._widths(pane)
        self._double_click_divider(pane, NAME)
        after = self._widths(pane)
        self.assertEqual(after[SIZE], before[SIZE], (before, after))
        self.assertEqual(sum(after), pane._table.viewport().width())
        saved = self._saved()["widths"] if self.prefs.exists() else {}
        self.assertNotIn(str(SIZE), saved)

    def test_double_click_on_the_name_divider_shows_cut_names_whole(self):
        from models.file_item import FileItem

        pane = self._pane([FileItem(name=LONG, size=1, modified=datetime(2026, 1, 1))])
        self._drag_divider(pane, NAME, -250)
        needed = pane._table.sizeHintForIndex(pane._proxy.index(0, NAME)).width()
        self.assertLess(self._widths(pane)[NAME], needed)
        self._double_click_divider(pane, NAME)
        self.assertGreaterEqual(self._widths(pane)[NAME], needed)
        self.assertEqual(sum(self._widths(pane)), pane._table.viewport().width())

    def test_guard_double_click_never_sorts(self):
        pane = self._pane()
        h = self._header(pane)
        self._double_click_divider(pane, SIZE)
        self.assertEqual(h.sortIndicatorSection(), NAME)


if __name__ == "__main__":
    unittest.main()
