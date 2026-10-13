"""Drag a selection box from empty space across the file rows."""

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


class _RubberBase(unittest.TestCase):
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
        for name in ("a.txt", "b.txt", "c.txt", "d.txt", "e.txt"):
            (self.root / name).write_text("x")
        patcher = mock.patch.object(CP, "DEFAULT_PATH", self.root / "cols.json")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.pane = FilePaneWidget(LocalFS())
        self.addCleanup(self.pane.deleteLater)
        self.pane.resize(800, 600)
        self.pane.show()
        self.pane.navigate(str(self.root))
        self.app.processEvents()
        self.table = self.pane._table
        self.vp = self.table.viewport()

    # --- helpers --------------------------------------------------------
    def _row_rect(self, name: str):
        proxy = self.pane._proxy
        for r in range(proxy.rowCount()):
            if proxy.data(proxy.index(r, 0)) == name:
                return self.table.visualRect(proxy.index(r, 0))
        self.fail(f"{name!r} not listed")

    def _empty_y(self) -> int:
        last = max(
            self.table.visualRect(self.pane._proxy.index(r, 0)).bottom()
            for r in range(self.pane._proxy.rowCount())
        )
        return last + 40

    def _selected_names(self) -> set[str]:
        proxy = self.pane._proxy
        return {proxy.data(i) for i in self.table.selectionModel().selectedRows(0)}

    def _press(self, pos, button=None, mods=None) -> None:
        from PyQt6.QtCore import Qt
        from PyQt6.QtTest import QTest

        QTest.mousePress(
            self.vp,
            button or Qt.MouseButton.LeftButton,
            mods or Qt.KeyboardModifier.NoModifier,
            pos,
        )

    def _move(self, pos, buttons=None, mods=None) -> None:
        from PyQt6.QtCore import QEvent, QPointF, Qt
        from PyQt6.QtGui import QMouseEvent
        from PyQt6.QtWidgets import QApplication

        ev = QMouseEvent(
            QEvent.Type.MouseMove,
            QPointF(pos),
            QPointF(self.vp.mapToGlobal(pos)),
            Qt.MouseButton.NoButton,
            buttons or Qt.MouseButton.LeftButton,
            mods or Qt.KeyboardModifier.NoModifier,
        )
        QApplication.sendEvent(self.vp, ev)
        self.app.processEvents()

    def _release(self, pos, button=None, mods=None) -> None:
        from PyQt6.QtCore import Qt
        from PyQt6.QtTest import QTest

        QTest.mouseRelease(
            self.vp,
            button or Qt.MouseButton.LeftButton,
            mods or Qt.KeyboardModifier.NoModifier,
            pos,
        )

    def _drag(self, start, end, **kw) -> None:
        self._press(start, **{k: v for k, v in kw.items() if k in ("button", "mods")})
        self._move(end, **{k: v for k, v in kw.items() if k in ("buttons", "mods")})
        self._release(end, **{k: v for k, v in kw.items() if k in ("button", "mods")})

    def _x(self) -> int:
        return self.vp.width() // 2


class RubberBandTest(_RubberBase):
    def test_dragging_up_from_empty_space_selects_the_rows_it_crosses(self) -> None:
        from PyQt6.QtCore import QPoint

        top = self._row_rect("b.txt").top() + 2
        self._drag(QPoint(self._x(), self._empty_y()), QPoint(self._x(), top))
        self.assertEqual(self._selected_names(), {"b.txt", "c.txt", "d.txt", "e.txt"})

    def test_the_band_follows_the_mouse_and_shrinks_again(self) -> None:
        from PyQt6.QtCore import QPoint

        start = QPoint(self._x(), self._empty_y())
        self._press(start)
        self._move(QPoint(self._x(), self._row_rect("a.txt").center().y()))
        wide = self._selected_names()
        self._move(QPoint(self._x(), self._row_rect("d.txt").center().y()))
        narrow = self._selected_names()
        self._release(QPoint(self._x(), self._row_rect("d.txt").center().y()))
        self.assertTrue(narrow < wide, (narrow, wide))
        self.assertEqual(narrow, {"d.txt", "e.txt"})

    def test_a_visible_band_is_shown_while_dragging_and_hidden_after(self) -> None:
        from PyQt6.QtCore import QPoint
        from PyQt6.QtWidgets import QRubberBand

        start = QPoint(self._x(), self._empty_y())
        self._press(start)
        self._move(QPoint(self._x() + 30, self._empty_y() - 80))
        band = self.vp.findChild(QRubberBand)
        self.assertIsNotNone(band)
        self.assertTrue(band.isVisible())
        self._release(QPoint(self._x() + 30, self._empty_y() - 80))
        self.assertFalse(band.isVisible())

    def test_dragging_only_over_empty_space_selects_nothing(self) -> None:
        from PyQt6.QtCore import QPoint

        y = self._empty_y()
        self._drag(QPoint(10, y), QPoint(300, y + 10))
        self.assertEqual(self._selected_names(), set())

    def test_a_plain_click_on_empty_space_clears_the_selection(self) -> None:
        from PyQt6.QtCore import QPoint

        self.table.selectRow(1)
        self._drag(QPoint(10, self._empty_y()), QPoint(10, self._empty_y()))
        self.assertEqual(self._selected_names(), set())

    def test_ctrl_drag_adds_to_the_existing_selection(self) -> None:
        from PyQt6.QtCore import QPoint, Qt

        self.table.selectRow(self.pane._proxy.mapFromSource(self.pane._model.index(0, 0)).row())
        first = self._selected_names()
        top = self._row_rect("e.txt").top() + 2
        ctrl = Qt.KeyboardModifier.ControlModifier
        self._drag(QPoint(self._x(), self._empty_y()), QPoint(self._x(), top), mods=ctrl)
        self.assertTrue(first <= self._selected_names())
        self.assertIn("e.txt", self._selected_names())

    def test_the_parent_entry_is_never_selected_by_the_band(self) -> None:
        from PyQt6.QtCore import QPoint

        self._drag(QPoint(self._x(), self._empty_y()), QPoint(self._x(), 1))
        self.assertNotIn("..", self._selected_names())
        self.assertTrue({"a.txt", "e.txt"} <= self._selected_names())

    def test_starting_on_a_row_does_not_start_a_band(self) -> None:
        from PyQt6.QtWidgets import QRubberBand

        pos = self._row_rect("a.txt").center()
        self._press(pos)
        self._move(pos + __import__("PyQt6.QtCore", fromlist=["QPoint"]).QPoint(0, 5))
        band = self.vp.findChild(QRubberBand)
        self.assertTrue(band is None or not band.isVisible())
        self._release(pos)

    def test_other_buttons_do_not_start_a_band(self) -> None:
        from PyQt6.QtCore import QPoint, Qt

        top = self._row_rect("b.txt").top() + 2
        self._drag(
            QPoint(self._x(), self._empty_y()),
            QPoint(self._x(), top),
            button=Qt.MouseButton.RightButton,
            buttons=Qt.MouseButton.RightButton,
        )
        self.assertEqual(self._selected_names(), set())

    def test_moving_without_a_press_does_nothing(self) -> None:
        from PyQt6.QtCore import QPoint

        self._move(QPoint(self._x(), self._empty_y()))
        self.assertEqual(self._selected_names(), set())

    def test_the_band_is_clipped_to_the_viewport(self) -> None:
        from PyQt6.QtCore import QPoint
        from PyQt6.QtWidgets import QRubberBand

        self._press(QPoint(self._x(), self._empty_y()))
        self._move(QPoint(self.vp.width() + 500, -500))
        band = self.vp.findChild(QRubberBand)
        self.assertTrue(self.vp.rect().contains(band.geometry()))
        self._release(QPoint(self.vp.width() + 500, -500))

    def test_a_file_drag_from_a_row_is_untouched(self) -> None:
        # pressing on a row still gives the normal row selection
        pos = self._row_rect("c.txt").center()
        self._press(pos)
        self._release(pos)
        self.assertEqual(self._selected_names(), {"c.txt"})


class ColumnStartTest(_RubberBase):
    """A drag that starts on a row but outside the Name column draws the box
    (long lists have no empty space); a drag from a name stays a file drag."""

    def setUp(self) -> None:
        super().setUp()
        self.dragged: list = []
        p = mock.patch.object(self.pane, "_start_drag", lambda: self.dragged.append(1))
        p.start()
        self.addCleanup(p.stop)

    def _cell(self, name: str, col: int):
        from PyQt6.QtCore import QPoint

        y = self._row_rect(name).center().y()
        return QPoint(self.table.columnViewportPosition(col) + 8, y)

    def test_dragging_from_each_non_name_column_selects_the_rows_crossed(self) -> None:
        from PyQt6.QtCore import QPoint

        for col in (1, 2, 3, 4):
            with self.subTest(col=col):
                self.table.clearSelection()
                start = self._cell("b.txt", col)
                end = QPoint(start.x(), self._row_rect("d.txt").center().y())
                self._drag(start, end)
                self.assertEqual(self._selected_names(), {"b.txt", "c.txt", "d.txt"})
        self.assertEqual(self.dragged, [], "no file drag may start")

    def test_a_tiny_movement_is_still_a_click_on_the_row(self) -> None:
        from PyQt6.QtCore import QPoint
        from PyQt6.QtWidgets import QRubberBand

        start = self._cell("c.txt", 1)
        self._drag(start, start + QPoint(0, 2))
        self.assertEqual(self._selected_names(), {"c.txt"})
        band = self.vp.findChild(QRubberBand)
        self.assertTrue(band is None or not band.isVisible())

    def test_a_plain_click_on_a_cell_still_reaches_the_view(self) -> None:
        clicked: list = []
        self.table.clicked.connect(clicked.append)
        pos = self._cell("c.txt", 2)
        self._press(pos)
        self._release(pos)
        self.assertEqual(len(clicked), 1)
        self.assertEqual(self._selected_names(), {"c.txt"})

    def test_dragging_from_the_name_still_starts_a_file_drag(self) -> None:
        from PyQt6.QtCore import QPoint
        from PyQt6.QtWidgets import QRubberBand

        start = self._cell("b.txt", 0)
        self._press(start)
        self._move(start + QPoint(0, 60))
        band = self.vp.findChild(QRubberBand)
        self.assertTrue(band is None or not band.isVisible())
        self._release(start + QPoint(0, 60))

    def test_ctrl_drag_from_a_cell_keeps_the_earlier_selection(self) -> None:
        from PyQt6.QtCore import QPoint, Qt

        self.table.clearSelection()
        a = self._cell("a.txt", 1)
        self._drag(a, a)
        ctrl = Qt.KeyboardModifier.ControlModifier
        start = self._cell("d.txt", 2)
        self._drag(start, QPoint(start.x(), self._row_rect("e.txt").center().y()), mods=ctrl)
        self.assertTrue({"a.txt", "d.txt", "e.txt"} <= self._selected_names())

    def test_the_parent_entry_is_still_excluded(self) -> None:
        from PyQt6.QtCore import QPoint

        start = self._cell("e.txt", 1)
        self._drag(start, QPoint(start.x(), 1))
        self.assertNotIn("..", self._selected_names())
        self.assertIn("a.txt", self._selected_names())

    def test_a_right_button_press_on_a_cell_does_not_start_a_band(self) -> None:
        from PyQt6.QtCore import QPoint, Qt

        start = self._cell("b.txt", 1)
        self._drag(
            start,
            QPoint(start.x(), self._row_rect("e.txt").center().y()),
            button=Qt.MouseButton.RightButton,
            buttons=Qt.MouseButton.RightButton,
        )
        self.assertNotIn("e.txt", self._selected_names())


if __name__ == "__main__":
    unittest.main()
