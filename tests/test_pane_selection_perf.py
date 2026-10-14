"""File pane: invert selection, filter keystrokes and item flags, faster
with the same result.

Measured before: inverting the selection of 20 000 rows took ~40 s (one
isSelected + select per row, each slower as the selection fragments); each
filter keystroke filtered twice (the key column and case sensitivity were
set again every time); ``flags()`` rebuilt its value on every call.
"""

from __future__ import annotations

import os
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PyQt6.QtCore import QAbstractTableModel, QItemSelectionModel, QModelIndex, Qt
    from PyQt6.QtWidgets import QApplication
except ImportError:  # pragma: no cover
    QApplication = None

from models.file_item import FileItem  # noqa: E402


def _old_invert(pane) -> None:
    """The former ``_invert_selection`` loop, verbatim."""
    sel = pane._table.selectionModel()
    sel.blockSignals(True)
    for row in range(pane._proxy.rowCount()):
        source_idx = pane._proxy.mapToSource(pane._proxy.index(row, 0))
        item = pane._model.get_item(source_idx.row())
        if item and item.name == "..":
            continue
        row_idx = pane._proxy.index(row, 0)
        if sel.isSelected(row_idx):
            sel.select(row_idx, sel.SelectionFlag.Deselect | sel.SelectionFlag.Rows)
        else:
            sel.select(row_idx, sel.SelectionFlag.Select | sel.SelectionFlag.Rows)
    sel.blockSignals(False)
    pane.selection_changed.emit()


@unittest.skipIf(QApplication is None, "PyQt6 not installed")
class _Pane(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def pane(self, n: int, dotdot: bool = True):
        from unittest import mock

        from core.local_fs import LocalFS
        from ui.file_pane import FilePaneWidget

        with mock.patch.object(FilePaneWidget, "navigate", lambda *a, **k: None):
            pane = FilePaneWidget(LocalFS())
        self.addCleanup(pane.deleteLater)
        items = [FileItem(name="..", is_dir=True)] if dotdot else []
        items += [FileItem(name=f"file_{i:05d}.txt", size=i) for i in range(n)]
        pane._model.set_items(items)
        return pane

    def selected(self, pane) -> set[str]:
        sel = pane._table.selectionModel()
        out = set()
        for r in range(pane._proxy.rowCount()):
            for c in range(pane._proxy.columnCount()):
                if sel.isSelected(pane._proxy.index(r, c)):
                    out.add((pane._proxy.data(pane._proxy.index(r, 0)), c))
        return out

    def select_rows(self, pane, rows, *, partial_col: int | None = None) -> None:
        sel = pane._table.selectionModel()
        for r in rows:
            if partial_col is None:
                flags = (
                    QItemSelectionModel.SelectionFlag.Select
                    | QItemSelectionModel.SelectionFlag.Rows
                )
                sel.select(pane._proxy.index(r, 0), flags)
            else:
                sel.select(
                    pane._proxy.index(r, partial_col), QItemSelectionModel.SelectionFlag.Select
                )


class InvertSelectionTest(_Pane):
    def _compare(self, setup) -> None:
        a, b = self.pane(60), self.pane(60)
        setup(a)
        setup(b)
        _old_invert(a)
        b._invert_selection()
        self.assertEqual(self.selected(b), self.selected(a))

    def test_happy_alternating_rows(self) -> None:
        self._compare(lambda p: self.select_rows(p, range(1, 60, 2)))

    def test_happy_nothing_selected_selects_all_but_dotdot(self) -> None:
        a = self.pane(10)
        a._invert_selection()
        names = {n for n, _c in self.selected(a)}
        self.assertNotIn("..", names)
        self.assertEqual(len(names), 10)

    def test_edge_everything_selected(self) -> None:
        self._compare(lambda p: self.select_rows(p, range(0, 61)))

    def test_edge_dotdot_selected_stays_untouched(self) -> None:
        self._compare(lambda p: self.select_rows(p, [0, 5, 6, 7]))

    def test_edge_a_partially_selected_row_behaves_as_before(self) -> None:
        self._compare(lambda p: self.select_rows(p, [3, 9], partial_col=2))

    def test_edge_no_dotdot_row(self) -> None:
        a, b = self.pane(30, dotdot=False), self.pane(30, dotdot=False)
        for p in (a, b):
            self.select_rows(p, [0, 1, 29])
        _old_invert(a)
        b._invert_selection()
        self.assertEqual(self.selected(b), self.selected(a))

    def test_edge_filtered_view_only_inverts_visible_rows(self) -> None:
        def setup(p):
            p._on_filter_changed("file_000")
            self.select_rows(p, [1, 2])

        self._compare(setup)

    def test_signal_fires_once(self) -> None:
        p = self.pane(20)
        hits = []
        p.selection_changed.connect(lambda: hits.append(1))
        p._invert_selection()
        self.assertEqual(hits, [1])

    def test_large_inversion_is_fast(self) -> None:
        from PyQt6.QtCore import QItemSelection

        p = self.pane(20000)
        start = QItemSelection()
        for r in range(1, 20001, 2):
            start.select(p._proxy.index(r, 0), p._proxy.index(r, p._proxy.columnCount() - 1))
        p._table.selectionModel().select(start, QItemSelectionModel.SelectionFlag.Select)
        t = time.perf_counter()
        p._invert_selection()
        self.assertLess(time.perf_counter() - t, 2.0)
        self.assertEqual(len(p._table.selectionModel().selectedRows()), 10000)


class FilterTest(_Pane):
    def test_happy_case_insensitive_substring(self) -> None:
        p = self.pane(50)
        p._on_filter_changed("FILE_0001")
        names = [p._proxy.data(p._proxy.index(r, 0)) for r in range(p._proxy.rowCount())]
        self.assertEqual(names[0], "..")
        self.assertEqual(sorted(names[1:]), [f"file_{i:05d}.txt" for i in range(10, 20)])

    def test_edge_clearing_the_filter_shows_everything(self) -> None:
        p = self.pane(50)
        p._on_filter_changed("file_0004")
        p._on_filter_changed("")
        self.assertEqual(p._proxy.rowCount(), 51)

    def test_one_filter_pass_per_keystroke(self) -> None:
        from unittest import mock

        from models.file_table_model import FileSortProxyModel

        p = self.pane(200)
        p._on_filter_changed("f")
        with mock.patch.object(
            FileSortProxyModel, "filterAcceptsRow", autospec=True, return_value=True
        ) as acc:
            p._on_filter_changed("fi")
        self.assertLessEqual(acc.call_count, 201)


class FlagsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if QApplication is None:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def test_flags_equal_the_former_computation(self) -> None:
        from models.file_table_model import FileTableModel

        m = FileTableModel()
        m.set_items([FileItem(name="a")])
        valid = m.index(0, 0)
        base_valid = QAbstractTableModel.flags(m, valid)
        base_invalid = QAbstractTableModel.flags(m, QModelIndex())
        self.assertEqual(
            m.flags(valid),
            base_valid
            | Qt.ItemFlag.ItemIsDragEnabled
            | Qt.ItemFlag.ItemIsEnabled
            | Qt.ItemFlag.ItemIsSelectable,
        )
        self.assertEqual(m.flags(QModelIndex()), base_invalid | Qt.ItemFlag.ItemIsDropEnabled)


if __name__ == "__main__":
    unittest.main()
