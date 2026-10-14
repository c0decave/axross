"""File list sorting: same order as before, without a Python callback per
comparison.

Measured before: ``set_items`` with 20 000 entries spent ~1.2 s on the GUI
thread, because QSortFilterProxyModel called the Python ``lessThan`` about
275 000 times (plus rowCount/columnCount per index). The source model now
sorts its own list with a key in ``sorted()``; the proxy only filters.

The reference below is the previous proxy, verbatim: Qt sorts with it, so
every comparison of orders is old-Qt-behaviour vs new.
"""

from __future__ import annotations

import os
import random
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PyQt6.QtCore import QModelIndex, QSortFilterProxyModel, Qt
    from PyQt6.QtWidgets import QApplication
except ImportError:  # pragma: no cover
    QApplication = None

from models.file_item import FileItem  # noqa: E402

if QApplication is not None:
    from models.file_table_model import (  # noqa: E402
        COL_MODIFIED,
        COL_NAME,
        COL_OWNER,
        COL_PERMS,
        COL_SIZE,
        FileSortProxyModel,
        FileTableModel,
    )

    class _OldProxy(QSortFilterProxyModel):
        """The proxy before the change (filter part not needed here)."""

        def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:
            model = self.sourceModel()
            left_item = model.get_item(left.row())
            right_item = model.get_item(right.row())
            if left_item is None or right_item is None:
                return False
            if left_item.name == "..":
                return True
            if right_item.name == "..":
                return False
            if left_item.is_dir != right_item.is_dir:
                return left_item.is_dir
            col = left.column()
            if col == COL_NAME:
                return left_item.name.lower() < right_item.name.lower()
            if col == COL_SIZE:
                return left_item.size < right_item.size
            if col == COL_MODIFIED:
                return left_item.modified < right_item.modified
            if col == COL_PERMS:
                return left_item.permissions < right_item.permissions
            if col == COL_OWNER:
                return left_item.owner < right_item.owner
            return False

    class _OldModel(FileTableModel):
        """Plain source model: no sorting of its own (``set_items`` as before)."""

        def sort(self, column, order=Qt.SortOrder.AscendingOrder) -> None:
            pass

        def set_items(self, items) -> None:
            self.beginResetModel()
            self._items = list(items)
            self.endResetModel()


def _items(n: int = 400, seed: int = 4) -> list[FileItem]:
    rnd = random.Random(seed)
    base = datetime(2026, 1, 1)
    names = ["a.txt", "A.txt", "b", "B", "zz", "Zz", "file10", "file2", ".hidden", "ä.txt"]
    out = [FileItem(name="..", is_dir=True)]
    for i in range(n):
        out.append(
            FileItem(
                name=rnd.choice(names) + ("" if rnd.random() < 0.3 else str(rnd.randint(0, 50))),
                size=rnd.choice([0, 10, 10, 512, 4096, rnd.randint(0, 10**6)]),
                modified=base + timedelta(minutes=rnd.choice([0, 0, 5, rnd.randint(0, 10**5)])),
                permissions=rnd.choice([0o644, 0o755, 0o600]),
                is_dir=rnd.random() < 0.25,
                owner=rnd.choice(["root", "dash", "alice", ""]),
                group=rnd.choice(["users", "wheel"]),
            )
        )
    return out


def _order(proxy) -> list[int]:
    src = proxy.sourceModel()
    return [
        id(src.get_item(proxy.mapToSource(proxy.index(r, 0)).row()))
        for r in range(proxy.rowCount())
    ]


@unittest.skipIf(QApplication is None, "PyQt6 not installed")
class SortEquivalenceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def _both(self, items):
        old_model, old = _OldModel(), _OldProxy()
        old.setSourceModel(old_model)
        new_model, new = FileTableModel(), FileSortProxyModel()
        new.show_hidden = True  # the reference does not filter
        new.setSourceModel(new_model)
        # As the pane does (ui/file_pane.py: sortByColumn before any
        # listing): a sort is always active when items arrive. A proxy that
        # was never sorted behaves differently on its very first descending
        # sort (Qt reverses instead of stable-sorting) — a state the app
        # never reaches.
        for proxy in (old, new):
            proxy.sort(COL_NAME, Qt.SortOrder.AscendingOrder)
        old_model.set_items(items)
        new_model.set_items(items)
        return old, new

    def test_every_column_and_order_matches_the_old_proxy(self) -> None:
        items = _items()
        old, new = self._both(items)
        for col in (COL_NAME, COL_SIZE, COL_MODIFIED, COL_PERMS, COL_OWNER, 7):
            for order in (Qt.SortOrder.AscendingOrder, Qt.SortOrder.DescendingOrder):
                with self.subTest(col=col, order=order):
                    old.sort(col, order)
                    new.sort(col, order)
                    self.assertEqual(_order(new), _order(old))

    def test_ties_keep_the_previous_order_like_qt(self) -> None:
        # Qt stable-sorts its current mapping, so ties keep the order of the
        # previous sort; a series of sorts must end in the same order.
        items = _items(seed=9)
        old, new = self._both(items)
        for col in (COL_SIZE, COL_OWNER, COL_NAME, COL_PERMS):
            old.sort(col, Qt.SortOrder.DescendingOrder)
            new.sort(col, Qt.SortOrder.DescendingOrder)
        self.assertEqual(_order(new), _order(old))

    def test_toggling_and_switching_columns_matches_step_by_step(self) -> None:
        old, new = self._both(_items(seed=13))
        steps = [
            (COL_SIZE, Qt.SortOrder.DescendingOrder),
            (COL_SIZE, Qt.SortOrder.AscendingOrder),
            (COL_NAME, Qt.SortOrder.DescendingOrder),
            (COL_OWNER, Qt.SortOrder.AscendingOrder),
            (COL_OWNER, Qt.SortOrder.DescendingOrder),
            (COL_MODIFIED, Qt.SortOrder.AscendingOrder),
        ]
        for col, order in steps:
            old.sort(col, order)
            new.sort(col, order)
            self.assertEqual(_order(new), _order(old), (col, order))

    def test_new_items_are_sorted_by_the_current_column(self) -> None:
        old, new = self._both(_items())
        old.sort(COL_SIZE, Qt.SortOrder.DescendingOrder)
        new.sort(COL_SIZE, Qt.SortOrder.DescendingOrder)
        fresh = _items(seed=21)
        old.sourceModel().set_items(fresh)
        new.sourceModel().set_items(fresh)
        self.assertEqual(_order(new), _order(old))

    def test_edge_dotdot_and_directories(self) -> None:
        items = [
            FileItem(name="b.txt"),
            FileItem(name="..", is_dir=True),
            FileItem(name="zdir", is_dir=True),
            FileItem(name="a.txt"),
            FileItem(name="Adir", is_dir=True),
        ]
        old, new = self._both(items)
        names = lambda p: [p.data(p.index(r, 0)) for r in range(p.rowCount())]  # noqa: E731
        new.sort(COL_NAME, Qt.SortOrder.AscendingOrder)
        self.assertEqual(names(new), ["..", "Adir", "zdir", "a.txt", "b.txt"])
        new.sort(COL_NAME, Qt.SortOrder.DescendingOrder)
        self.assertEqual(names(new), ["b.txt", "a.txt", "zdir", "Adir", ".."])

    def test_edge_empty_and_single(self) -> None:
        for items in ([], [FileItem(name="..", is_dir=True)], [FileItem(name="x")]):
            old, new = self._both(items)
            new.sort(COL_SIZE, Qt.SortOrder.DescendingOrder)
            old.sort(COL_SIZE, Qt.SortOrder.DescendingOrder)
            self.assertEqual(_order(new), _order(old))


@unittest.skipIf(QApplication is None, "PyQt6 not installed")
class SortWithViewTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from PyQt6.QtWidgets import QTableView

        self.model = FileTableModel()
        self.proxy = FileSortProxyModel()
        self.proxy.setSourceModel(self.model)
        self.view = QTableView()
        self.addCleanup(self.view.deleteLater)
        self.view.setModel(self.proxy)
        self.view.setSortingEnabled(True)
        self.view.sortByColumn(COL_NAME, Qt.SortOrder.AscendingOrder)
        self.model.set_items(_items(50))

    def test_the_selection_follows_its_rows_through_a_sort(self) -> None:
        from PyQt6.QtCore import QItemSelectionModel

        sel = self.view.selectionModel()
        flags = QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows
        picked = set()
        for r in (3, 7, 11):
            idx = self.proxy.index(r, 0)
            sel.select(idx, flags)
            picked.add(id(self.model.get_item(self.proxy.mapToSource(idx).row())))
        self.view.sortByColumn(COL_SIZE, Qt.SortOrder.DescendingOrder)
        now = {id(self.model.get_item(self.proxy.mapToSource(i).row())) for i in sel.selectedRows()}
        self.assertEqual(now, picked)

    def test_header_click_sorts(self) -> None:
        self.view.sortByColumn(COL_SIZE, Qt.SortOrder.AscendingOrder)
        sizes = [
            self.model.get_item(self.proxy.mapToSource(self.proxy.index(r, 0)).row())
            for r in range(self.proxy.rowCount())
        ]
        files = [it.size for it in sizes if not it.is_dir]
        self.assertEqual(files, sorted(files))

    def test_filtering_still_works_with_sorting(self) -> None:
        self.proxy.setFilterFixedString("file")
        self.proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        names = [self.proxy.data(self.proxy.index(r, 0)) for r in range(self.proxy.rowCount())]
        self.assertTrue(all(n == ".." or "file" in n.lower() for n in names))
        self.assertGreater(len(names), 1)

    def test_a_large_listing_never_calls_python_per_comparison(self) -> None:
        from unittest import mock

        with mock.patch.object(FileSortProxyModel, "lessThan", autospec=True) as lt:
            self.model.set_items(_items(3000))
            self.view.sortByColumn(COL_MODIFIED, Qt.SortOrder.DescendingOrder)
        self.assertEqual(lt.call_count, 0)


if __name__ == "__main__":
    unittest.main()
