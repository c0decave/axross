"""A descending sort keeps "." and ".." on top and the folders first.

Found in review (round 2 of the 2026-11 reviews, UI shell): clicking the
Name (or Size, Modified ...) header a second time reversed the whole
list - the files came first, the folders after them and ".." last, at
the very bottom of a long folder. Total Commander, Midnight Commander
and Finder keep ".." on top and the folders together before the files;
only the order inside each group is reversed.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from models.file_item import FileItem  # noqa: E402
from models.file_table_model import (  # noqa: E402
    COL_MODIFIED,
    COL_NAME,
    COL_SIZE,
    FileSortProxyModel,
    FileTableModel,
    sort_positions,
)

APP = QApplication.instance() or QApplication([])
BASE = datetime(2026, 1, 1)


def _items() -> list[FileItem]:
    return [
        FileItem(name="b.txt", size=5, modified=BASE + timedelta(days=2)),
        FileItem(name="..", is_dir=True),
        FileItem(name="zdir", is_dir=True, size=1, modified=BASE),
        FileItem(name="a.txt", size=9, modified=BASE + timedelta(days=1)),
        FileItem(name=".", is_dir=True),
        FileItem(name="Adir", is_dir=True, size=2, modified=BASE + timedelta(days=3)),
    ]


def _names(col: int, order) -> list[str]:
    model, proxy = FileTableModel(), FileSortProxyModel()
    proxy.show_hidden = True
    proxy.setSourceModel(model)
    proxy.sort(COL_NAME, Qt.SortOrder.AscendingOrder)
    model.set_items(_items())
    proxy.sort(col, order)
    return [proxy.data(proxy.index(r, 0)) for r in range(proxy.rowCount())]


def test_happy_ascending_by_name():
    assert _names(COL_NAME, Qt.SortOrder.AscendingOrder) == [
        ".", "..", "Adir", "zdir", "a.txt", "b.txt"]


def test_sad_descending_by_name_keeps_dotdot_and_folders_on_top():
    assert _names(COL_NAME, Qt.SortOrder.DescendingOrder) == [
        ".", "..", "zdir", "Adir", "b.txt", "a.txt"]


def test_sad_descending_by_size_and_date_too():
    assert _names(COL_SIZE, Qt.SortOrder.DescendingOrder) == [
        ".", "..", "Adir", "zdir", "a.txt", "b.txt"]
    assert _names(COL_MODIFIED, Qt.SortOrder.DescendingOrder) == [
        ".", "..", "Adir", "zdir", "b.txt", "a.txt"]


def test_edge_a_large_listing_sorted_in_pieces_keeps_the_groups():
    items = [FileItem(name=f"f{i:06d}") for i in range(40000)]
    items += [FileItem(name=f"d{i:06d}", is_dir=True) for i in range(3)]
    items.append(FileItem(name="..", is_dir=True))
    order = sort_positions(items, COL_NAME, Qt.SortOrder.DescendingOrder, in_pieces=True)
    names = [items[i].name for i in order]
    assert names[:4] == ["..", "d000002", "d000001", "d000000"]
    assert names[4] == "f039999" and names[-1] == "f000000"
