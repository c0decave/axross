"""ui.column_fit: every divider draggable, yet the table looks fitted -
numbers as wide as their content, one column the free width - until the
user drags a column, which then keeps its width. A test holds every view
in ui/ to it: no Stretch / ResizeToContents / Fixed section, which Qt never
lets a user drag (reported: columns of the views could not be resized)."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt6.QtCore import QPoint, Qt  # noqa: E402
from PyQt6.QtGui import QStandardItem, QStandardItemModel  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QHeaderView, QTableView, QTableWidget, QTreeView  # noqa: E402

APP = QApplication.instance() or QApplication([])
LONG = "/some/rather/long/folder/name/that/needs/space/in/the/first/column"


def _table_widget(rows):
    t = QTableWidget(len(rows), 3)
    t.setHorizontalHeaderLabels(["Path", "Size", "When"])
    for r, row in enumerate(rows):
        for c, text in enumerate(row):
            from PyQt6.QtWidgets import QTableWidgetItem

            t.setItem(r, c, QTableWidgetItem(text))
    return t


def _show(view, width=800):
    view.resize(width, 300)
    view.show()
    APP.processEvents()
    APP.processEvents()


def _widths(view):
    h = view.horizontalHeader() if hasattr(view, "horizontalHeader") else view.header()
    return [h.sectionSize(c) for c in range(h.count())]


def test_happy_fill_column_takes_the_free_width_numbers_fit():
    from ui.column_fit import ColumnFitter

    t = _table_widget([[LONG, "12 KiB", "2026-10-21 12:00"], ["b", "1 B", "2026-01-01 00:00"]])
    ColumnFitter(t, fill=0)
    _show(t)
    w = _widths(t)
    h = t.horizontalHeader()
    assert w[1] >= t.sizeHintForColumn(1) and w[2] >= t.sizeHintForColumn(2)
    assert sum(w) == t.viewport().width(), w
    assert all(h.sectionResizeMode(c) == QHeaderView.ResizeMode.Interactive for c in range(3))


def test_happy_rows_arriving_later_refit():
    from ui.column_fit import ColumnFitter

    t = _table_widget([["a", "1", "x"]])
    ColumnFitter(t, fill=0)
    _show(t)
    before = _widths(t)[2]
    from PyQt6.QtWidgets import QTableWidgetItem

    t.setRowCount(2)
    t.setItem(1, 2, QTableWidgetItem("a much longer timestamp text 2026-10-21 12:00:00"))
    APP.processEvents()
    APP.processEvents()
    assert _widths(t)[2] > before


def test_sad_a_dragged_column_keeps_its_width():
    from ui.column_fit import ColumnFitter

    t = _table_widget([[LONG, "12 KiB", "2026"]])
    ColumnFitter(t, fill=0)
    _show(t)
    h = t.horizontalHeader()
    x = h.sectionViewportPosition(1) + h.sectionSize(1) - 1
    y = h.height() // 2
    vp = h.viewport()
    QTest.mousePress(vp, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, QPoint(x, y))
    for step in range(1, 6):
        QTest.mouseMove(vp, QPoint(x + 10 * step, y))
    QTest.mouseRelease(
        vp, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, QPoint(x + 50, y)
    )
    APP.processEvents()
    dragged = h.sectionSize(1)
    assert dragged >= 40 + t.sizeHintForColumn(1) - 15
    t.resize(1100, 300)
    APP.processEvents()
    APP.processEvents()
    assert h.sectionSize(1) == dragged


def test_edge_tree_view_and_a_model_set_later():
    from ui.column_fit import ColumnFitter

    tree = QTreeView()
    ColumnFitter(tree, fill=1)
    model = QStandardItemModel()
    model.setHorizontalHeaderLabels(["Key", "Action"])
    model.appendRow([QStandardItem("Ctrl+Shift+Alt+F12"), QStandardItem("Something")])
    tree.setModel(model)
    _show(tree, 600)
    w = _widths(tree)
    assert w[0] >= tree.sizeHintForColumn(0)
    assert sum(w) == tree.viewport().width(), w


def test_edge_an_empty_view_does_not_fail():
    from ui.column_fit import ColumnFitter

    t = QTableView()
    ColumnFitter(t, fill=0)
    _show(t)


_NOT_DRAGGABLE = re.compile(r"ResizeMode\.(Stretch|ResizeToContents|Fixed)\b")


@pytest.mark.parametrize("top", ["ui", "resources"])
def test_sad_no_view_has_a_section_the_user_cannot_drag(top):
    hits = []
    for path in sorted((ROOT / top).rglob("*.py")):
        if path.name == "column_fit.py":
            continue
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if _NOT_DRAGGABLE.search(line):
                hits.append(f"{path.relative_to(ROOT)}:{n}: {line.strip()}")
    assert hits == []


def test_sad_a_narrow_view_keeps_the_fill_column_readable():
    """Reported by the theme audit: a 320 px archive dock gave Name 31 px of
    the 120 it needs, the numbers took their full content width."""
    from ui.column_fit import ColumnFitter

    t = _table_widget([[LONG, "12.3 KiB", "2026-10-21 12:00:00"]])
    ColumnFitter(t, fill=0)
    _show(t, 320)
    h = t.horizontalHeader()
    w = _widths(t)
    vp = t.viewport().width()
    assert w[0] >= min(t.sizeHintForColumn(0), vp // 2), w
    for c in (1, 2):
        assert w[c] >= h.minimumSectionSize(), (c, w)  # elided, never gone
