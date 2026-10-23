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


# -- keep: a column that identifies the row is never squeezed away --------
# Reported: "wenn man extension folder öffnet sieht man manchmal den namen
# nicht der extension dafuer beschreibung und ob geladen". In the
# Extensions list the description is the fill column; Name was one of the
# "others" that share what is left in proportion to their content, so a
# long description and a long status took its width (Name 48 px in a
# 560 px Settings dialog, "Ch…").

_EXT_ROWS = [
    ["", "Chatty Extension With A Long Name", "1.0", "user", "x " * 120,
     "no EXTENSION manifest " * 3],
    ["", "Drives Overview", "1.0", "bundled", "A panel with every drive " * 6, "off"],
]


def _ext_table(rows=_EXT_ROWS):
    from PyQt6.QtWidgets import QTableWidgetItem

    t = QTableWidget(len(rows), 6)
    t.setHorizontalHeaderLabels(["On", "Name", "Version", "Source", "Description", "Status"])
    for r, row in enumerate(rows):
        for c, text in enumerate(row):
            t.setItem(r, c, QTableWidgetItem(text))
    return t


def _kept_need(t, col):
    return min(t.sizeHintForColumn(col), t.viewport().width() // 3)


@pytest.mark.parametrize("width", [900, 560, 400])
def test_happy_a_kept_column_gets_its_content_before_the_others_share(width):
    from ui.column_fit import ColumnFitter

    t = _ext_table()
    ColumnFitter(t, fill=4, keep=(1,))
    _show(t, width)
    w = _widths(t)
    assert w[1] >= _kept_need(t, 1), (width, w)
    assert all(x >= t.horizontalHeader().minimumSectionSize() for x in w), w


def test_sad_without_keep_the_name_is_squeezed_the_reported_look():
    """Negative control: the old fit gives Name less than it needs."""
    from ui.column_fit import ColumnFitter

    t = _ext_table()
    ColumnFitter(t, fill=4)
    _show(t, 560)
    assert _widths(t)[1] < _kept_need(t, 1)


def test_sad_keep_naming_a_missing_hidden_or_the_fill_column_does_not_fail():
    from ui.column_fit import ColumnFitter

    t = _ext_table()
    t.setColumnHidden(3, True)
    ColumnFitter(t, fill=4, keep=(1, 3, 4, 99))
    _show(t, 560)
    w = _widths(t)
    assert w[1] >= _kept_need(t, 1)
    assert t.horizontalHeader().isSectionHidden(3)


def test_edge_a_dragged_kept_column_keeps_the_dragged_width():
    from ui.column_fit import ColumnFitter

    t = _ext_table()
    fitter = ColumnFitter(t, fill=4, keep=(1,))
    _show(t, 700)
    t.horizontalHeader().resizeSection(1, 40)  # the user makes it narrow
    APP.processEvents()
    APP.processEvents()
    assert 1 in fitter.user_sized
    t.resize(500, 300)
    APP.processEvents()
    APP.processEvents()
    assert _widths(t)[1] == 40


def test_edge_a_short_kept_column_takes_no_more_than_its_content():
    from ui.column_fit import ColumnFitter

    rows = [["", "Ab", "1.0", "user", "x " * 120, "off"]]
    t = _ext_table(rows)
    ColumnFitter(t, fill=4, keep=(1,))
    _show(t, 560)
    h = t.horizontalHeader()
    content = max(t.sizeHintForColumn(1), h.sectionSizeHint(1), h.minimumSectionSize())
    assert _widths(t)[1] <= content


@pytest.mark.parametrize(
    "module, name_col",
    [
        ("ui/extensions_dialog.py", "1, 2, 3"),
        ("ui/find_files_dialog.py", "COL_NAME"),
        ("ui/metadata_search_dialog.py", "0"),
        ("ui/cas_dialog.py", "COL_NAME"),
    ],
)
def test_happy_views_whose_fill_is_not_the_name_keep_the_name(module, name_col):
    """The same squeeze in every view where a path or description fills
    and the name is one of the others."""
    text = (ROOT / module).read_text(encoding="utf-8")
    assert re.search(rf"ColumnFitter\([^)]*keep=\({name_col},?\)", text), module


def test_happy_with_kept_columns_the_others_keep_their_header_label():
    """A long description fills, a long error is the status: the fill gives
    way so "Version" and "Status" stay readable instead of "…"."""
    from ui.column_fit import ColumnFitter

    t = _ext_table()
    ColumnFitter(t, fill=4, keep=(1, 2, 3))
    _show(t, 560)
    h = t.horizontalHeader()
    w = _widths(t)
    for c in (2, 3, 5):  # Version, Source, Status
        assert w[c] >= h.sectionSizeHint(c), (c, w)
    assert sum(w) == t.viewport().width(), w


def test_edge_when_not_even_the_labels_fit_the_share_stays_proportional():
    from ui.column_fit import ColumnFitter

    t = _ext_table()
    ColumnFitter(t, fill=4, keep=(1, 2, 3))
    _show(t, 300)
    h = t.horizontalHeader()
    w = _widths(t)
    assert all(x >= h.minimumSectionSize() for x in w), w
    assert w[1] >= _kept_need(t, 1), w
