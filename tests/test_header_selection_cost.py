"""Select All in a large folder no longer freezes the window.

A table's column header paints each section with whether its neighbours
are selected, and Qt answers "is this column selected" by asking the
model for the flags of every row. With 30 000 files selected, each header
repaint asked 150 000 times through Python: Select All froze the window
for about a second, and so did leaving the folder while the selection
stood. The header now gets an empty selection model of its own
(ui.column_fit.detach_header_selection); a list selecting whole rows
never shows a column as selected anyway. Measured by the number of model
calls, not by time.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt  # noqa: E402
from PyQt6.QtWidgets import QAbstractItemView, QApplication, QTableView  # noqa: E402

from models.file_item import FileItem  # noqa: E402

APP = QApplication.instance() or QApplication([])

ROWS = 4000


def _settle(rounds: int = 6) -> None:
    for _ in range(rounds):
        APP.processEvents()


def _pane(n: int = ROWS):
    from core.local_fs import LocalFS
    from ui.file_pane import FilePaneWidget

    with mock.patch.object(FilePaneWidget, "navigate", lambda *a, **k: None):
        pane = FilePaneWidget(LocalFS())
    pane._model.set_items([FileItem(name=f"file_{i:05d}.txt", size=i) for i in range(n)])
    pane.resize(900, 500)
    pane.show()
    _settle()
    return pane


def _count_flags(model_class):
    calls = []
    real = model_class.flags

    def counted(self, index):
        calls.append(1)
        return real(self, index)

    return calls, mock.patch.object(model_class, "flags", counted)


def test_happy_select_all_asks_the_model_about_the_shown_rows_only():
    """Select All repaints the header and the shown rows: a few hundred
    flag reads, not one per cell of the folder (5 x 4000 before)."""
    from models.file_table_model import FileTableModel

    pane = _pane()
    try:
        calls, patch = _count_flags(FileTableModel)
        with patch:
            pane._table.selectAll()
            pane._table.horizontalHeader().viewport().repaint()
            _settle()
        assert len(pane._selected_rows()) == ROWS
        assert len(calls) < ROWS, len(calls)
    finally:
        pane.close()
        pane.deleteLater()
        _settle()


def test_happy_the_header_still_sorts_on_a_click():
    """The header keeps working: a click on Size sorts by size."""
    pane = _pane(50)
    try:
        header = pane._table.horizontalHeader()
        from models.file_table_model import COL_SIZE

        header.sectionClicked.emit(COL_SIZE)
        pane._table.sortByColumn(COL_SIZE, Qt.SortOrder.DescendingOrder)
        _settle()
        first = pane._proxy.data(pane._proxy.index(0, 0))
        assert first == "file_00049.txt"
    finally:
        pane.close()
        pane.deleteLater()
        _settle()


def test_edge_the_view_keeps_its_own_selection_model():
    """Only the header's selection model changes: the pane's selection
    (and its selectionChanged listeners) stay on the table's."""
    pane = _pane(20)
    try:
        table = pane._table
        assert table.horizontalHeader().selectionModel() is not table.selectionModel()
        seen = []
        pane.selection_changed.connect(lambda: seen.append(1))
        table.selectRow(3)
        assert seen and pane._selected_rows() == [3]
    finally:
        pane.close()
        pane.deleteLater()
        _settle()


class _Model(QAbstractTableModel):
    def __init__(self, rows: int) -> None:
        super().__init__()
        self.rows = rows
        self.flag_calls = 0

    def rowCount(self, parent=QModelIndex()):  # noqa: N802 - Qt override
        return self.rows

    def columnCount(self, parent=QModelIndex()):  # noqa: N802 - Qt override
        return 4

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        return "x" if role == Qt.ItemDataRole.DisplayRole else None

    def flags(self, index):
        self.flag_calls += 1
        return Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled


@pytest.mark.parametrize("detach", [False, True])
def test_edge_detach_header_selection_on_a_plain_table(detach):
    """The helper on its own: without it a selected-everything repaint
    reads every cell's flags; with it only the shown ones."""
    from ui.column_fit import detach_header_selection

    model = _Model(ROWS)
    view = QTableView()
    view.setModel(model)
    view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    if detach:
        detach_header_selection(view)
    view.resize(600, 400)
    view.show()
    _settle()
    try:
        model.flag_calls = 0
        view.selectAll()
        view.horizontalHeader().viewport().repaint()
        _settle()
        if detach:
            assert model.flag_calls < ROWS, model.flag_calls
        else:
            assert model.flag_calls >= ROWS, model.flag_calls
    finally:
        view.close()
        view.deleteLater()
        _settle()


def test_sad_a_view_without_a_model_is_left_alone():
    from ui.column_fit import detach_header_selection

    view = QTableView()
    detach_header_selection(view)
    assert view.horizontalHeader().selectionModel() is None
    view.deleteLater()
