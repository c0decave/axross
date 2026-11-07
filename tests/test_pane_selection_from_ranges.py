"""The pane reads its selected rows off the selection's ranges.

Measured on 2026-11-02 (feedback: optimise everything, measured): with
20 000 entries selected, QItemSelectionModel.selectedRows() took 0.4 s on
the GUI thread - it asks the model for the flags of every column of every
row - on every copy (F5), every refresh of the folder (the selection is
kept by name) and every right-click. The table selects whole rows, so the
rows are the ranges' rows; the proxy maps them by index. Same rows, same
order; a range that is not whole rows falls back to selectedRows().
"""

from __future__ import annotations

import os
import random
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QItemSelection, QItemSelectionModel  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from models.file_table_model import COL_NAME  # noqa: E402

APP = QApplication.instance() or QApplication([])
F = QItemSelectionModel.SelectionFlag


@pytest.fixture
def pane(tmp_path):
    from ui.file_pane import FilePaneWidget

    for i in range(120):
        (tmp_path / (f".hidden{i}" if i % 7 == 0 else f"f{i:03d}.txt")).write_text("x")
    for i in range(10):
        (tmp_path / f"dir{i}").mkdir()
    p = FilePaneWidget(LocalFS())
    p.navigate(str(tmp_path))
    yield p
    p.shutdown()
    p.deleteLater()


def _qt_rows(pane) -> list[int]:
    return [i.row() for i in pane._table.selectionModel().selectedRows(COL_NAME)]


def _qt_items(pane) -> list:
    return [pane._model.get_item(pane._proxy.mapToSource(i).row())
            for i in pane._table.selectionModel().selectedRows(COL_NAME)]


def _random_selection(pane, rnd: random.Random) -> None:
    proxy, sel = pane._proxy, pane._table.selectionModel()
    sel.clearSelection()
    rows = proxy.rowCount()
    for _ in range(rnd.randint(1, 6)):
        top = rnd.randrange(rows)
        bottom = min(rows - 1, top + rnd.randint(0, 30))
        flag = rnd.choice([F.Select, F.Toggle, F.Deselect])
        sel.select(QItemSelection(proxy.index(top, 0), proxy.index(bottom, 0)), flag | F.Rows)


def test_happy_the_rows_and_items_are_selectedrows_own(pane):
    rnd = random.Random(11)
    for round_ in range(60):
        if round_ == 20:
            pane.set_show_hidden(True)
        if round_ == 40:
            pane._proxy.setFilterFixedString("1")
        _random_selection(pane, rnd)
        assert pane._selected_rows() == _qt_rows(pane), round_
        assert pane._selected_source_items() == _qt_items(pane), round_


def test_happy_select_all_and_invert_read_the_same(pane):
    pane._select_all()
    assert pane._selected_rows() == _qt_rows(pane)
    pane._invert_selection()
    assert pane._selected_rows() == _qt_rows(pane)
    names = [item.name for item in pane.selected_file_items()]
    assert names == [i.name for i in _qt_items(pane) if not i.is_nav]


def test_edge_a_single_cell_selected_by_code_falls_back_to_qt(pane):
    """selectedRows() leaves out a row of which only some columns are
    selected; the ranges are not whole rows then, and Qt is asked."""
    proxy, sel = pane._proxy, pane._table.selectionModel()
    sel.clearSelection()
    sel.select(proxy.index(3, 0), F.Select)  # one cell, no Rows flag
    sel.select(proxy.index(5, 0), F.Select | F.Rows)
    assert pane._selected_rows() == _qt_rows(pane) == [5]


def test_perf_twenty_thousand_selected_rows_are_read_quickly(tmp_path):
    from core.ram_fs import RamFsSession
    from ui.file_pane import FilePaneWidget

    fs = RamFsSession(max_bytes=1 << 30, system_reserve_bytes=0)
    fs.mkdir("/big")
    for i in range(20000):
        with fs.open_write(f"/big/f{i:05d}") as fh:
            fh.write(b"x")
    pane = FilePaneWidget(fs)
    try:
        pane.navigate("/big")
        pane._select_all()
        start = time.perf_counter()
        qt = _qt_rows(pane)
        qt_took = time.perf_counter() - start
        start = time.perf_counter()
        ours = pane._selected_rows()
        took = time.perf_counter() - start
        assert ours == qt and len(ours) >= 20000  # and ".."
        assert took < qt_took / 5, (took, qt_took)
    finally:
        pane.shutdown()
        pane.deleteLater()


def _selected_names(pane) -> list[str]:
    return sorted(i.name for i in _qt_items(pane))


def test_happy_a_refresh_keeps_the_selection_and_the_current_row(pane):
    """The selection is taken by name and given back after the reload - in
    one range per run of adjacent rows now (one per row made Qt merge
    20 000 ranges: 2 s per refresh of a folder with everything selected)."""
    rnd = random.Random(5)
    for round_ in range(15):
        _random_selection(pane, rnd)
        sel = pane._table.selectionModel()
        rows = _qt_rows(pane)
        if rows:
            sel.setCurrentIndex(pane._proxy.index(rnd.choice(rows), 0), F.NoUpdate)
        before = _selected_names(pane)
        current = sel.currentIndex().data()
        pane.refresh()
        assert _selected_names(pane) == before, round_
        if before:
            assert pane._table.selectionModel().currentIndex().data() == current, round_


def test_perf_everything_selected_comes_back_as_one_range(pane):
    pane._select_all()
    count = len(_qt_rows(pane))
    pane.refresh()
    ranges = list(pane._table.selectionModel().selection())
    assert len(ranges) == 1 and ranges[0].height() == count
