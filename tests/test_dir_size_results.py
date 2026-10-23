"""Calculate Size: a sortable result table, and the size in the pane.

Operator (punch list 38): "wenn fertig tabellenausgabe in der man z.b. auch
sortieren kann nach name, größe...etc.pp." and (39): "wenn da größe
kalkuliert wurde auch im normalen pane anzeigen z.b. interessant bei
verzeichnissen". Before, the result was a message box with one
"name: size" line per folder, and the pane's Size column stayed empty for
folders.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, QItemSelectionModel, QPoint, Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from core.tree_size import TreeSize  # noqa: E402
from models.file_table_model import COL_NAME, COL_SIZE  # noqa: E402

APP = QApplication.instance() or QApplication([])
GiB = 1024**3


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


def wait_until(cond, timeout: float = 10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return cond()


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "root"
    big = root / "big"
    (big / "inner" / "deeper").mkdir(parents=True)
    (big / "a.bin").write_bytes(b"x" * 100)
    (big / "inner" / "b.bin").write_bytes(b"x" * 150)
    (big / "inner" / "deeper" / "c.bin").write_bytes(b"x" * 50)
    small = root / "small"
    small.mkdir()
    (small / "d.bin").write_bytes(b"x" * 10)
    (root / "mid").mkdir()
    (root / "mid" / "e.bin").write_bytes(b"x" * 40)
    (root / "loose.txt").write_bytes(b"x" * 5)
    (tmp_path / "elsewhere" / "big").mkdir(parents=True)
    return root


@pytest.fixture
def pane(tree, tmp_path, monkeypatch):
    from ui import column_prefs as CP
    from ui.file_pane import FilePaneWidget

    monkeypatch.setattr(CP, "DEFAULT_PATH", tmp_path / "cols.json")
    widget = FilePaneWidget(LocalFS())
    widget.resize(900, 500)
    widget.show()
    widget.navigate(str(tree))
    pump()
    yield widget
    dialog = getattr(widget, "_size_dialog", None)
    if dialog is not None:
        dialog.close()
    widget.shutdown()
    widget.close()
    widget.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    pump()


def _select(pane, *names) -> None:
    proxy = pane._table.model()
    sel = pane._table.selectionModel()
    sel.clearSelection()
    for row in range(proxy.rowCount()):
        if proxy.index(row, 0).data() in names:
            sel.select(
                proxy.index(row, 0),
                QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows,
            )
    pump()


def _calculate(pane, *names) -> None:
    """Through the right-click entry, as a user does."""
    _select(pane, *names)
    menu = pane._build_context_menu()
    action = next(a for a in menu.actions() if a.property("axCommand") == "calculate-size")
    action.trigger()
    assert wait_until(lambda: pane._size_job is not None and not pane._size_job.running)
    pump()


def _size_cell(pane, name: str) -> str:
    proxy = pane._proxy
    for row in range(proxy.rowCount()):
        if proxy.index(row, COL_NAME).data() == name:
            return proxy.index(row, COL_SIZE).data()
    raise AssertionError(name)


def _names_in_order(pane) -> list[str]:
    proxy = pane._proxy
    return [proxy.index(r, COL_NAME).data() for r in range(proxy.rowCount())]


def _click_header(view, section: int) -> None:
    header = view.horizontalHeader()
    x = header.sectionViewportPosition(section) + header.sectionSize(section) // 2
    QTest.mouseClick(header.viewport(), Qt.MouseButton.LeftButton, pos=QPoint(x, 5))
    pump()


# --- happy -----------------------------------------------------------------


def test_happy_e2e_the_result_is_a_table_with_totals(pane, tree):
    _calculate(pane, "big", "small", "mid")
    dialog = pane._size_dialog
    assert dialog is not None and dialog.isVisible()
    rows = {r[0]: r for r in dialog.displayed_rows()}
    assert set(rows) == {"big", "small", "mid"}
    assert rows["big"][1:5] == ("300 B", "3", "2", "85.7 %")
    assert rows["small"][1:5] == ("10 B", "1", "0", "2.9 %")
    assert rows["mid"][1:5] == ("40 B", "1", "0", "11.4 %")
    assert dialog.total_text() == "Total: 350 B, 5 files, 2 folders"


@pytest.mark.parametrize(
    ("column", "ascending"),
    [
        (0, ["big", "mid", "small"]),
        (1, ["small", "mid", "big"]),
        (2, ["mid", "small", "big"]),  # files 1, 1, 3: ties keep the name order
        (3, ["mid", "small", "big"]),
        (4, ["small", "mid", "big"]),
    ],
)
def test_happy_e2e_every_column_sorts_both_ways(pane, column, ascending):
    _calculate(pane, "big", "small", "mid")
    dialog = pane._size_dialog
    view = dialog.table
    dialog.model.sort(0, Qt.SortOrder.AscendingOrder)  # a known start: by name
    header = view.horizontalHeader()
    _click_header(view, column)
    first = [r[0] for r in dialog.displayed_rows()]
    _click_header(view, column)
    second = [r[0] for r in dialog.displayed_rows()]
    assert header.sortIndicatorSection() == column
    if header.sortIndicatorOrder() == Qt.SortOrder.AscendingOrder:
        asc_rows, desc_rows = second, first
    else:
        asc_rows, desc_rows = first, second
    assert asc_rows == ascending
    if column in (2, 3):  # big has the most; the tie keeps the name order
        assert desc_rows == ["big", "mid", "small"]
    else:
        assert desc_rows == ascending[::-1]


def test_happy_e2e_the_pane_shows_and_sorts_by_the_computed_size(pane):
    assert _size_cell(pane, "big") == ""  # a folder shows no size before
    _calculate(pane, "big", "small", "mid")
    assert _size_cell(pane, "big") == "300 B"
    assert _size_cell(pane, "small") == "10 B"
    assert _size_cell(pane, "mid") == "40 B"
    pane._table.sortByColumn(COL_SIZE, Qt.SortOrder.DescendingOrder)
    pump()
    folders = [n for n in _names_in_order(pane) if n in ("big", "small", "mid")]
    assert folders == ["big", "mid", "small"]
    pane._table.sortByColumn(COL_SIZE, Qt.SortOrder.AscendingOrder)
    pump()
    folders = [n for n in _names_in_order(pane) if n in ("big", "small", "mid")]
    assert folders == ["small", "mid", "big"]


def test_happy_a_size_arriving_while_sorted_by_size_resorts_at_once(pane):
    pane._table.sortByColumn(COL_SIZE, Qt.SortOrder.DescendingOrder)
    pump()
    _calculate(pane, "big", "small", "mid")
    folders = [n for n in _names_in_order(pane) if n in ("big", "small", "mid")]
    assert folders == ["big", "mid", "small"]


# --- sad -------------------------------------------------------------------


def test_sad_a_failed_walk_shows_a_warning_and_no_table(pane, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("backend went away")

    monkeypatch.setattr("core.tree_size.tree_size", boom)
    with mock.patch("ui.file_pane.QMessageBox.warning") as warning:
        _calculate(pane, "big")
    assert warning.called and "backend went away" in warning.call_args[0][2]
    assert getattr(pane, "_size_dialog", None) is None
    assert _size_cell(pane, "big") == ""


def test_sad_a_cancelled_walk_changes_nothing(pane):
    _select(pane, "big")
    pane._calculate_dir_size()
    pane._cancel_dir_size()
    assert wait_until(lambda: not pane._size_job.running)
    pump()
    if getattr(pane, "_size_dialog", None) is None:  # cancelled before the end
        assert _size_cell(pane, "big") == ""


def test_sad_a_result_for_a_folder_left_meanwhile_is_not_put_into_the_new_one(pane, tree):
    _select(pane, "big")
    pane._calculate_dir_size()
    origin = pane._size_origin
    assert wait_until(lambda: not pane._size_job.running)
    # Replay the finish after a move to a folder with a same-named "big".
    pane.navigate(str(tree.parent / "elsewhere"))
    pump()
    pane._size_origin = origin
    pane._on_dir_size_finished("done", [("big", TreeSize(bytes=999, files=1, folders=1))], False)
    pump()
    assert _size_cell(pane, "big") == ""
    assert pane._size_dialog is not None  # the table still reports it


def test_sad_an_unreadable_part_marks_the_size_as_a_lower_bound(pane, tree):
    locked = tree / "big" / "inner"
    locked.chmod(0)
    try:
        _calculate(pane, "big")
    finally:
        locked.chmod(0o755)
    if os.geteuid() == 0:
        pytest.skip("root reads every folder")
    assert _size_cell(pane, "big") == "≥ 100 B"
    (row,) = pane._size_dialog.displayed_rows()
    assert row[1] == "≥ 100 B" and "could not be read" in row[5]


# --- edge ------------------------------------------------------------------


def test_edge_sizes_over_2_gib_survive_the_signal_and_sort(pane, monkeypatch):
    sizes = {"big": 5 * GiB, "small": 3 * GiB, "mid": 100}

    def fake(backend, path, **_kw):
        return TreeSize(bytes=sizes[Path(path).name], files=1, folders=1)

    monkeypatch.setattr("core.tree_size.tree_size", fake)
    _calculate(pane, "big", "small", "mid")
    assert _size_cell(pane, "big") == "5.0 GB"
    assert _size_cell(pane, "small") == "3.0 GB"
    pane._table.sortByColumn(COL_SIZE, Qt.SortOrder.DescendingOrder)
    pump()
    folders = [n for n in _names_in_order(pane) if n in sizes]
    assert folders == ["big", "small", "mid"]
    dialog = pane._size_dialog
    dialog.model.sort(1, Qt.SortOrder.DescendingOrder)
    assert [r[0] for r in dialog.displayed_rows()] == ["big", "small", "mid"]
    assert dialog.model.raw_bytes() == [5 * GiB, 3 * GiB, 100]


def test_edge_a_reload_or_another_folder_clears_the_computed_size(pane, tree):
    _calculate(pane, "big")
    assert _size_cell(pane, "big") == "300 B"
    pane.refresh()
    pump()
    assert wait_until(lambda: not pane.is_loading)
    assert _size_cell(pane, "big") == ""
    _calculate(pane, "big")
    pane.navigate(str(tree / "big"))
    pump()
    pane.navigate(str(tree))
    pump()
    assert _size_cell(pane, "big") == ""


def test_edge_empty_folders_give_no_division_by_zero(pane, tree):
    (tree / "empty1").mkdir()
    (tree / "empty2").mkdir()
    pane.refresh()
    assert wait_until(lambda: not pane.is_loading)
    pump()
    _calculate(pane, "empty1", "empty2")
    rows = pane._size_dialog.displayed_rows()
    assert [r[4] for r in rows] == ["—", "—"]
    assert _size_cell(pane, "empty1") == "0 B"


def test_edge_the_table_has_the_close_corner_and_escape_closes_it(pane):
    from PyQt6.QtWidgets import QToolButton

    _calculate(pane, "big")
    dialog = pane._size_dialog
    assert dialog.findChildren(QToolButton, "axCloseCorner")
    QTest.keyClick(dialog, Qt.Key.Key_Escape)
    pump()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    pump()
    assert pane._size_dialog is None  # closed and deleted


def test_edge_a_second_calculation_replaces_the_first_table(pane):
    _calculate(pane, "big")
    first = pane._size_dialog
    _calculate(pane, "small")
    assert pane._size_dialog is not first
    assert [r[0] for r in pane._size_dialog.displayed_rows()] == ["small"]
    assert _size_cell(pane, "big") == "300 B"  # still this listing: kept


# --- the selection stays on its folder when the table is sorted (bughunt
# 2026-10-22: DirSizeModel.sort moved the rows but not the persistent indexes,
# so a selected folder's highlight stayed on its row number and marked another
# folder after a click on a header) ---------------------------------------------


def _selected_names(dialog) -> list[str]:
    rows = dialog.model.rows()
    return sorted(rows[i.row()].name for i in dialog.table.selectionModel().selectedRows())


def test_edge_e2e_the_selection_follows_its_folder_when_sorted(pane):
    _calculate(pane, "big", "small", "mid")
    dialog = pane._size_dialog
    view = dialog.table
    view.selectRow(0)  # largest first: "big"
    pump()
    assert _selected_names(dialog) == ["big"]
    _click_header(view, 0)  # by name
    assert _selected_names(dialog) == ["big"]
    assert dialog.model.rows()[view.currentIndex().row()].name == "big"
    _click_header(view, 1)  # by size again
    assert _selected_names(dialog) == ["big"]


def test_edge_a_selection_of_two_folders_survives_every_sort(pane):
    _calculate(pane, "big", "small", "mid")
    dialog = pane._size_dialog
    model, view = dialog.model, dialog.table
    names = [r.name for r in model.rows()]
    selection = view.selectionModel()
    for name in ("small", "mid"):
        index = model.index(names.index(name), 0)
        selection.select(index, QItemSelectionModel.SelectionFlag.Select
                         | QItemSelectionModel.SelectionFlag.Rows)
    for column in range(model.columnCount()):
        for order in (Qt.SortOrder.AscendingOrder, Qt.SortOrder.DescendingOrder):
            model.sort(column, order)
            assert _selected_names(dialog) == ["mid", "small"], (column, order)


def test_sad_sorting_by_a_column_that_does_not_exist_changes_nothing(pane):
    _calculate(pane, "big", "small", "mid")
    dialog = pane._size_dialog
    before = [r.name for r in dialog.model.rows()]
    dialog.model.sort(99)
    assert [r.name for r in dialog.model.rows()] == before
