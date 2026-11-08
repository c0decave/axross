"""File pane: a filter change, Show Hidden Files and a sort keep the
selection on the entries selected - never more, never others.

Found in the final review: with the pane's own proxy (no longer a
QSortFilterProxyModel) a filter change was one layout change. Over a
layout change QItemSelectionModel takes a shortcut while one range selects
the whole table (more than 1000 cells): it selects the whole table again
when the row count stayed, else it keeps the range from its first to its
last entry. Click ".", Shift+click the last of 250 photos, View > Show
Hidden Files: .ssh, .gnupg and .bashrc were selected for F6/F8. A filter
switch to as many other entries selected all of them; a narrowing filter
dropped the whole selection. Now the proxy reports which rows went and
came as row removals and insertions, run by run (a change of thousands of
runs: the first run so, the rest as a layout change once the selection is
held as ranges).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt6.QtCore import QItemSelection, QItemSelectionModel, Qt  # noqa: E402
from PyQt6.QtWidgets import QAbstractItemView, QApplication, QTableView  # noqa: E402

from models.file_item import FileItem  # noqa: E402
from models.file_table_model import (  # noqa: E402
    COL_NAME,
    COL_SIZE,
    FileSortProxyModel,
    FileTableModel,
)

APP = QApplication.instance() or QApplication([])


def _names() -> list[str]:
    return ([f"a{i:03d}" for i in range(400)] + [f"b{i:03d}" for i in range(400)]
            + [f".h{i:03d}" for i in range(60)])


def _setup(names=None):
    model = FileTableModel()
    proxy = FileSortProxyModel()
    proxy.setSourceModel(model)
    proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
    view = QTableView()
    view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    view.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
    view.setModel(proxy)
    model.sort(COL_NAME, Qt.SortOrder.AscendingOrder)
    model.set_items([FileItem(name=".", is_dir=True), FileItem(name="..", is_dir=True)]
                    + [FileItem(name=n, size=i % 7) for i, n in enumerate(names or _names())])
    return model, proxy, view


def _selected(model, proxy, view) -> set[str]:
    return {model.get_item(proxy.mapToSource(i).row()).name
            for i in view.selectionModel().selectedRows(0)}


def _shown(model, proxy) -> set[str]:
    return {model.get_item(proxy.mapToSource(proxy.index(r, 0)).row()).name
            for r in range(proxy.rowCount())}


def _select_whole_table(proxy, view) -> None:
    """One range over every shown cell, as Shift+click from "." to the last
    row makes it - the selection QItemSelectionModel's shortcut takes."""
    view.selectionModel().select(
        QItemSelection(proxy.index(0, 0),
                       proxy.index(proxy.rowCount() - 1, proxy.columnCount() - 1)),
        QItemSelectionModel.SelectionFlag.ClearAndSelect)
    assert proxy.rowCount() * proxy.columnCount() > 1000  # the shortcut's size


class _Signals:
    def __init__(self, proxy):
        self.layouts = self.removed = self.inserted = 0
        proxy.layoutChanged.connect(self._layout)
        proxy.rowsRemoved.connect(self._removed)
        proxy.rowsInserted.connect(self._inserted)

    def _layout(self, *_a):
        self.layouts += 1

    def _removed(self, *_a):
        self.removed += 1

    def _inserted(self, *_a):
        self.inserted += 1


# -- happy --------------------------------------------------------------------------------------


def test_happy_show_hidden_after_a_whole_table_selection_selects_no_hidden_entry():
    model, proxy, view = _setup()
    _select_whole_table(proxy, view)
    before = _selected(model, proxy, view)
    signals = _Signals(proxy)
    proxy.show_hidden = True
    assert ".h000" in _shown(model, proxy)
    assert _selected(model, proxy, view) == before
    assert signals.layouts == 0 and signals.inserted >= 1  # rows came: inserted
    proxy.show_hidden = False
    assert _selected(model, proxy, view) == before


def test_happy_a_filter_switch_to_as_many_other_entries_selects_none_of_them():
    model, proxy, view = _setup()
    proxy.setFilterFixedString("a")
    _select_whole_table(proxy, view)
    proxy.setFilterFixedString("b")  # 402 rows before and after, other entries
    assert _selected(model, proxy, view) == {".", ".."}


def test_happy_a_narrowing_filter_keeps_the_selected_entries_still_shown():
    model, proxy, view = _setup()
    _select_whole_table(proxy, view)
    proxy.setFilterFixedString("a0")
    expected = {".", ".."} | {f"a0{i:02d}" for i in range(100)}
    assert _shown(model, proxy) == expected
    assert _selected(model, proxy, view) == expected
    proxy.setFilterFixedString("")  # widened: the entries back are not selected
    assert _selected(model, proxy, view) == expected


@pytest.mark.parametrize("column, order", [(COL_NAME, Qt.SortOrder.DescendingOrder),
                                           (COL_SIZE, Qt.SortOrder.AscendingOrder)])
def test_happy_a_sort_keeps_a_whole_table_and_a_partial_selection(column, order):
    model, proxy, view = _setup()
    _select_whole_table(proxy, view)
    everything = _selected(model, proxy, view)
    proxy.sort(column, order)
    assert _selected(model, proxy, view) == everything == _shown(model, proxy)
    proxy.setFilterFixedString("1")
    narrowed = _selected(model, proxy, view)
    assert narrowed == _shown(model, proxy)
    proxy.sort(COL_NAME, Qt.SortOrder.AscendingOrder)
    assert _selected(model, proxy, view) == narrowed


def test_happy_the_reviewers_sequence_keeps_the_selection_on_its_entries():
    """Whole table selected from the "." row, then Show Hidden, a same-count
    filter switch, a narrowing filter and a sort."""
    model, proxy, view = _setup()
    _select_whole_table(proxy, view)
    expected = _selected(model, proxy, view)
    for step in (lambda: setattr(proxy, "show_hidden", True),
                 lambda: proxy.setFilterFixedString("0"),
                 lambda: proxy.sort(COL_SIZE, Qt.SortOrder.DescendingOrder),
                 lambda: proxy.setFilterFixedString(""),
                 lambda: proxy.setFilterFixedString("00"),
                 lambda: proxy.sort(COL_NAME, Qt.SortOrder.AscendingOrder)):
        step()
        expected &= _shown(model, proxy)
        assert _selected(model, proxy, view) == expected
    assert expected >= {".", "..", "a000", "a100", "b200"}
    assert not [name for name in expected if name.startswith(".h")]
    proxy.setFilterFixedString("a")
    _select_whole_table(proxy, view)
    proxy.setFilterFixedString("b")  # as many rows, other entries
    assert _selected(model, proxy, view) == {".", ".."}


# -- edge ---------------------------------------------------------------------------------------


def test_edge_thousands_of_runs_keep_the_selection_and_are_no_signal_per_run():
    names = [f"{i:05d}{'x' if i % 2 else 'y'}" for i in range(6000)]  # 3000 runs a switch
    model, proxy, view = _setup(names)
    _select_whole_table(proxy, view)
    signals = _Signals(proxy)
    proxy.setFilterFixedString("x")
    expected = {".", ".."} | {n for n in names if n.endswith("x")}
    assert _selected(model, proxy, view) == expected == _shown(model, proxy)
    assert signals.removed + signals.inserted <= 2 and signals.layouts == 1
    proxy.setFilterFixedString("y")  # as many rows, every one another entry
    assert _selected(model, proxy, view) == {".", ".."}
    proxy.setFilterFixedString("")
    assert _selected(model, proxy, view) == {".", ".."}
    # Only insertions: the first run is inserted as such, then the layout.
    proxy.setFilterFixedString("x")
    _select_whole_table(proxy, view)
    signals.layouts = signals.removed = signals.inserted = 0
    proxy.setFilterFixedString("")
    assert _selected(model, proxy, view) == expected
    assert (signals.removed, signals.inserted, signals.layouts) == (0, 1, 1)


def test_edge_a_partial_selection_and_the_current_row_follow_their_entries():
    model, proxy, view = _setup()
    sel = view.selectionModel()
    flags = QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows
    picked = ["a005", "a150", "b007", "b399"]
    for row in range(proxy.rowCount()):
        if model.get_item(proxy.mapToSource(proxy.index(row, 0)).row()).name in picked:
            sel.select(proxy.index(row, 0), flags)
            if model.get_item(proxy.mapToSource(proxy.index(row, 0)).row()).name == "a150":
                sel.setCurrentIndex(proxy.index(row, 0),
                                    QItemSelectionModel.SelectionFlag.NoUpdate)

    def current() -> str:
        return model.get_item(proxy.mapToSource(sel.currentIndex()).row()).name

    proxy.show_hidden = True
    proxy.setFilterFixedString("5")
    assert _selected(model, proxy, view) == {"a005", "a150"} and current() == "a150"
    proxy.sort(COL_SIZE, Qt.SortOrder.DescendingOrder)
    proxy.setFilterFixedString("")
    assert _selected(model, proxy, view) == {"a005", "a150"} and current() == "a150"


# -- sad ----------------------------------------------------------------------------------------


def test_sad_a_filter_that_matches_nothing_leaves_only_the_navigation_rows_selected():
    model, proxy, view = _setup()
    _select_whole_table(proxy, view)
    proxy.setFilterFixedString("no-such-entry")
    assert _shown(model, proxy) == {".", ".."}
    assert _selected(model, proxy, view) == {".", ".."}
    proxy.setFilterFixedString("")
    assert _selected(model, proxy, view) == {".", ".."}


# -- the pane, as the reviewer clicked it --------------------------------------------------------


def test_happy_pane_shift_click_from_dot_then_show_hidden_selects_no_dot_file(tmp_path):
    from PyQt6.QtTest import QTest

    from core.local_fs import LocalFS
    from ui.file_pane import FilePaneWidget

    for i in range(250):
        (tmp_path / f"photo{i:03d}.jpg").touch()
    (tmp_path / ".ssh").mkdir()
    (tmp_path / ".gnupg").mkdir()
    (tmp_path / ".bashrc").touch()
    pane = FilePaneWidget(LocalFS())
    try:
        pane.resize(900, 700)
        pane.show()
        pane.set_show_hidden(False)
        pane.navigate(str(tmp_path))
        view, proxy = pane._table, pane._proxy
        assert proxy.rowCount() == 252
        view.scrollToTop()
        QTest.mouseClick(view.viewport(), Qt.MouseButton.LeftButton,
                         Qt.KeyboardModifier.NoModifier, view.visualRect(proxy.index(0, 0)).center())
        last = proxy.index(proxy.rowCount() - 1, 0)
        view.scrollTo(last)
        QTest.mouseClick(view.viewport(), Qt.MouseButton.LeftButton,
                         Qt.KeyboardModifier.ShiftModifier, view.visualRect(last).center())
        before = sorted(os.path.basename(p) for p in pane.selected_items())
        assert len(before) == 250 and not [n for n in before if n.startswith(".")]
        pane.set_show_hidden(True)
        assert proxy.rowCount() == 255
        assert sorted(os.path.basename(p) for p in pane.selected_items()) == before
    finally:
        pane.shutdown()
        pane.deleteLater()
