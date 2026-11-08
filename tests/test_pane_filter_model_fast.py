"""File pane: the filter works over the model's lists, not per row in Qt.

Measured before (scripts/pane_bench.py, 100,000 entries): nine filter keys
made Qt call the Python ``FileSortProxyModel.filterAcceptsRow`` 900,000
times (12.7 s of 16.1 s); every key cost 350-500 ms of GUI time, opening the
folder stalled the window 300-500 ms in ``endResetModel`` and a sort, and
select-all mapped every row through the proxy (300-500 ms). Now the proxy
keeps the shown rows as one list, worked out over casefolded names the
model keeps (on the listing thread for a new listing), narrowing the
previous result when the filter text grows.

The guards count work instead of timing it: entries read per filter pass,
rows mapped by select-all, calls into Python per row.
"""

from __future__ import annotations

import os
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt6.QtCore import QItemSelectionModel, QModelIndex, Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication, QTableView  # noqa: E402

from models import file_table_model as M  # noqa: E402
from models.file_item import FileItem  # noqa: E402
from models.file_table_model import (  # noqa: E402
    COL_NAME,
    COL_SIZE,
    FileSortProxyModel,
    FileTableModel,
    PreparedListing,
    prepare_listing,
)

APP = QApplication.instance() or QApplication([])


def _items(n: int, seed: int = 1) -> list[FileItem]:
    rnd = random.Random(seed)
    words = ["entry", "Report", "STRASSE", "straße", "ÄÖü", "a.b", "x*y", "[x]", "日本"]
    out = [FileItem(name=".", is_dir=True), FileItem(name="..", is_dir=True)]
    for i in range(n):
        name = f"{rnd.choice(words)}_{i:05d}{rnd.choice(['.txt', '.DAT', ''])}"
        if i % 9 == 0:
            name = "." + name
        out.append(FileItem(name=name, size=rnd.randrange(1000), is_dir=i % 13 == 0,
                            attr_hidden=i % 17 == 0))
    return out


def _rule(item: FileItem, text: str, show_hidden: bool) -> bool:
    """The filter's rule, written out: the reference every test compares with."""
    if item.is_nav:
        return True
    if not show_hidden and item.is_hidden:
        return False
    return text.casefold() in item.name.casefold()


def _setup(items, sort=(COL_NAME, Qt.SortOrder.AscendingOrder)):
    model = FileTableModel()
    proxy = FileSortProxyModel()
    proxy.setSourceModel(model)
    proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
    if sort is not None:
        proxy.sort(*sort)
    model.set_items(items)
    return model, proxy


def _shown(model, proxy) -> list[str]:
    return [model.get_item(proxy.mapToSource(proxy.index(r, 0)).row()).name
            for r in range(proxy.rowCount())]


def _expected(model, text, show_hidden) -> list[str]:
    return [it.name for it in model._items if _rule(it, text, show_hidden)]


# -- happy --------------------------------------------------------------------------------------


@pytest.mark.parametrize("hidden", [False, True])
def test_happy_typing_shows_what_the_rule_admits_at_every_key(hidden):
    model, proxy = _setup(_items(2000))
    proxy.show_hidden = hidden
    typed = ""
    for ch in "entry_01":
        typed += ch
        proxy.setFilterFixedString(typed)
        assert _shown(model, proxy) == _expected(model, typed, hidden), typed
    for _ in range(4):  # backspace: the text shrinks, every row is looked at again
        typed = typed[:-1]
        proxy.setFilterFixedString(typed)
        assert _shown(model, proxy) == _expected(model, typed, hidden), typed


def test_happy_case_insensitive_text_compares_casefolded_names():
    model, proxy = _setup(_items(300))
    proxy.show_hidden = True
    proxy.setFilterFixedString("strasse")
    names = _shown(model, proxy)
    assert any(n.startswith("STRASSE") for n in names)
    assert any(n.startswith("straße") for n in names)  # casefold: ß is ss
    proxy.setFilterFixedString("äöü")
    assert all(n in (".", "..") or n.lstrip(".").startswith("ÄÖü") for n in _shown(model, proxy))


def test_happy_a_listing_prepared_off_the_gui_thread_is_shown_as_a_plain_one():
    items = _items(1500, seed=3)
    for order in (Qt.SortOrder.AscendingOrder, Qt.SortOrder.DescendingOrder):
        for col in (COL_NAME, COL_SIZE, 2, 3, 4, 9):
            plain_model, plain = _setup(list(items), (col, order))
            model, proxy = _setup([], (col, order))
            model.set_items(prepare_listing(list(items), model))
            assert [id(i) for i in model._items] == [id(i) for i in plain_model._items], col
            for p in (proxy, plain):
                p.setFilterFixedString("rep")
            assert _shown(model, proxy) == _shown(plain_model, plain)


def test_happy_the_sort_keeps_the_filtered_rows_and_their_order_rule():
    model, proxy = _setup(_items(800, seed=5))
    proxy.setFilterFixedString("e")
    for col in range(5):
        for order in (Qt.SortOrder.DescendingOrder, Qt.SortOrder.AscendingOrder):
            proxy.sort(col, order)
            assert _shown(model, proxy) == _expected(model, "e", False), (col, order)


def test_happy_tag_and_regular_expression_filters_still_work():
    model, proxy = _setup(_items(400, seed=6))
    proxy.show_hidden = True
    proxy.set_tag_filter(lambda item: "Report" in item.name)
    assert _shown(model, proxy) == [it.name for it in model._items
                                    if it.is_nav or "Report" in it.name]
    proxy.set_tag_filter(None)
    proxy.setFilterRegularExpression("^entry_00[0-4]")
    assert _shown(model, proxy) == [it.name for it in model._items if it.is_nav
                                    or it.name.lower().startswith(("entry_000", "entry_001",
                                                                   "entry_002", "entry_003",
                                                                   "entry_004"))]
    proxy.setFilterWildcard("*.dat")
    assert all(n in (".", "..") or n.lower().endswith(".dat") for n in _shown(model, proxy))


# -- edge ---------------------------------------------------------------------------------------


def test_edge_selection_and_current_row_follow_their_entries_through_filter_and_sort():
    model, proxy = _setup(_items(600, seed=7))
    view = QTableView()
    view.setModel(proxy)
    sel = view.selectionModel()
    flags = QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows
    keep = [r for r in range(proxy.rowCount())
            if "entry_00" in _shown(model, proxy)[r].lower()][:5]
    drop = [r for r in range(proxy.rowCount()) if "report" in _shown(model, proxy)[r].lower()][:3]
    names = _shown(model, proxy)
    for r in keep + drop:
        sel.select(proxy.index(r, 0), flags)
    sel.setCurrentIndex(proxy.index(keep[0], 0), QItemSelectionModel.SelectionFlag.NoUpdate)

    def selected() -> set[str]:
        return {model.get_item(proxy.mapToSource(i).row()).name for i in sel.selectedRows()}

    proxy.setFilterFixedString("entry_00")  # the "Report" rows go, the others stay selected
    assert selected() == {names[r] for r in keep}
    assert model.get_item(proxy.mapToSource(sel.currentIndex()).row()).name == names[keep[0]]
    proxy.sort(COL_SIZE, Qt.SortOrder.DescendingOrder)
    assert selected() == {names[r] for r in keep}
    proxy.setFilterFixedString("")  # widened: a row that was filtered out comes back unselected
    assert selected() == {names[r] for r in keep}
    view.deleteLater()


def test_edge_a_stale_prepared_listing_is_sorted_again():
    items = _items(300, seed=8)
    model, proxy = _setup([], (COL_NAME, Qt.SortOrder.AscendingOrder))
    prepared = prepare_listing(list(items), model)
    proxy.sort(COL_SIZE, Qt.SortOrder.DescendingOrder)  # the sort changed while it was listed
    model.set_items(prepared)
    reference, _p = _setup(list(items), (COL_SIZE, Qt.SortOrder.DescendingOrder))
    assert [id(i) for i in model._items] == [id(i) for i in reference._items]
    changed = PreparedListing(list(items), model.sort_spec)
    changed.append(FileItem(name="late.txt"))  # changed after it was prepared
    model.set_items(changed)
    assert "late.txt" in [i.name for i in model._items]


def test_edge_nav_rows_are_found_wherever_the_sort_puts_them():
    model, proxy = _setup(_items(500, seed=9))
    for order in (Qt.SortOrder.AscendingOrder, Qt.SortOrder.DescendingOrder):
        proxy.sort(COL_NAME, order)
        shown = _shown(model, proxy)
        assert [shown[r] for r in proxy.nav_rows()] == [n for n in shown if n in (".", "..")]
    unsorted_model, unsorted = _setup([FileItem(name="a"), FileItem(name="..", is_dir=True),
                                       FileItem(name="b")] * 3, sort=None)
    assert [_shown(unsorted_model, unsorted)[r] for r in unsorted.nav_rows()] == [".."] * 3


def test_edge_a_row_replaced_in_place_is_filtered_again():
    model, proxy = _setup(_items(100, seed=10))
    proxy.setFilterFixedString("entry")
    row = next(r for r, it in enumerate(model._items) if it.name.startswith("entry"))
    model._items[row] = FileItem(name="renamed.txt")
    model.dataChanged.emit(model.index(row, 0), model.index(row, 4))
    assert "renamed.txt" not in _shown(model, proxy)
    proxy.setFilterFixedString("renamed")
    assert "renamed.txt" in _shown(model, proxy)


# -- sad ----------------------------------------------------------------------------------------


def test_sad_no_match_leaves_only_the_navigation_rows():
    model, proxy = _setup(_items(200, seed=11))
    proxy.setFilterFixedString("nothing-is-called-this")
    assert _shown(model, proxy) == [".", ".."]
    assert proxy.mapFromSource(model.index(5, 0)).isValid() is False
    assert proxy.index(5, 0).isValid() is False
    assert proxy.data(QModelIndex()) is None


def test_sad_an_empty_listing_shows_nothing_and_breaks_nothing():
    model, proxy = _setup([])
    proxy.setFilterFixedString("x")
    proxy.show_hidden = True
    proxy.sort(COL_SIZE, Qt.SortOrder.DescendingOrder)
    assert proxy.rowCount() == 0 and proxy.nav_rows() == []


# -- regression guards (counted work, robust under load) ----------------------------------------


class _CountingList(list):
    reads = 0

    def __getitem__(self, i):
        _CountingList.reads += 1
        return list.__getitem__(self, i)


def test_perf_happy_a_growing_filter_text_reads_only_the_rows_shown_before():
    model, proxy = _setup(_items(20000, seed=12))
    proxy.setFilterFixedString("entry_0")
    before = proxy.rowCount()
    cache = model.row_cache()
    cache.folded = _CountingList(cache.folded)
    _CountingList.reads = 0
    proxy.setFilterFixedString("entry_00")
    assert 0 < _CountingList.reads <= before  # not the 20,000 rows of the listing
    _CountingList.reads = 0
    proxy.setFilterFixedString("entry_0")  # shrunk: every unhidden row once
    assert _CountingList.reads <= len(model._items)


def test_perf_sad_the_counter_sees_a_full_pass():
    """Negative control: a text that does not grow reads every candidate row."""
    model, proxy = _setup(_items(5000, seed=13))
    proxy.setFilterFixedString("entry_0")
    cache = model.row_cache()
    cache.folded = _CountingList(cache.folded)
    _CountingList.reads = 0
    proxy.setFilterFixedString("report")
    assert _CountingList.reads >= len(cache.unhidden) - 2


def test_perf_happy_filtering_never_asks_filter_accepts_row(monkeypatch):
    model, proxy = _setup(_items(5000, seed=14))
    calls = []
    real = FileSortProxyModel._accepts
    monkeypatch.setattr(FileSortProxyModel, "_accepts",
                        lambda self, item: calls.append(1) or real(self, item))
    for text in ("e", "en", "ent", ""):
        proxy.setFilterFixedString(text)
    proxy.show_hidden = True
    proxy.sort(COL_SIZE, Qt.SortOrder.DescendingOrder)
    assert calls == []


def test_perf_happy_a_sort_works_on_positions_not_on_python_comparisons(monkeypatch):
    model, proxy = _setup(_items(5000, seed=15))
    calls = []
    real = M._column_values
    monkeypatch.setattr(M, "_column_values", lambda *a: calls.append(1) or real(*a))
    proxy.sort(COL_SIZE, Qt.SortOrder.DescendingOrder)
    assert calls == [1]  # one value list for the column, then sorted() in C


def test_perf_happy_select_all_maps_no_row_through_the_proxy(monkeypatch):
    from unittest import mock

    from core.local_fs import LocalFS
    from ui.file_pane import FilePaneWidget

    with mock.patch.object(FilePaneWidget, "navigate", lambda *a, **k: None):
        pane = FilePaneWidget(LocalFS())
    try:
        pane._model.set_items(_items(5000, seed=16))
        maps = []
        real = FileSortProxyModel.mapToSource
        monkeypatch.setattr(FileSortProxyModel, "mapToSource",
                            lambda self, index: maps.append(1) or real(self, index))
        pane._select_all()
        pane._invert_selection()
        pane._select_all()
        assert len(maps) <= 4
        names = [item.name for item in pane._selected_source_items()]
        assert "." not in names and ".." not in names
        assert len(names) == pane._proxy.rowCount() - 2
    finally:
        pane.shutdown()
        pane.deleteLater()


def test_perf_happy_the_listing_thread_prepares_what_the_gui_thread_shows(tmp_path):
    from unittest import mock

    from core.local_fs import LocalFS
    from ui.file_pane import FilePaneWidget

    for i in range(50):
        (tmp_path / f"f{i:02d}.txt").write_text("x")
    with mock.patch.object(FilePaneWidget, "navigate", lambda *a, **k: None):
        pane = FilePaneWidget(LocalFS())
    try:
        path, listing = pane._fetch_listing(str(tmp_path))
        assert isinstance(listing, PreparedListing) and listing.has_orphan_name is False
        sorts = []
        real = M.sort_positions
        with mock.patch.object(M, "sort_positions",
                               lambda *a, **k: sorts.append(1) or real(*a, **k)):
            pane._apply_listing(path, listing)
        assert sorts == []  # sorted on the listing thread already
        assert pane._proxy.rowCount() == 52
    finally:
        pane.shutdown()
        pane.deleteLater()
