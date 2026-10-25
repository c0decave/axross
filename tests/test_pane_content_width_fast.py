"""File pane: measuring what the Name column needs reads the listing's
texts straight from the items instead of 5000 ``index.data`` round trips
through the proxy and the Python model.

Measured before (scripts/pane_bench.py, 20,000 entries): every listing,
sort and filter keystroke measured column 0 again - 5000 proxy data() calls,
~30 ms of GUI-thread time each time. The width must not change: the tests
compare with the former ``_content_width``, kept verbatim below.
"""

from __future__ import annotations

import os
import random
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from models.file_item import FileItem  # noqa: E402
from models.file_table_model import COLUMNS, FileSortProxyModel, FileTableModel  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _old_content_width(pane, col: int) -> int:
    """The former FilePaneWidget._content_width, verbatim (without its cache)."""
    from ui import file_pane as FP

    rows = min(pane._proxy.rowCount(), FP._MEASURE_ROWS)
    lengths = []
    for row in range(rows):
        index = pane._proxy.index(row, col)
        text = index.data(Qt.ItemDataRole.DisplayRole)
        lengths.append((len(text) if isinstance(text, str) else 0, row))
    lengths.sort(reverse=True)
    width = 0
    for _length, row in lengths[: FP._MEASURE_LONGEST]:
        width = max(width, pane._table.sizeHintForIndex(pane._proxy.index(row, col)).width())
    return width


def _items(n: int, seed: int = 1) -> list[FileItem]:
    rnd = random.Random(seed)
    out = [FileItem(name="..", is_dir=True)]
    for i in range(n):
        name = "".join(rnd.choice("abcWMil.日ä ") for _ in range(rnd.randint(1, 60)))
        out.append(FileItem(
            name=f"{'.' if i % 7 == 0 else ''}{name}_{i}", size=rnd.choice([0, 5, 2**20, 2**41]),
            modified=datetime(2020 + i % 6, 1 + i % 12, 1 + i % 28, i % 24, i % 60),
            permissions=rnd.randrange(0o7777), is_dir=i % 5 == 0, is_link=i % 11 == 0,
            owner=rnd.choice(["", "root", "a-very-long-owner-name"]),
            group=rnd.choice(["", "wheel", "staff"]), attr_hidden=i % 13 == 0))
    return out


def _pane(items):
    from unittest import mock

    from core.local_fs import LocalFS
    from ui.file_pane import FilePaneWidget

    with mock.patch.object(FilePaneWidget, "navigate", lambda *a, **k: None):
        pane = FilePaneWidget(LocalFS())
    pane._model.set_items(items)
    pane.resize(900, 600)
    pane.show()
    APP.processEvents()
    return pane


@pytest.fixture
def pane():
    p = _pane(_items(1500))
    yield p
    p.shutdown()
    p.deleteLater()


def _assert_widths_equal(pane) -> None:
    for col in range(len(COLUMNS)):
        pane._content_widths = {}
        assert pane._content_width(col) == _old_content_width(pane, col), col


# -- the same texts, the same rows, the same width --------------------------------------------


def test_happy_display_text_is_what_data_shows():
    model = FileTableModel()
    items = _items(300, seed=2)
    model.set_items(items)
    model.set_computed_sizes({it.name: (12345, i % 2 == 0)
                              for i, it in enumerate(items) if it.is_dir})
    for row in range(model.rowCount()):
        item = model.get_item(row)
        for col in range(len(COLUMNS)):
            assert model.display_text(item, col) == model.data(model.index(row, col)), (row, col)


def test_happy_source_rows_are_the_proxy_mapping():
    model = FileTableModel()
    proxy = FileSortProxyModel()
    proxy.setSourceModel(model)
    proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
    model.set_items(_items(800, seed=3))

    def check(limit=None):
        n = proxy.rowCount() if limit is None else limit
        expected = [proxy.mapToSource(proxy.index(r, 0)).row() for r in range(n)]
        assert proxy.source_rows(n) == expected

    check()
    check(10)
    proxy.setFilterFixedString("a")
    check()
    model.sort(2, Qt.SortOrder.DescendingOrder)
    check()
    proxy.show_hidden = True
    check(37)
    proxy.set_tag_filter(lambda item: "W" in item.name)  # per-row path: no worked-out rows
    check()
    proxy.set_tag_filter(None)
    check()
    model.set_items(_items(5, seed=4))
    check()
    check(0)


def test_happy_content_width_equals_the_former_measurement(pane):
    _assert_widths_equal(pane)


def test_edge_filtered_sorted_hidden_and_sized_listings_measure_the_same(pane):
    pane._on_filter_changed("a")
    APP.processEvents()
    _assert_widths_equal(pane)
    pane._table.sortByColumn(4, Qt.SortOrder.DescendingOrder)
    APP.processEvents()
    _assert_widths_equal(pane)
    pane.set_show_hidden(True)
    _assert_widths_equal(pane)
    dirs = {it.name: (2**40, True) for it in pane._model._items if it.is_dir}
    pane._model.set_computed_sizes(dirs)
    _assert_widths_equal(pane)
    pane._on_filter_changed("no-such-name-at-all")  # only ".." is left
    APP.processEvents()
    assert pane._proxy.rowCount() == 1
    _assert_widths_equal(pane)


def test_edge_more_rows_than_measured_judge_the_first_rows_in_sort_order():
    from ui import file_pane as FP

    p = _pane(_items(FP._MEASURE_ROWS + 400, seed=5))
    try:
        _assert_widths_equal(p)
        p._table.sortByColumn(0, Qt.SortOrder.DescendingOrder)
        APP.processEvents()
        _assert_widths_equal(p)
    finally:
        p.shutdown()
        p.deleteLater()


def test_edge_a_tag_filter_measures_through_the_proxy_like_before(pane):
    pane._proxy.set_tag_filter(lambda item: "M" in item.name)
    APP.processEvents()
    _assert_widths_equal(pane)


def test_sad_an_empty_folder_needs_no_width():
    p = _pane([])
    try:
        _assert_widths_equal(p)
        assert p._content_width(0) == 0
    finally:
        p.shutdown()
        p.deleteLater()


# -- fast -------------------------------------------------------------------------------------


def _data_calls(pane, measure) -> int:
    calls = [0]
    real = FileTableModel.data

    def counted(self, *args):
        calls[0] += 1
        return real(self, *args)

    FileTableModel.data = counted
    try:
        pane._content_widths = {}
        measure(pane, 0)
    finally:
        FileTableModel.data = real
    return calls[0]


def test_perf_happy_measuring_reads_no_texts_through_the_model(pane):
    from ui.file_pane import FilePaneWidget

    # Only the eight longest texts are sized by the view (its delegate
    # reads their roles); no per-row data() round trip is left.
    assert _data_calls(pane, FilePaneWidget._content_width) < 200


def test_perf_sad_the_former_measurement_read_every_row(pane):
    """Negative control: the counter sees the former per-row reads."""
    assert _data_calls(pane, _old_content_width) >= pane._proxy.rowCount()


def _cost_ms(pane, measure) -> float:
    costs = []
    for _ in range(4):
        pane._content_widths = {}
        start = time.thread_time()
        measure(pane, 0)
        costs.append((time.thread_time() - start) * 1000)
    return min(costs)


def test_perf_happy_measuring_20000_entries_costs_a_fraction_of_before():
    from ui.file_pane import FilePaneWidget

    p = _pane(_items(20000, seed=6))
    try:
        new = min(_cost_ms(p, FilePaneWidget._content_width) for _ in range(2))
        old = min(_cost_ms(p, _old_content_width) for _ in range(2))
    finally:
        p.shutdown()
        p.deleteLater()
    assert new < old * 0.5, (new, old)


def test_perf_sad_the_comparison_catches_a_measurement_as_slow_as_before():
    """Negative control of the comparison above: the former measurement
    against itself is not half as expensive."""
    p = _pane(_items(20000, seed=6))
    try:
        again = min(_cost_ms(p, _old_content_width) for _ in range(2))
        old = min(_cost_ms(p, _old_content_width) for _ in range(2))
    finally:
        p.shutdown()
        p.deleteLater()
    assert not again < old * 0.5, (again, old)
