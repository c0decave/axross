"""File pane proxy: which rows a listing shows is worked out once per
listing, sort, filter text or hidden switch, not once per row and call.

Measured before (scripts/pane_bench.py, 20,000 entries): every listing,
every sort and every filter keystroke ran ``filterAcceptsRow`` in Python for
all 20,000 rows (~3.7 us each: the source model, the item, the hidden rule
and a new QRegularExpression wrapper per row), ~70 ms of each listing's and
each sort's GUI-thread time.

The rows shown must not change: every test compares with the former
``filterAcceptsRow``, kept verbatim in ``_OldProxy``.
"""

from __future__ import annotations

import os
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt6.QtCore import QModelIndex, Qt  # noqa: E402
from PyQt6.QtGui import QStandardItemModel  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from models.file_item import FileItem  # noqa: E402
from models.file_table_model import FileSortProxyModel, FileTableModel  # noqa: E402

APP = QApplication.instance() or QApplication([])


class _OldProxy(FileSortProxyModel):
    """FileSortProxyModel with the former filterAcceptsRow, verbatim."""

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:  # noqa: N802
        model = self.sourceModel()
        if not isinstance(model, FileTableModel):
            return True
        item = model.get_item(source_row)
        if item is None:
            return False
        # ".." is always visible
        if item.name == "..":
            return True
        # Hidden files filter: dot names and entries the backend flags hidden
        if not self._show_hidden and item.is_hidden:
            return False
        if self._tag_filter is not None and not self._tag_filter(item):
            return False
        # Text filter from filter bar
        regex = self.filterRegularExpression()
        if regex.pattern():
            return regex.match(item.name).hasMatch()
        return True


def _items(n: int, seed: int = 1, dotdot: bool = True) -> list[FileItem]:
    rnd = random.Random(seed)
    words = ["entry", "Report", "a.b", "[x]", "zeta", "ÄÖü", "日本", "a+b", "x*y"]
    out = [FileItem(name="..", is_dir=True)] if dotdot else []
    for i in range(n):
        name = f"{rnd.choice(words)}_{i:05d}{rnd.choice(['.txt', '.DAT', ''])}"
        if i % 9 == 0:
            name = "." + name
        out.append(FileItem(name=name, size=rnd.randrange(10_000), is_dir=i % 13 == 0,
                            attr_hidden=i % 17 == 0))
    return out


def _pair(items):
    """(new proxy, old proxy), each over its own model with *items*."""
    out = []
    for cls in (FileSortProxyModel, _OldProxy):
        model = FileTableModel()
        proxy = cls()
        proxy.setSourceModel(model)
        proxy.setFilterKeyColumn(0)
        proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        model.set_items(items)
        out.append(proxy)
    return out


def _shown(proxy) -> list[str]:
    return [proxy.index(r, 0).data() for r in range(proxy.rowCount())]


def _both(new, old, change) -> None:
    change(new)
    change(old)
    assert _shown(new) == _shown(old)


# -- the rows shown are the former ones -------------------------------------------------------


@pytest.mark.parametrize("text", ["", "entry", "ENTRY", "a.b", "[x]", "a+b", "x*y", "日本",
                                  "äöü", "_000", "nothing-matches", " "])
@pytest.mark.parametrize("hidden", [False, True])
def test_happy_filter_text_and_hidden_switch_show_the_former_rows(text, hidden):
    new, old = _pair(_items(400))
    for proxy in (new, old):
        proxy.show_hidden = hidden
        proxy.setFilterFixedString(text)
    assert _shown(new) == _shown(old)


def test_happy_a_sequence_of_changes_keeps_showing_the_former_rows():
    new, old = _pair(_items(600, seed=4))
    _both(new, old, lambda p: p.setFilterFixedString("ent"))
    _both(new, old, lambda p: p.sort(1, Qt.SortOrder.DescendingOrder))
    _both(new, old, lambda p: setattr(p, "show_hidden", True))
    _both(new, old, lambda p: p.setFilterFixedString("entr"))
    _both(new, old, lambda p: p.sourceModel().set_items(_items(300, seed=5)))
    _both(new, old, lambda p: p.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseSensitive))
    _both(new, old, lambda p: p.setFilterFixedString("Report"))
    _both(new, old, lambda p: p.setFilterRegularExpression("^\\.?zeta_00[0-4]"))
    _both(new, old, lambda p: p.sort(0, Qt.SortOrder.AscendingOrder))
    _both(new, old, lambda p: setattr(p, "show_hidden", False))
    _both(new, old, lambda p: p.setFilterFixedString(""))
    _both(new, old, lambda p: p.sourceModel().set_cut_names({"entry_00003.txt"}))
    _both(new, old, lambda p: p.sourceModel().set_items([]))
    _both(new, old, lambda p: p.sourceModel().set_items(_items(50, seed=6, dotdot=False)))


def test_edge_a_tag_filter_asks_the_predicate_like_before():
    new, old = _pair(_items(200, seed=8))
    wanted = {"entry", "zeta"}
    calls = []

    def tagged(item):
        calls.append(item.name)
        return item.name.split("_")[0].lstrip(".") in wanted

    _both(new, old, lambda p: p.set_tag_filter(tagged))
    _both(new, old, lambda p: setattr(p, "show_hidden", True))
    wanted.discard("zeta")  # the tag store changed; the pane invalidates
    _both(new, old, lambda p: p.invalidateFilter())
    _both(new, old, lambda p: p.set_tag_filter(None))
    assert calls


def test_edge_invalidate_and_identical_listings_stay_right():
    items = _items(120, seed=9)
    new, old = _pair(items)
    _both(new, old, lambda p: p.setFilterFixedString("e"))
    _both(new, old, lambda p: p.invalidate())
    # The same items again (a refresh with nothing changed): a new list.
    _both(new, old, lambda p: p.sourceModel().set_items(list(items)))


def test_edge_an_item_replaced_in_place_with_data_changed_is_filtered_anew():
    new, old = _pair(_items(80, seed=10))
    for proxy in (new, old):
        proxy.setFilterFixedString("entry")
        proxy.rowCount()
    for proxy in (new, old):
        model = proxy.sourceModel()
        row = next(r for r, it in enumerate(model._items) if it.name.startswith("entry"))
        model._items[row] = FileItem(name="renamed_elsewhere.txt")
        model.dataChanged.emit(model.index(row, 0), model.index(row, 4))
    assert _shown(new) == _shown(old)
    assert "renamed_elsewhere.txt" not in _shown(new)


def test_edge_a_second_source_model_is_filtered_and_the_first_forgotten():
    proxy = FileSortProxyModel()
    first, second = FileTableModel(), FileTableModel()
    proxy.setSourceModel(first)
    first.set_items(_items(30, seed=1))
    proxy.setSourceModel(second)
    second.set_items(_items(40, seed=2))
    first.dataChanged.emit(first.index(0, 0), first.index(0, 0))  # no longer watched
    ref = _OldProxy()
    ref.setSourceModel(second)
    assert _shown(proxy) == _shown(ref)


def test_sad_another_source_model_shows_every_row():
    proxy = FileSortProxyModel()
    model = QStandardItemModel(5, 1)
    proxy.setSourceModel(model)
    proxy.setFilterFixedString("nothing")
    assert proxy.rowCount() == 5


def test_sad_a_row_beyond_the_listing_is_not_accepted():
    new, old = _pair(_items(10))
    for row in (-1, 11, 500):
        assert new.filterAcceptsRow(row, QModelIndex()) is False
        assert old.filterAcceptsRow(row, QModelIndex()) is False


def test_happy_e2e_typing_into_a_pane_filter_shows_the_former_rows():
    from unittest import mock

    from PyQt6.QtTest import QTest

    from core.local_fs import LocalFS
    from ui.file_pane import FilePaneWidget

    with mock.patch.object(FilePaneWidget, "navigate", lambda *a, **k: None):
        pane = FilePaneWidget(LocalFS())
    try:
        items = _items(3000, seed=11)
        pane._model.set_items(items)
        pane.resize(900, 600)
        pane.show()
        ref_model = FileTableModel()
        ref = _OldProxy()
        ref.setSourceModel(ref_model)
        ref.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        ref_model.set_items(items)
        ref_model.sort(0, Qt.SortOrder.AscendingOrder)
        pane._filter_edit.setFocus()
        typed = ""
        for ch in "entry_01":
            QTest.keyClicks(pane._filter_edit, ch)
            typed += ch
            ref.setFilterFixedString(typed)
            APP.processEvents()
            assert _shown(pane._proxy) == _shown(ref), typed
        pane.set_show_hidden(True)
        ref.show_hidden = True
        assert _shown(pane._proxy) == _shown(ref)
        QTest.keyClick(pane._filter_edit, Qt.Key.Key_Backspace)
        ref.setFilterFixedString(typed[:-1])
        assert _shown(pane._proxy) == _shown(ref)
    finally:
        pane.shutdown()
        pane.deleteLater()


# -- fast -------------------------------------------------------------------------------------


def _filter_cost_ms(cls, n: int = 20000, rounds: int = 4) -> float:
    """Cheapest GUI-thread CPU of one filter pass (a keystroke) over *n*
    entries, alternating two texts so every pass refilters."""
    model = FileTableModel()
    proxy = cls()
    proxy.setSourceModel(model)
    proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
    model.set_items(_items(n, seed=12))
    costs = []
    for i in range(rounds):
        start = time.thread_time()
        proxy.setFilterFixedString("entry_1" if i % 2 else "entry_")
        proxy.rowCount()
        costs.append((time.thread_time() - start) * 1000)
    return min(costs)


def _regex_reads_per_pass(cls, n: int = 3000) -> int:
    """How often one filter pass asks for the filter expression."""
    model = FileTableModel()
    proxy = cls()
    proxy.setSourceModel(model)
    model.set_items(_items(n, seed=13))
    proxy.rowCount()
    calls = [0]
    real = proxy.filterRegularExpression

    def counted():
        calls[0] += 1
        return real()

    proxy.filterRegularExpression = counted
    proxy.setFilterFixedString("entry")
    proxy.rowCount()
    return calls[0]


def test_perf_happy_a_filter_pass_reads_the_expression_once_not_per_row():
    assert _regex_reads_per_pass(FileSortProxyModel) <= 1


def test_perf_sad_the_former_filter_read_it_per_row():
    """Negative control: the counter sees the former per-row reads."""
    assert _regex_reads_per_pass(_OldProxy) >= 2000  # every shown candidate row


#: A filter pass costs at most this share of the former one. Measured
#: 21 ms against 35 ms over 20,000 entries; most of what is left is Qt
#: calling a Python filterAcceptsRow at all (20 ms for one that returns
#: True). Compared in one process, so the host's load hits both. On a loaded
#: host one comparison still went either way (the former filter against itself:
#: 44 ms against 64 ms), so each verdict gets up to ATTEMPTS comparisons: a real
#: regression fails every one, noise does not fail them all.
FILTER_SHARE = 0.8


ATTEMPTS = 3


def _paired_costs(first, second, rounds: int = 3) -> tuple[float, float]:
    a, b = [], []
    for _ in range(rounds):
        a.append(_filter_cost_ms(first))
        b.append(_filter_cost_ms(second))
    return min(a), min(b)


def _holds_once(check, first, second) -> tuple[bool, list]:
    seen = []
    for _ in range(ATTEMPTS):
        costs = _paired_costs(first, second)
        seen.append(costs)
        if check(*costs):
            return True, seen
    return False, seen


def test_perf_happy_a_filter_pass_over_20000_entries_is_cheaper():
    ok, seen = _holds_once(lambda new, old: new < old * FILTER_SHARE,
                           FileSortProxyModel, _OldProxy)
    assert ok, seen


def test_perf_sad_the_comparison_catches_a_filter_as_slow_as_before():
    """Negative control: the former filter against itself is no cheaper."""
    ok, seen = _holds_once(lambda again, old: not again < old * FILTER_SHARE,
                           _OldProxy, _OldProxy)
    assert ok, seen
