"""Find Files: the Name column sorts in Qt, not through a Python ``__lt__``.

Measured before: the results table sorts again after every batch of rows
(sorting is switched off while a batch goes in), and by default it sorts by
Name, whose cells were ``_SortItem``s - a Python call per comparison, ~66,000
per batch at 5000 results. A name cell has no sort value, so ``_SortItem``
only ever fell back to Qt's own comparison; a plain item gives the same
order without the calls. Every test compares with name cells as
``_SortItem``.
"""

from __future__ import annotations

import collections
import os
import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import file_search as FS  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.search_federation import SearchHit  # noqa: E402
from ui import find_files_dialog as FD  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _hits(n: int, seed: int = 1) -> list[SearchHit]:
    rnd = random.Random(seed)
    words = ["report", "Report", "älter", "Zeta", "a b", "日本", "", "x" * 40, "10", "9", "a.b"]
    out = []
    for i in range(n):
        name = f"{rnd.choice(words)}{rnd.choice(['', str(i % 7), '.txt'])}"
        out.append(SearchHit(backend_label="Local", path=f"/srv/d{i % 13}/{name or 'n'}",
                             size=rnd.choice([0, 7, 7, 2**33]), mtime=1.7e9 + rnd.randrange(50),
                             category=""))
    return out


def _dialog(hits, monkeypatch=None, former: bool = False):
    if former:
        monkeypatch.setattr(FD, "_NameItem", FD._SortItem)
    dialog = FD.FindFilesDialog([FD.ScopeChoice(LocalFS(), "/srv")])
    scope = FS.SearchScope(LocalFS(), "/srv")
    dialog._queue = collections.deque((scope, h) for h in hits)
    while dialog._queue:
        dialog._drain()
    if former:
        monkeypatch.undo()
    return dialog


def _order(dialog) -> list[tuple]:
    table = dialog.table
    return [tuple(table.item(r, c).text() for c in range(table.columnCount()))
            + (table.item(r, FD.COL_NAME).data(FD._ROW_ROLE),)
            for r in range(table.rowCount())]


def test_happy_every_column_sorts_like_before(monkeypatch):
    hits = _hits(600)
    new = _dialog(hits)
    old = _dialog(hits, monkeypatch, former=True)
    assert _order(new) == _order(old)
    for col in range(new.table.columnCount()):
        for order in (Qt.SortOrder.AscendingOrder, Qt.SortOrder.DescendingOrder):
            new.table.sortItems(col, order)
            old.table.sortItems(col, order)
            assert _order(new) == _order(old), (col, order)


def test_edge_rows_arriving_in_batches_keep_the_former_order(monkeypatch):
    hits = _hits(1300, seed=2)  # three batches of _ROWS_PER_TICK
    new = _dialog(hits)
    old = _dialog(hits, monkeypatch, former=True)
    assert _order(new) == _order(old)
    assert new.table.rowCount() == 1300


def test_sad_activating_a_row_still_finds_its_hit():
    hits = _hits(40, seed=3)
    dialog = _dialog(hits)
    for row in range(dialog.table.rowCount()):
        scope, hit = dialog._row_entry(row)
        assert hit.path.endswith(dialog.table.item(row, FD.COL_NAME).text() or "n")


def test_perf_happy_sorting_by_name_calls_no_python_comparison(monkeypatch):
    calls = [0]
    real = FD._SortItem.__lt__

    def counted(self, other):
        calls[0] += 1
        return real(self, other)

    monkeypatch.setattr(FD._SortItem, "__lt__", counted)
    _dialog(_hits(1500, seed=4))
    assert calls[0] == 0


def test_perf_sad_the_former_name_cells_called_python_per_comparison(monkeypatch):
    """Negative control: with name cells as _SortItem the counter runs."""
    calls = [0]
    real = FD._SortItem.__lt__

    def counted(self, other):
        calls[0] += 1
        return real(self, other)

    monkeypatch.setattr(FD._SortItem, "__lt__", counted)
    monkeypatch.setattr(FD, "_NameItem", FD._SortItem)
    _dialog(_hits(1500, seed=4))
    assert calls[0] > 1500
