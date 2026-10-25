"""ui.column_fit with ``cache_widths``: a table whose rows change all the
time (the transfer queue) is fitted from remembered cell widths instead of
measuring up to 1000 rows per column again after every changed row.

Measured before (scripts/pane_bench.py, 2000 small files through the
queue): every progress signal's dataChanged refitted the Transfers dock,
each fit read 7 columns x 1000 rows through the Python model (~300 ms at
2000 jobs), so the copy took 236 s with 185 s of GUI-thread CPU and the
window froze for up to 2.4 s at a time.

The cache must not change a single width: every test compares with Qt's
own ``sizeHintForColumn`` or with a fitter that does not cache.
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
from PyQt6.QtCore import QModelIndex, QObject, Qt, pyqtSignal  # noqa: E402
from PyQt6.QtGui import QFont, QStandardItem, QStandardItemModel  # noqa: E402
from PyQt6.QtWidgets import QApplication, QTableView, QTreeView  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _model(rows: int, cols: int = 3, seed: int = 1) -> QStandardItemModel:
    rnd = random.Random(seed)
    model = QStandardItemModel(rows, cols)
    for r in range(rows):
        for c in range(cols):
            model.setItem(r, c, QStandardItem("w" * rnd.randint(1, 40)))
    return model


def _pump() -> None:
    for _ in range(3):
        APP.processEvents()


def _view(model, *, cache: bool, width: int = 700, show: bool = True):
    from ui.column_fit import ColumnFitter

    view = QTableView()
    view.setModel(model)
    fitter = ColumnFitter(view, fill=0, cache_widths=cache)
    view.resize(width, 300)
    if show:
        view.show()
    _pump()
    return view, fitter


def _widths(view) -> list[int]:
    header = view.horizontalHeader()
    return [header.sectionSize(c) for c in range(header.count())]


def _assert_hints_match_qt(view, fitter) -> None:
    for col in range(view.model().columnCount()):
        assert fitter.column_hint(col) == view.sizeHintForColumn(col), col


# -- the cached hint is Qt's hint -------------------------------------------------------------


@pytest.mark.parametrize("rows", [0, 1, 7, 60, 2500])
@pytest.mark.parametrize("show", [True, False])
def test_happy_cached_hint_equals_qt_size_hint_for_column(rows, show):
    view, fitter = _view(_model(rows), cache=True, show=show)
    _assert_hints_match_qt(view, fitter)
    _assert_hints_match_qt(view, fitter)  # the second time from the cache


@pytest.mark.parametrize("precision", [0, 1, 10, -1])
def test_edge_every_resize_contents_precision_samples_the_rows_qt_samples(precision):
    model = _model(1500, seed=precision + 5)
    # The widest cell far down: only "all rows" (-1) reaches it.
    model.setItem(1400, 1, QStandardItem("W" * 120))
    view, fitter = _view(model, cache=True)
    view.horizontalHeader().setResizeContentsPrecision(precision)
    _assert_hints_match_qt(view, fitter)


def test_edge_scrolled_hidden_and_moved_rows_sample_like_qt():
    model = _model(3000, seed=3)
    view, fitter = _view(model, cache=True)
    view.scrollTo(model.index(1800, 0))
    _pump()
    _assert_hints_match_qt(view, fitter)
    for r in range(1795, 1830, 3):
        view.setRowHidden(r, True)
    view.verticalHeader().moveSection(1801, 5)
    view.verticalHeader().moveSection(10, 2900)
    _pump()
    _assert_hints_match_qt(view, fitter)


def test_edge_grid_off_and_a_bigger_font_are_measured_again():
    view, fitter = _view(_model(80), cache=True)
    view.setShowGrid(False)
    _assert_hints_match_qt(view, fitter)
    font = QFont(view.font())
    font.setPointSize(font.pointSize() + 6)
    view.setFont(font)
    _pump()
    _assert_hints_match_qt(view, fitter)
    view.setStyleSheet("QTableView::item { padding: 0px 30px; }")
    _pump()
    _assert_hints_match_qt(view, fitter)


# -- changes keep it equal --------------------------------------------------------------------


def test_happy_changed_rows_grow_and_shrink_the_columns_as_without_cache():
    a_model, b_model = _model(1200), _model(1200)
    a, _fa = _view(a_model, cache=False)
    b, fb = _view(b_model, cache=True)
    assert _widths(b) == _widths(a)
    rnd = random.Random(7)
    for step in range(60):
        r, c = rnd.randrange(1200), rnd.randrange(1, 3)
        text = "x" * rnd.choice([1, 2, 3, 60, 90]) if step % 7 else ""
        for model in (a_model, b_model):
            model.item(r, c).setText(text)
        _pump()
        assert _widths(b) == _widths(a), step
    _assert_hints_match_qt(b, fb)


def test_edge_rows_inserted_removed_sorted_reset_stay_equal():
    a_model, b_model = _model(400, seed=9), _model(400, seed=9)
    a, _fa = _view(a_model, cache=False)
    b, fb = _view(b_model, cache=True)

    def both(change) -> None:
        change(a_model)
        change(b_model)
        _pump()
        assert _widths(b) == _widths(a)
        _assert_hints_match_qt(b, fb)

    both(lambda m: m.appendRow([QStandardItem("y" * 70), QStandardItem("1"),
                                QStandardItem("2")]))
    both(lambda m: m.insertRow(0, [QStandardItem("a"), QStandardItem("z" * 95),
                                   QStandardItem("b")]))
    both(lambda m: m.removeRows(0, 5))
    both(lambda m: m.sort(1, Qt.SortOrder.DescendingOrder))
    both(lambda m: m.removeRows(10, 300))
    both(lambda m: m.setRowCount(0))
    both(lambda m: m.appendRow([QStandardItem("q"), QStandardItem("r"), QStandardItem("s")]))


def test_edge_a_new_model_drops_the_old_cells():
    view, fitter = _view(_model(50, seed=1), cache=True)
    _assert_hints_match_qt(view, fitter)
    view.setModel(_model(50, seed=2))
    _pump()
    _assert_hints_match_qt(view, fitter)


# -- where it does not apply ------------------------------------------------------------------


def test_sad_a_tree_view_falls_back_to_qt():
    from ui.column_fit import ColumnFitter

    tree = QTreeView()
    tree.setModel(_model(30))
    fitter = ColumnFitter(tree, fill=0, cache_widths=True)
    tree.show()
    _pump()
    for col in range(3):
        assert fitter.column_hint(col) == tree.sizeHintForColumn(col)


def test_sad_no_model_answers_like_qt():
    from ui.column_fit import ColumnFitter

    view = QTableView()
    fitter = ColumnFitter(view, fill=0, cache_widths=True)
    assert fitter.column_hint(0) == view.sizeHintForColumn(0) == -1


# -- the Transfers dock: fast and the same --------------------------------------------------


class _Signals(QObject):
    """The manager signals TransferDock connects; no worker thread."""

    job_added = pyqtSignal(object)
    job_updated = pyqtSignal(str)
    job_finished = pyqtSignal(str)
    job_error = pyqtSignal(str, str)


def _dock(jobs: int):
    from core.transfer_worker import TransferDirection, TransferJob
    from ui.transfer_dock import TransferDock

    signals = _Signals()
    signals.all_jobs = lambda: list(dock._model._jobs)
    dock = TransferDock(signals)
    dock.resize(1000, 300)
    dock.show()
    for i in range(jobs):
        dock._model.add_job(TransferJob(job_id=f"j{i}", source_path=f"/a/f{i:05d}.bin",
                                        dest_path=f"/b/f{i:05d}.bin", filename=f"f{i:05d}.bin",
                                        direction=TransferDirection.UPLOAD, total_bytes=4096))
    _pump()
    return dock


def _update_cost_ms(dock, updates: int = 40) -> float:
    """GUI-thread CPU of *updates* progress updates, each handled like the
    real ones: the job changes, job_updated, one event-loop turn."""
    from core.transfer_worker import TransferStatus

    start = time.thread_time()
    for i in range(updates):
        job = dock._model._jobs[i]
        job.status = TransferStatus.ACTIVE
        job.transferred_bytes = 2048
        job.speed = 1234.0 * (i + 1)
        dock._on_job_updated(job.job_id)
        APP.processEvents()
    return (time.thread_time() - start) * 1000


#: GUI CPU budget for 40 updates of a 2000-job queue (before: ~10 000 ms).
UPDATE_BUDGET_MS = 400


def test_perf_happy_transfer_updates_on_a_long_queue_stay_cheap():
    dock = _dock(2000)
    try:
        assert dock._columns._cache_widths
        cheapest = min(_update_cost_ms(dock) for _ in range(3))
    finally:
        dock.close()
    assert cheapest < UPDATE_BUDGET_MS, cheapest


def test_perf_sad_the_uncached_fit_is_caught_by_the_budget():
    """Negative control: the same updates with the former fit (measuring
    every column again) are over the budget."""
    dock = _dock(2000)
    try:
        dock._columns._cache_widths = False
        cost = _update_cost_ms(dock, updates=8) * 5  # 40 updates' worth
    finally:
        dock.close()
    assert cost > UPDATE_BUDGET_MS, cost


def test_happy_e2e_dock_widths_equal_the_uncached_fit_after_updates():
    cached, plain = _dock(1500), _dock(1500)
    try:
        plain._columns._cache_widths = False
        for dock in (cached, plain):
            _update_cost_ms(dock, updates=25)
            dock._model._jobs[3].filename = "a much longer file name " * 6
            dock._on_job_updated("j3")
            end = time.perf_counter() + 0.25  # past the dock's 100 ms data delay
            while time.perf_counter() < end:
                APP.processEvents()
                time.sleep(0.005)
        assert _widths(cached._table) == _widths(plain._table)
        for col in range(cached._model.columnCount()):
            assert cached._columns.column_hint(col) == cached._table.sizeHintForColumn(col)
    finally:
        cached.close()
        plain.close()


def test_edge_an_invalid_data_changed_range_forgets_everything():
    view, fitter = _view(_model(30), cache=True)
    _assert_hints_match_qt(view, fitter)
    view.model().dataChanged.emit(QModelIndex(), QModelIndex())
    assert not fitter._cell_widths
    _assert_hints_match_qt(view, fitter)


# -- data changes are fitted at most every data_delay_ms ------------------------------------


def _count_fits(fitter) -> list[int]:
    fits = [0]
    real = fitter.fit

    def counted():
        fits[0] += 1
        real()

    fitter.fit = counted
    return fits


def _burst(model, fitter_view, changes: int = 50, gap_s: float = 0.004) -> float:
    """*changes* dataChanged, each handled in its own event-loop turn (the
    way queued progress signals arrive), then quiet for 0.3 s. Returns the
    seconds the changes took."""
    start = time.perf_counter()
    for i in range(changes):
        model.item(i % model.rowCount(), 1).setText("v" * (i % 30 + 1))
        end = time.perf_counter() + gap_s
        while time.perf_counter() < end:
            APP.processEvents()
    took = time.perf_counter() - start
    end = time.perf_counter() + 0.3
    while time.perf_counter() < end:
        APP.processEvents()
        time.sleep(0.005)
    return took


def _delayed_view(model, delay: int):
    from ui.column_fit import ColumnFitter

    view = QTableView()
    view.setModel(model)
    fitter = ColumnFitter(view, fill=0, cache_widths=True, data_delay_ms=delay)
    view.resize(700, 300)
    view.show()
    _pump()
    return view, fitter


def test_perf_happy_a_burst_of_data_changes_is_fitted_a_few_times():
    view, fitter = _delayed_view(_model(400), delay=100)
    fits = _count_fits(fitter)
    took = _burst(view.model(), view)
    # 50 changes over ~0.2 s (longer on a busy host): one fit per 100 ms,
    # plus the last one.
    assert 1 <= fits[0] <= took / 0.1 + 2, (fits[0], took)
    assert fits[0] < 25, fits[0]
    _assert_hints_match_qt(view, fitter)


def test_perf_sad_without_a_delay_every_change_is_fitted():
    """Negative control: the counter sees a fit per event-loop turn."""
    view, fitter = _delayed_view(_model(400), delay=0)
    fits = _count_fits(fitter)
    _burst(view.model(), view)
    assert fits[0] >= 40, fits[0]


def test_happy_after_a_burst_the_widths_equal_the_uncached_fit():
    a_model, b_model = _model(900, seed=21), _model(900, seed=21)
    a, _fa = _view(a_model, cache=False)
    b, _fb = _delayed_view(b_model, delay=100)
    for model, view in ((a_model, a), (b_model, b)):
        _burst(model, view, changes=30)
    assert _widths(b) == _widths(a)


def test_edge_rows_and_resizes_are_fitted_at_once_despite_the_delay():
    view, fitter = _delayed_view(_model(50), delay=10_000)
    before = _widths(view)[1]
    view.model().appendRow([QStandardItem("a"), QStandardItem("z" * 120), QStandardItem("b")])
    _pump()
    assert _widths(view)[1] > before
    view.resize(900, 300)
    _pump()
    assert sum(_widths(view)) == view.viewport().width()


def test_sad_a_negative_delay_is_refused():
    from ui.column_fit import ColumnFitter

    with pytest.raises(ValueError):
        ColumnFitter(QTableView(), cache_widths=True, data_delay_ms=-1)


def test_happy_the_transfers_dock_fits_progress_at_most_every_100_ms():
    dock = _dock(50)
    try:
        assert dock._columns._data_delay_ms == 100
    finally:
        dock.close()
