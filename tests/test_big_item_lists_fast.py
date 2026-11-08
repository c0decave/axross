"""Big item lists: built off the GUI thread, or not built at all.

Measured before (scripts in the measurement notes, gui_stall.py):

* ui.markup_guard: wrapping the virtual ``setData`` sent every setData Qt
  makes itself (setText, setEditable, setFlags) through Python, and the
  wrapper read an enum property per call: 50,000 items + setData +
  setToolTip went from 83 to 456 ms. A role given by keyword
  (``setData(text, role=ToolTipRole)``) was not defused at all.
* The archive pane built its 250,000 QStandardItems (a 50,000-member zip)
  on the GUI thread: a 2.1-2.6 s freeze.
* Compare's "All" made a QTableWidgetItem per cell (100,000) - 2.7-3.3 s.
* Find Files switched sorting off and on around every batch of rows (ten
  times a second, every row sorted again and every column measured again)
  and put all rows still queued at the end in at once.

The guards count calls and threads, not milliseconds.
"""

from __future__ import annotations

import collections
import os
import sys
import threading
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtGui import QStandardItem  # noqa: E402
from PyQt6.QtWidgets import (  # noqa: E402
    QApplication,
    QComboBox,
    QListWidgetItem,
    QTableWidgetItem,
    QTreeWidgetItem,
)

import ui  # noqa: E402,F401 - installs ui.markup_guard
from ui import markup_guard as MG  # noqa: E402

APP = QApplication.instance() or QApplication([])
WIDE = "<img width=4000 height=4000 src=nothing-here>"
TIP = Qt.ItemDataRole.ToolTipRole


def _wait(cond, timeout=30.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.005)
    return cond()


# -- ui.markup_guard ------------------------------------------------------------------------------


def test_happy_every_item_kind_still_defuses_a_tooltip_set_by_role():
    std = QStandardItem("x")
    std.setData(WIDE, TIP)
    table = QTableWidgetItem("x")
    table.setData(TIP, WIDE)
    lst = QListWidgetItem("x")
    lst.setData(TIP, WIDE)
    tree = QTreeWidgetItem(["x"])
    tree.setData(0, TIP, WIDE)
    combo = QComboBox()
    combo.addItem("x")
    combo.setItemData(0, WIDE, TIP)
    for text in (std.toolTip(), table.toolTip(), lst.toolTip(), tree.toolTip(0),
                 combo.itemData(0, TIP)):
        assert "&lt;img" in text
    as_int = QStandardItem("x")
    as_int.setData(WIDE, int(TIP))
    assert "&lt;img" in as_int.toolTip()


def test_sad_a_tooltip_role_given_by_keyword_is_defused_too():
    """Before: setData(text, role=ToolTipRole) passed the wrapper unchanged."""
    std = QStandardItem("x")
    std.setData(WIDE, role=TIP)
    assert "&lt;img" in std.toolTip()
    combo = QComboBox()
    combo.addItem("x")
    combo.setItemData(0, WIDE, role=TIP)
    assert "&lt;img" in combo.itemData(0, TIP)


def test_edge_other_values_and_roles_pass_unchanged():
    item = QStandardItem("x")
    item.setData(5, TIP)
    assert item.data(TIP) == 5
    item.setData(WIDE, Qt.ItemDataRole.DisplayRole)  # shown as plain text in a view
    assert item.text() == WIDE
    item.setData("a < b", TIP)
    assert item.toolTip() == "a < b"  # a "<" that is no markup stays as written


def test_perf_happy_items_without_markup_never_reach_defuse(monkeypatch):
    calls = []
    real = MG.defuse
    monkeypatch.setattr(MG, "defuse", lambda text: calls.append(text) or real(text))
    for i in range(500):
        item = QTableWidgetItem(f"name {i}")
        item.setData(Qt.ItemDataRole.UserRole, i)
        item.setToolTip(f"/some/path/{i}")
        std = QStandardItem(f"n{i}")
        std.setEditable(False)
        std.setData(f"member/{i}", Qt.ItemDataRole.UserRole)
    assert calls == []


def test_perf_sad_markup_still_reaches_defuse(monkeypatch):
    """Negative control: the counter sees a text with markup."""
    calls = []
    real = MG.defuse
    monkeypatch.setattr(MG, "defuse", lambda text: calls.append(text) or real(text))
    QTableWidgetItem("x").setToolTip(WIDE)
    QStandardItem("x").setData(WIDE, TIP)
    assert len(calls) >= 2


# -- the archive pane ------------------------------------------------------------------------------


def _entries(n: int):
    from core.archive import ArchiveEntry

    out = []
    for i in range(n):
        out.append(ArchiveEntry(f"dir{i // 50:02d}/sub{i % 3}/file_{i:04d}.txt", i, i // 2,
                                1.7e9, False, 0o644, "file"))
    out.append(ArchiveEntry("dir00/inner.zip", 10, 5, 1.7e9, False, 0o644, "file"))
    out.append(ArchiveEntry("empty/", 0, 0, None, True, None, "dir"))
    return out


def _tree_rows(model) -> list[tuple]:
    out = []
    stack = [(model.invisibleRootItem(), 0)]
    while stack:
        parent, depth = stack.pop()
        for r in range(parent.rowCount()):
            cells = [parent.child(r, c) for c in range(5)]
            out.append((depth, tuple(c.text() for c in cells),
                        cells[0].data(Qt.ItemDataRole.UserRole), cells[0].toolTip(),
                        tuple(c.isEditable() for c in cells)))
            stack.append((cells[0], depth + 1))
    return out


def test_happy_rows_made_on_a_worker_thread_give_the_same_tree():
    from ui import archive_pane as AP

    entries = _entries(400)
    made = {}
    worker = threading.Thread(target=lambda: made.setdefault("rows", AP.archive_rows(entries)))
    worker.start()
    worker.join()
    assert _tree_rows(AP._tree_model(made["rows"])) == _tree_rows(AP.build_archive_tree(entries))
    rows = _tree_rows(AP.build_archive_tree(entries))
    assert all(editable == (False,) * 5 for *_rest, editable in rows)
    assert any(tip for _d, _t, _m, tip, _e in rows)  # the archive member's tooltip


def test_edge_a_cancelled_build_stops():
    from ui import archive_pane as AP

    with pytest.raises(AP._Cancelled):
        AP.archive_rows(_entries(5000), cancel=lambda: True)


def test_perf_happy_the_pane_builds_its_tree_off_the_gui_thread(tmp_path, monkeypatch):
    from ui import archive_pane as AP

    path = tmp_path / "many.zip"
    with zipfile.ZipFile(path, "w") as zf:
        for i in range(300):
            zf.writestr(f"d{i // 100}/f{i:03d}.txt", b"x")
    threads = []
    real = AP.archive_rows
    monkeypatch.setattr(AP, "archive_rows", lambda *a, **k: threads.append(
        threading.current_thread() is threading.main_thread()) or real(*a, **k))
    builds = []
    real_build = AP.build_archive_tree
    monkeypatch.setattr(AP, "build_archive_tree", lambda e: builds.append(1) or real_build(e))
    pane = AP.ArchivePaneWidget(str(path), background=True)
    try:
        assert _wait(lambda: not pane.loading and pane._entries)
        assert threads == [False] and builds == []  # made once, on the worker
        model = pane._tree.model()
        assert sum(model.item(r, 0).rowCount() for r in range(model.rowCount())) == 300
    finally:
        pane.close()
        pane.deleteLater()


# -- Compare ---------------------------------------------------------------------------------------


def _compare_dialog(entries):
    from ui.compare_dialog import CompareDialog

    class Pane:
        backend = None
        current_path = "/"

    dlg = CompareDialog(Pane(), Pane(), compare_fn=lambda *a, **k: entries)
    dlg.wait_for_compare()
    return dlg


def _compared(n: int):
    from core.tree_compare import ComparedEntry, Status
    from models.file_item import FileItem

    out = []
    for i in range(n):
        side = FileItem(name=f"f{i:05d}", size=i)
        status = (Status.SAME, Status.DIFFERS, Status.LEFT_ONLY)[i % 3]
        out.append(ComparedEntry(rel_path=f"d/f{i:05d}", status=status,
                                 left=side, right=None if status == Status.LEFT_ONLY else side,
                                 reason="size" if status == Status.DIFFERS else ""))
    return out


def test_happy_compare_rows_are_the_visible_entries_and_selection_maps_back():
    entries = _compared(300)
    dlg = _compare_dialog(entries)
    try:
        dlg.set_filter("All")
        assert dlg._table.rowCount() == 300
        model = dlg._table.model()
        assert model.index(4, 0).data() == "d/f00004"
        assert model.index(4, 1).data() == "differs"
        assert model.index(5, 3).data() == "—"  # only left
        dlg._table.selectRow(7)
        assert [e.rel_path for e in dlg.selected_entries()] == ["d/f00007"]
        dlg.set_filter("Left only")
        assert dlg._table.rowCount() == 100
        dlg._table.selectAll()
        assert len(dlg.selected_entries()) == 100
    finally:
        dlg.close()
        dlg.deleteLater()


def test_perf_happy_all_asks_only_for_the_rows_on_screen(monkeypatch):
    from ui import compare_dialog as CD

    dlg = _compare_dialog(_compared(20000))
    try:
        dlg.resize(900, 500)
        dlg.show()
        calls = []
        real = CD._EntriesModel.cell_text
        monkeypatch.setattr(CD._EntriesModel, "cell_text",
                            lambda self, e, c: calls.append(1) or real(self, e, c))
        dlg.set_filter("All")
        for _ in range(5):
            APP.processEvents()
        assert dlg._table.rowCount() == 20000
        assert len(calls) < 20000  # not five texts per entry made up front
    finally:
        dlg.close()
        dlg.deleteLater()


# -- Find Files ------------------------------------------------------------------------------------


def _find_dialog():
    from core.local_fs import LocalFS
    from ui import find_files_dialog as FD

    return FD.FindFilesDialog([FD.ScopeChoice(LocalFS(), "/srv")])


def _hits(n):
    from core.search_federation import SearchHit

    return [SearchHit(backend_label="Local", path=f"/srv/d{i % 7}/n{(i * 7919) % n:05d}.log",
                      size=i, mtime=1.7e9 + i) for i in range(n)]


def test_happy_the_results_are_sorted_once_the_search_has_ended(monkeypatch):
    from core import file_search as FS
    from ui import find_files_dialog as FD

    dlg = _find_dialog()
    try:
        scope = FS.SearchScope(dlg._checked_scopes()[0].backend, "/srv")
        switched = []
        real = dlg.table.setSortingEnabled
        monkeypatch.setattr(dlg.table, "setSortingEnabled",
                            lambda on: switched.append(on) or real(on))
        dlg.table.setSortingEnabled(False)  # as start_search leaves it
        switched.clear()
        dlg._queue = collections.deque((scope, h) for h in _hits(1200))
        while dlg._queue:
            dlg._drain()
        assert switched == []  # no sort while rows come in
        dlg._on_finished("done", FS.SearchSummary(found=1200), False)
        assert _wait(lambda: not dlg.is_running)
        assert switched == [True]
        names = [dlg.table.item(r, FD.COL_NAME).text() for r in range(dlg.table.rowCount())]
        header = dlg.table.horizontalHeader()
        assert header.sortIndicatorSection() == FD.COL_NAME
        descending = header.sortIndicatorOrder() == Qt.SortOrder.DescendingOrder
        assert names == sorted(names, reverse=descending) and len(names) == 1200
        assert "1200 found" in dlg.status_label.text()
    finally:
        dlg.close()
        dlg.deleteLater()


def test_edge_rows_queued_at_the_end_go_in_in_steps_before_it_is_finished(monkeypatch):
    from core import file_search as FS
    from ui import find_files_dialog as FD

    monkeypatch.setattr(FD, "_DRAIN_BUDGET_S", 0.0)  # every step: 16 rows, then the event loop
    dlg = _find_dialog()
    try:
        scope = FS.SearchScope(dlg._checked_scopes()[0].backend, "/srv")
        dlg.table.setSortingEnabled(False)
        dlg._queue = collections.deque((scope, h) for h in _hits(200))
        dlg._on_finished("done", FS.SearchSummary(found=200), False)
        assert dlg.is_running and dlg.table.rowCount() < 200  # not all at once
        assert _wait(lambda: not dlg.is_running)
        assert dlg.table.rowCount() == 200 and "200 found" in dlg.status_label.text()
    finally:
        dlg.close()
        dlg.deleteLater()


def test_sad_closing_while_rows_go_in_leaves_a_sorted_table_and_no_timer():
    from core import file_search as FS

    dlg = _find_dialog()
    try:
        scope = FS.SearchScope(dlg._checked_scopes()[0].backend, "/srv")
        dlg.table.setSortingEnabled(False)
        dlg._queue = collections.deque((scope, h) for h in _hits(3000))
        dlg._on_finished("done", FS.SearchSummary(found=3000), False)
        dlg.close()
        assert not dlg._drain_timer.isActive() and not dlg.is_running
        assert dlg.table.isSortingEnabled()
    finally:
        dlg.deleteLater()
