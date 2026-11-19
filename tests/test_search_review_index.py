"""Search review (2026-11-19): Find in Index, Edit > Index Active Folder… and
Tools > Find on Network Hosts.

What was wrong, each reproduced here before it was fixed:

* Find in Index - the size fields were byte spin boxes capped at
  2,000,000,000: no file above ~1.86 GiB could be searched for, a size had
  to be typed in bytes, and "max 0" meant "no limit" (no search for empty
  files). They take ``10K`` / ``1.5M`` / ``4G`` now, like Find Files.
* Find in Index - the handbook promises a date range; the window had none.
  *Modified: after / before* now, both days included.
* Find in Index - the window opened with the focus on the close corner:
  typing went nowhere. The name field has it now.
* Find in Index - Enter on a selected result ran the search again (the
  default button) instead of opening the result.
* Find in Index - sizes were cut, not rounded (1.99 GiB read "1 GiB"),
  folders read "0 B", and the columns did not sort.
* Opening an index hit worked only when the *active* pane was on its
  connection (another open pane on it was ignored), and a file hit only
  showed its folder, the file not selected.
* Index Active Folder - a folder that is a link (an SMB junction is listed
  as a folder) was walked into: a junction pointing up indexed the same
  files again, level after level, up to 50 levels deep.
* Find on Network Hosts - every hit re-sorted the whole result table:
  10,000 hits held the window for ~50 s.
* Find on Network Hosts - Enter on a selected result started a new search
  and threw the results away.
* Find on Network Hosts - a host whose search was cancelled midway was
  listed as "done" and counted as searched.
"""

from __future__ import annotations

import dataclasses
import os
import sys
import time
import types
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QDate, Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import metadata_index as MX  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])
GIB = 1024**3


def _wait(cond, timeout: float = 15.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return cond()


# ---------------------------------------------------------------------------
# Find in Index
# ---------------------------------------------------------------------------


@pytest.fixture
def db(tmp_path, monkeypatch):
    path = tmp_path / "metadata.sqlite"
    monkeypatch.setattr(MX, "_DEFAULT_DB", path)
    rows = [
        ("/d/disk.iso", "disk.iso", 5 * GIB, datetime(2026, 11, 10, 23, 30)),
        ("/d/movie.mkv", "movie.mkv", 3 * GIB, datetime(2026, 11, 11, 0, 10)),
        ("/d/notes.txt", "notes.txt", 1536, datetime(2026, 11, 9, 12, 0)),
        ("/d/empty.txt", "empty.txt", 0, datetime(2026, 11, 1, 8, 0)),
        ("/d/big.bin", "big.bin", 2 * GIB - 1, datetime(2026, 10, 1, 8, 0)),
    ]
    for path_, name, size, when in rows:
        MX.upsert(path, "LocalFS:Local", path_, name=name, size=size, is_dir=False, modified=when)
    MX.upsert(path, "LocalFS:Local", "/d", name="d", size=4096, is_dir=True,
              modified=datetime(2026, 11, 11, 1, 0))
    return path


@pytest.fixture
def dialog(db):
    from ui import metadata_search_dialog as MSD

    dlg = MSD.MetadataSearchDialog()
    dlg.show()
    APP.processEvents()
    yield dlg
    dlg.reject()
    dlg.deleteLater()
    APP.processEvents()


def _search(dlg) -> list[str]:
    dlg._search_btn.click()
    assert _wait(lambda: not dlg._search_job.running)
    APP.processEvents()
    return sorted(dlg._table.item(r, 0).text() for r in range(dlg._table.rowCount()))


def test_sad_files_above_2_gib_can_be_searched_by_size(dialog):
    dialog._min_size_edit.setText("4G")
    assert _search(dialog) == ["disk.iso"]
    dialog._min_size_edit.setText("2.5 GiB")
    dialog._max_size_edit.setText("3G")
    assert _search(dialog) == ["movie.mkv"]


def test_edge_max_size_zero_finds_the_empty_files(dialog):
    dialog._max_size_edit.setText("0")
    assert _search(dialog) == ["empty.txt"]


def test_sad_a_size_that_is_no_size_says_so_and_searches_nothing(dialog, monkeypatch):
    from ui import metadata_search_dialog as MSD

    warned = []
    monkeypatch.setattr(MSD.QMessageBox, "warning", lambda *a, **k: warned.append(a))
    started = []
    monkeypatch.setattr(dialog._search_job, "start", lambda *a, **k: started.append(a))
    dialog._min_size_edit.setText("lots")
    dialog._search_btn.click()
    assert warned and "lots" in warned[0][2]
    assert not started


def test_happy_date_range_includes_both_whole_days(dialog):
    dialog._needle_edit.setText(".")  # files only, not the folder "d"
    dialog._after_box.setChecked(True)
    dialog._after_edit.setDate(QDate(2026, 11, 10))
    dialog._before_box.setChecked(True)
    dialog._before_edit.setDate(QDate(2026, 11, 10))
    # 23:30 on the "before" day is in; 00:10 the next day is not.
    assert _search(dialog) == ["disk.iso"]
    dialog._before_box.setChecked(False)
    assert _search(dialog) == ["disk.iso", "movie.mkv"]


def test_happy_the_name_field_has_the_focus_when_the_window_opens(dialog):
    dialog.activateWindow()
    APP.processEvents()
    assert dialog.focusWidget() is dialog._needle_edit


def test_sad_enter_on_a_result_opens_it_and_does_not_search_again(dialog, monkeypatch):
    _search(dialog)
    opened = []
    dialog.open_requested.connect(lambda *a: opened.append(a))
    searches = []
    monkeypatch.setattr(dialog, "_do_search", lambda: searches.append(1))
    dialog._table.setFocus()
    dialog._table.setCurrentCell(0, 0)
    QTest.keyClick(dialog._table, Qt.Key.Key_Return)
    APP.processEvents()
    assert len(opened) == 1 and not searches


def test_edge_sizes_are_rounded_folders_have_none_and_columns_sort(dialog):
    from ui.format_utils import human_bytes

    _search(dialog)
    table = dialog._table
    by_name = {table.item(r, 0).text(): r for r in range(table.rowCount())}
    assert table.item(by_name["big.bin"], 2).text() == human_bytes(2 * GIB - 1)  # not "1 GiB"
    assert table.item(by_name["notes.txt"], 2).text() == human_bytes(1536)
    assert table.item(by_name["d"], 2).text() == ""
    assert table.isSortingEnabled()
    table.sortItems(2, Qt.SortOrder.DescendingOrder)
    names = [table.item(r, 0).text() for r in range(table.rowCount())]
    assert names[:3] == ["disk.iso", "movie.mkv", "big.bin"]  # by bytes, not by text
    # The row's entry follows the sort: Enter opens what is shown.
    opened = []
    dialog.open_requested.connect(lambda *a: opened.append(a))
    table.setCurrentCell(0, 1)
    dialog._on_row_activated()
    assert opened == [("LocalFS:Local", "/d/disk.iso", False)]


# ---------------------------------------------------------------------------
# Opening an index hit (main window)
# ---------------------------------------------------------------------------


class _Pane:
    def __init__(self, backend, path="/"):
        self.backend = backend
        self.current_path = path
        self.revealed: list = []
        self.navigated: list = []

    def reveal_path(self, path):
        self.revealed.append(path)

    def navigate_async(self, path):
        self.navigated.append(path)


class _Remote:
    name = "alice@fs1"

    def parent(self, path):
        return path.rsplit("/", 1)[0] or "/"


def _window(active, panes):
    from ui.main_window import MainWindow

    win = types.SimpleNamespace(_active_pane=active, _panes=list(panes), activated=[])
    win._pane_for_backend_id = types.MethodType(MainWindow._pane_for_backend_id, win)
    win._set_active_pane = lambda pane: (win.activated.append(pane),
                                         setattr(win, "_active_pane", pane))
    return win, MainWindow._on_metadata_search_open


def test_sad_a_hit_opens_in_the_other_pane_that_is_on_its_connection(monkeypatch):
    from ui import main_window as MW

    infos = []
    monkeypatch.setattr(MW.QMessageBox, "information", lambda *a, **k: infos.append(a))
    local, remote = _Pane(LocalFS()), _Pane(_Remote())
    win, handler = _window(local, [local, remote])
    handler(win, "_Remote:alice@fs1", "/share/docs/report.docx", False)
    assert not infos
    assert win.activated == [remote]
    assert remote.revealed == ["/share/docs/report.docx"]  # the file selected
    handler(win, "_Remote:alice@fs1", "/share/docs", True)
    assert remote.navigated == ["/share/docs"]


def test_sad_a_hit_on_a_connection_no_pane_is_on_says_so(monkeypatch):
    from ui import main_window as MW

    infos = []
    monkeypatch.setattr(MW.QMessageBox, "information", lambda *a, **k: infos.append(a))
    local = _Pane(LocalFS())
    win, handler = _window(local, [local])
    handler(win, "_Remote:bob@fs9", "/x.txt", False)
    assert infos and "bob@fs9" in infos[0][2]
    assert not local.revealed and not local.navigated


# ---------------------------------------------------------------------------
# Index Active Folder: link folders
# ---------------------------------------------------------------------------


class _JunctionFS(LocalFS):
    """LocalFS that lists a link to a folder the way SMB lists a junction:
    a folder that is a link."""

    def list_dir(self, path):
        items = super().list_dir(path)
        return [dataclasses.replace(i, is_dir=True) if i.is_link and os.path.isdir(
            os.path.join(path, i.name)) else i for i in items]


def test_sad_a_link_folder_is_indexed_but_not_walked_into(tmp_path):
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "a.txt").write_text("a")
    os.symlink(root, root / "sub" / "up")  # a junction pointing up: a loop
    db = tmp_path / "m.sqlite"
    indexed, removed = MX.reindex_dir(_JunctionFS(), str(root), backend_id="J", db_path=db)
    paths = sorted(e.path for e in MX.search_all(db_path=db))
    assert paths == sorted([str(root / "sub"), str(root / "sub" / "a.txt"),
                            str(root / "sub" / "up")])
    assert indexed == 3 and removed == 0


# ---------------------------------------------------------------------------
# Find on Network Hosts
# ---------------------------------------------------------------------------


@pytest.fixture
def settings(monkeypatch):
    from core import open_limits as OL

    store: dict = {}
    monkeypatch.setattr(OL, "read_setting", lambda key, default=None: store.get(key, default))
    monkeypatch.setattr(OL, "write_setting", lambda key, value: store.__setitem__(key, value))
    return store


def _hits_sweep(n, runs):
    from core import remote_sweep as RS

    def sweep(config, *, on_hit, on_status, cancel=None, **_kw):
        runs.append(config)
        on_status("fs1", "searching", "")
        for i in range(n):
            on_hit(RS.SweepHit("fs1", "data", f"/d/f{i:05}.txt", i, 1_700_000_000.0))
        on_status("fs1", "done", "")
        return RS.SweepResult(hosts_total=1, hosts_searched=1, hits=n)

    return sweep


def test_perf_sad_many_hits_do_not_hold_the_window(settings):
    from ui.network_search_dialog import NetworkSearchDialog

    runs: list = []
    dlg = NetworkSearchDialog(sweep_fn=_hits_sweep(6000, runs))
    try:
        dlg.targets_edit.setPlainText("fs1")
        started = time.monotonic()
        dlg.start()
        assert _wait(lambda: not dlg.is_running(), timeout=60)
        elapsed = time.monotonic() - started
        assert dlg.results_table.rowCount() == 6000
        assert "6000 files" in dlg.summary_label.text()
        # ~18 s before (every hit re-sorted the whole table), well under 1 s now.
        assert elapsed < 6, f"6000 hits took {elapsed:.1f} s"
        # Still sorted, and a row still leads to its own hit.
        dlg.results_table.sortItems(1, Qt.SortOrder.DescendingOrder)
        dlg.results_table.selectRow(0)
        assert [h.size for h in dlg._selected_hits()] == [5999]
    finally:
        dlg.close()
        dlg.deleteLater()


def test_sad_enter_on_a_result_opens_it_and_starts_no_new_search(settings):
    from ui.network_search_dialog import NetworkSearchDialog

    runs: list = []
    opened: list = []
    dlg = NetworkSearchDialog(sweep_fn=_hits_sweep(3, runs),
                              open_hit=lambda hit, login: opened.append(hit))
    try:
        dlg.targets_edit.setPlainText("fs1")
        dlg.show()
        dlg.start()
        assert _wait(lambda: not dlg.is_running())
        dlg.results_table.setFocus()
        dlg.results_table.selectRow(1)
        QTest.keyClick(dlg.results_table, Qt.Key.Key_Return)
        _wait(lambda: False, timeout=0.3)
        assert len(runs) == 1, "Enter started another search"
        assert dlg.results_table.rowCount() == 3
        assert len(opened) == 1
    finally:
        dlg.close()
        dlg.deleteLater()


def test_sad_a_host_cancelled_midway_is_not_listed_as_searched():
    import threading

    from test_remote_sweep import _FakeSmb, _Host

    from core import remote_sweep as RS

    cancel = threading.Event()

    class Slow(_FakeSmb):
        def list_dir(self, share, path):
            cancel.set()  # the user cancels while the first folder is read
            return [("a.txt", False, 1, 0.0), ("sub", True, 0, 0.0)]

    statuses = []
    config = RS.SweepConfig(targets="fs1", username="alice", password="pw")
    result = RS.sweep(config, on_hit=lambda h: None,
                      on_status=lambda host, state, detail="": statuses.append(state),
                      connect=lambda h, port, timeout: Slow(_Host()),
                      reachable=lambda h, port, timeout: True, cancel=cancel)
    assert result.cancelled
    assert result.hosts_searched == 0
    assert "done" not in statuses and statuses[-1] == "cancelled"


def test_edge_results_are_listed_a_to_z_by_default(settings):
    from ui.network_search_dialog import NetworkSearchDialog

    runs: list = []
    dlg = NetworkSearchDialog(sweep_fn=_hits_sweep(3, runs))
    try:
        dlg.targets_edit.setPlainText("fs1")
        dlg.start()
        assert _wait(lambda: not dlg.is_running())
        uncs = [dlg.results_table.item(r, 0).text() for r in range(3)]
        assert uncs == sorted(uncs)
    finally:
        dlg.close()
        dlg.deleteLater()


def test_sad_a_name_without_wildcards_matches_anywhere_in_the_name():
    """As in Find Files: "report" finds "Q3-report.docx" (it found only a
    file named exactly "report"), case and Unicode form ignored."""
    import unicodedata

    from test_remote_sweep import _Host, _run

    hosts = {"fs1": _Host({"data": {
        "/docs/Q3-report.docx": 1, "/docs/other.txt": 2, "/Straße.txt": 3,
        "/" + unicodedata.normalize("NFD", "Ärger.pdf"): 4}})}
    _, hits, _ = _run(hosts, name="report")
    assert [h.path for h in hits] == ["/docs/Q3-report.docx"]
    _, hits, _ = _run(hosts, name="STRASSE")
    assert [h.path for h in hits] == ["/Straße.txt"]
    _, hits, _ = _run(hosts, name="ärger*")
    assert [h.size for h in hits] == [4]
    _, hits, _ = _run(hosts, name="*.TXT")
    assert sorted(h.path for h in hits) == ["/Straße.txt", "/docs/other.txt"]


# ---------------------------------------------------------------------------
# Index Active Folder: folders that cannot be read
# ---------------------------------------------------------------------------


class _Unreadable(LocalFS):
    """LocalFS where the folders named in ``refuse`` cannot be listed."""

    def __init__(self, refuse):
        super().__init__()
        self.refuse = set(refuse)

    def list_dir(self, path):
        if path in self.refuse:
            raise PermissionError(13, "Permission denied", path)
        return super().list_dir(path)


def _index_in_dialog(monkeypatch, tmp_path, backend, folder):
    from PyQt6.QtWidgets import QMessageBox

    from ui import metadata_search_dialog as MSD

    monkeypatch.setattr(MX, "_DEFAULT_DB", tmp_path / "m.sqlite")
    monkeypatch.setattr(MSD.QMessageBox, "question",
                        lambda *a, **k: QMessageBox.StandardButton.Yes)
    shown = []
    monkeypatch.setattr(MSD.QMessageBox, "information", lambda *a, **k: shown.append(("info", a[2])))
    monkeypatch.setattr(MSD.QMessageBox, "warning", lambda *a, **k: shown.append(("warning", a[2])))
    pane = types.SimpleNamespace(backend=backend, current_path=folder)
    dlg = MSD.MetadataSearchDialog(pane)
    try:
        dlg._do_index_active()
        assert _wait(lambda: bool(shown))
    finally:
        dlg.reject()
        dlg.deleteLater()
    return shown[0]


def test_sad_a_folder_that_cannot_be_read_is_not_reported_as_indexed(monkeypatch, tmp_path):
    root = tmp_path / "share"
    root.mkdir()
    kind, text = _index_in_dialog(monkeypatch, tmp_path, _Unreadable({str(root)}), str(root))
    # It said "Indexed 0 entries under …" - as if the folder were empty.
    assert kind == "warning"
    assert "Permission denied" in text or "permission" in text.lower()


def test_sad_subfolders_that_cannot_be_read_are_named(monkeypatch, tmp_path):
    root = tmp_path / "share"
    (root / "open").mkdir(parents=True)
    (root / "open" / "a.txt").write_text("a")
    (root / "locked").mkdir()
    kind, text = _index_in_dialog(monkeypatch, tmp_path,
                                  _Unreadable({str(root / "locked")}), str(root))
    assert kind == "info"
    assert "Indexed 3 entries" in text
    assert str(root / "locked") in text


def test_edge_brackets_in_a_plain_name_are_part_of_the_name():
    from test_remote_sweep import _Host, _run

    hosts = {"fs1": _Host({"data": {"/Song [Remix].mp3": 1, "/Song R.mp3": 2, "/IMG_7.jpg": 3}})}
    _, hits, _ = _run(hosts, name="song [remix]")
    assert [h.size for h in hits] == [1]
    _, hits, _ = _run(hosts, name="IMG_[0-9].*")  # with * it stays a pattern
    assert [h.size for h in hits] == [3]
