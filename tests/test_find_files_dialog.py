"""The Find Files dialog (Edit > Find Files…, Alt+F7, pane "Find in This
Folder…"), driven offscreen: the real dialog and the real MainWindow,
LocalFS and RamFs backends.

Operator punch-list items 1, 25, 51, 52 and 2 / 26 (where indexing starts).
"""

from __future__ import annotations

import io
import os
import sys
import time
import zipfile
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

import core.bookmarks as BM  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402
from ui import find_files_dialog as FD  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


def wait_until(predicate, timeout: float = 15.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


@pytest.fixture
def folder(tmp_path):
    root = tmp_path / "data"
    (root / "projects" / "alpha").mkdir(parents=True)
    (root / "projects" / "alpha" / "target-report.txt").write_text("quarterly numbers\n")
    (root / "projects" / "beta.txt").write_text("nothing\n")
    (root / "photo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\0" * 16)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("inner/target-in-zip.txt", "quarterly numbers inside\n")
    (root / "bundle.zip").write_bytes(buf.getvalue())
    return root


def _dialog(folder, **kwargs):
    scopes = [FD.ScopeChoice(LocalFS(), str(folder), label=str(folder))]
    dlg = FD.FindFilesDialog(scopes, **kwargs)
    dlg.resize(1000, 700)
    dlg.show()
    pump()
    return dlg


def _run(dlg) -> None:
    QTest.mouseClick(dlg.search_btn, Qt.MouseButton.LeftButton)
    assert wait_until(lambda: not dlg.is_running), "search did not finish"
    pump(0.15)


def _names(dlg) -> set[str]:
    return {dlg.table.item(r, 0).text() for r in range(dlg.table.rowCount())}


# --- helpers -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "value"),
    [("", -1), ("10", 10), ("10K", 10240), ("1.5 MiB", 1572864), ("2g", 2 * 1024**3),
     (" 3 kb ", 3072), ("1T", 1024**4)],
)
def test_happy_size_fields_take_units(text, value) -> None:
    assert FD.parse_size(text) == value


@pytest.mark.parametrize("text", ["abc", "-5", "1.2.3", "10Q", "1e9999"])
def test_sad_a_bad_size_is_refused(text) -> None:
    with pytest.raises(ValueError):
        FD.parse_size(text)


# --- the dialog on its own ------------------------------------------------------


def test_happy_name_search_streams_rows_and_reports_counts(folder) -> None:
    dlg = _dialog(folder)
    QTest.keyClicks(dlg.name_edit, "target*.txt")
    _run(dlg)
    assert _names(dlg) == {"target-report.txt"}
    row = 0
    assert dlg.table.item(row, 1).text() == str(folder / "projects" / "alpha")
    assert dlg.table.item(row, 4).text() == "Documents"
    assert dlg.table.item(row, 5).text() == "Local"
    assert "1 found" in dlg.status_label.text()
    dlg.close()


def test_happy_content_inside_archives_and_categories(folder) -> None:
    dlg = _dialog(folder)
    dlg.contains_edit.setText("QUARTERLY")
    dlg.archives_box.setChecked(True)
    _run(dlg)
    assert _names(dlg) == {"target-report.txt", "target-in-zip.txt"}
    member_row = next(r for r in range(dlg.table.rowCount())
                      if dlg.table.item(r, 0).text() == "target-in-zip.txt")
    assert dlg.table.item(member_row, 1).text() == f"{folder / 'bundle.zip'}!/inner"
    assert "quarterly numbers inside" in dlg.table.item(member_row, 6).text()
    dlg.contains_edit.clear()
    dlg.archives_box.setChecked(False)
    dlg.category_boxes["images"].setChecked(True)
    _run(dlg)
    assert _names(dlg) == {"photo.png"}
    dlg.close()


def test_happy_results_sort_by_size_numerically(folder) -> None:
    (folder / "small.bin").write_bytes(b"x" * 9)
    (folder / "large.bin").write_bytes(b"x" * 100)
    dlg = _dialog(folder)
    dlg.name_edit.setText("*.bin")
    _run(dlg)
    dlg.table.sortItems(2, Qt.SortOrder.AscendingOrder)
    assert [dlg.table.item(r, 0).text() for r in range(2)] == ["small.bin", "large.bin"]
    dlg.close()


def test_happy_a_remote_scope_is_searched_through_its_backend() -> None:
    ram = RamFsSession()
    ram.mkdir("/srv")
    with ram.open_write("/srv/disk.qcow2") as fh:
        fh.write(b"QFI\xfb")
    dlg = FD.FindFilesDialog([FD.ScopeChoice(ram, "/srv", label="ram:/srv")])
    dlg.show()
    dlg.category_boxes["disk_images"].setChecked(True)
    _run(dlg)
    assert _names(dlg) == {"disk.qcow2"}
    assert dlg.table.item(0, 5).text() == ram.name
    dlg.close()


def test_happy_activating_rows_asks_for_the_right_target(folder) -> None:
    dlg = _dialog(folder)
    dlg.contains_edit.setText("quarterly")
    dlg.archives_box.setChecked(True)
    _run(dlg)
    reveals, archives = [], []
    dlg.reveal_requested.connect(lambda backend, path: reveals.append(path))
    dlg.open_archive_requested.connect(
        lambda backend, path, member: archives.append((path, member))
    )
    for row in range(dlg.table.rowCount()):
        dlg.table.selectRow(row)
        QTest.keyClick(dlg.table, Qt.Key.Key_Return)
    assert reveals == [str(folder / "projects" / "alpha" / "target-report.txt")]
    assert archives == [(str(folder / "bundle.zip"), "inner/target-in-zip.txt")]
    dlg.close()


def test_happy_context_menu_copy_path_and_send_to_agent(folder) -> None:
    dlg = _dialog(folder)
    dlg.name_edit.setText("*.txt")
    _run(dlg)
    dlg.table.selectAll()
    menu = dlg._build_context_menu()
    labels = [a.text() for a in menu.actions() if not a.isSeparator()]
    assert labels == ["Open", "Reveal in Pane", "Copy Path", "Send to Agent"]
    next(a for a in menu.actions() if a.text() == "Copy Path").trigger()
    copied = set(QApplication.clipboard().text().splitlines())
    assert copied == {str(folder / "projects" / "beta.txt"),
                      str(folder / "projects" / "alpha" / "target-report.txt")}
    sent = []
    dlg.send_to_agent_requested.connect(lambda backend, paths: sent.append(sorted(paths)))
    next(a for a in menu.actions() if a.text() == "Send to Agent").trigger()
    assert sent == [sorted(copied)]
    dlg.close()


def test_happy_the_index_is_a_source_and_its_location_is_shown(folder, tmp_path) -> None:
    from core import metadata_index as MX

    db = tmp_path / "idx.sqlite"
    MX.index_dir(LocalFS(), str(folder), backend_id="LocalFS:Local", db_path=db)
    dlg = FD.FindFilesDialog([], index_db=db)
    dlg.show()
    assert str(db) in dlg.index_box.toolTip()
    dlg.index_box.setChecked(True)
    dlg.name_edit.setText("beta.txt")
    _run(dlg)
    assert _names(dlg) == {"beta.txt"}
    assert dlg.table.item(0, 5).text() == "Index: LocalFS:Local"
    opened = []
    dlg.index_open_requested.connect(lambda bid, path, is_dir: opened.append((bid, path)))
    dlg.table.selectRow(0)
    dlg._activate_current()
    assert opened == [("LocalFS:Local", str(folder / "projects" / "beta.txt"))]
    dlg.close()


# --- sad -------------------------------------------------------------------------


def test_sad_invalid_input_is_reported_and_nothing_runs(folder) -> None:
    dlg = _dialog(folder)
    dlg.name_regex_box.setChecked(True)
    dlg.name_edit.setText("[")
    QTest.mouseClick(dlg.search_btn, Qt.MouseButton.LeftButton)
    assert not dlg.is_running
    assert "invalid" in dlg.status_label.text().lower()
    dlg.name_regex_box.setChecked(False)
    dlg.name_edit.clear()
    dlg.min_size_edit.setText("lots")
    QTest.mouseClick(dlg.search_btn, Qt.MouseButton.LeftButton)
    assert not dlg.is_running and "size" in dlg.status_label.text().lower()
    dlg.close()


def test_sad_without_a_folder_or_the_index_nothing_runs() -> None:
    dlg = FD.FindFilesDialog([])
    dlg.show()
    QTest.mouseClick(dlg.search_btn, Qt.MouseButton.LeftButton)
    assert not dlg.is_running
    assert "folder" in dlg.status_label.text().lower()
    dlg.close()


def test_sad_an_unavailable_scope_is_shown_but_not_searched(folder) -> None:
    scopes = [
        FD.ScopeChoice(LocalFS(), str(folder), label=str(folder)),
        FD.ScopeChoice(None, "/remote", label="sftp://box/remote", available=False),
    ]
    dlg = FD.FindFilesDialog(scopes)
    dlg.show()
    item = dlg.scope_list.item(1)
    assert "not connected" in item.text()
    assert not item.flags() & Qt.ItemFlag.ItemIsEnabled
    dlg.name_edit.setText("beta.txt")
    _run(dlg)
    assert _names(dlg) == {"beta.txt"}
    dlg.close()


# --- edge -------------------------------------------------------------------------


def test_edge_stop_cancels_a_running_search_quickly(tmp_path) -> None:
    root = tmp_path / "wide"
    for d in range(150):
        sub = root / f"d{d}"
        sub.mkdir(parents=True)
        for f in range(20):
            (sub / f"f{f}.txt").write_text("needle\n")
    dlg = _dialog(root)
    dlg.contains_edit.setText("needle")
    QTest.mouseClick(dlg.search_btn, Qt.MouseButton.LeftButton)
    assert wait_until(lambda: dlg.table.rowCount() > 0, 10)
    started = time.monotonic()
    QTest.mouseClick(dlg.stop_btn, Qt.MouseButton.LeftButton)
    assert wait_until(lambda: not dlg.is_running, 5)
    assert time.monotonic() - started < 1.5
    assert "cancelled" in dlg.status_label.text().lower()
    dlg.close()


def test_edge_closing_the_dialog_abandons_the_search(tmp_path) -> None:
    root = tmp_path / "wide"
    for d in range(60):
        sub = root / f"d{d}"
        sub.mkdir(parents=True)
        for f in range(20):
            (sub / f"f{f}.txt").write_text("x\n")
    dlg = _dialog(root)
    dlg.contains_edit.setText("x")
    QTest.mouseClick(dlg.search_btn, Qt.MouseButton.LeftButton)
    dlg.close()
    assert dlg._job.cancelling


def test_edge_a_saved_search_fills_the_fields_and_runs(folder) -> None:
    from core import file_search as FS
    from core.search_federation import SearchQuery

    saved = FS.saved_search_to_dict(
        SearchQuery(name="*.png", categories=("images",), include_hidden=False),
        [{"backend_name": "Local", "profile_name": "", "path": str(folder)}],
    )
    dlg = FD.FindFilesDialog([FD.ScopeChoice(LocalFS(), str(folder), label=str(folder))],
                             saved=saved, autostart=True)
    dlg.show()
    assert wait_until(lambda: not dlg.is_running and dlg.table.rowCount() == 1)
    assert dlg.name_edit.text() == "*.png"
    assert dlg.category_boxes["images"].isChecked()
    assert not dlg.hidden_box.isChecked()
    dlg.close()


def test_edge_save_as_smart_folder_emits_the_query(folder) -> None:
    dlg = _dialog(folder)
    dlg.name_edit.setText("*.iso")
    dlg.category_boxes["disk_images"].setChecked(True)
    saved = []
    dlg.save_smart_folder_requested.connect(lambda name, data: saved.append((name, data)))
    dlg.save_as_smart_folder("ISOs")
    assert saved and saved[0][0] == "ISOs"
    assert saved[0][1]["name"] == "*.iso" and saved[0][1]["categories"] == ["disk_images"]
    assert saved[0][1]["scopes"] == [
        {"backend_name": "Local", "profile_name": "", "path": str(folder)}]
    dlg.close()


# --- e2e through the MainWindow -----------------------------------------------------


@pytest.fixture
def window(tmp_path, monkeypatch, folder):
    monkeypatch.setattr(BM, "BOOKMARKS_FILE", tmp_path / "bookmarks.json")
    from ui.main_window import MainWindow

    win = MainWindow()
    win._reconnect_timer.stop()
    win.show()
    win._active_pane.navigate(str(folder))
    pump()
    yield win
    for dlg in list(getattr(win, "_find_dialogs", [])):
        dlg.close()
    win.close()
    win.deleteLater()
    pump()


def _edit_menu_action(win, text: str):
    menu = next(a.menu() for a in win.menuBar().actions() if a.text() == "&Edit")
    return next(a for a in menu.actions() if a.text() == text)


def test_e2e_find_double_click_navigates_the_pane_and_selects_the_file(window, folder) -> None:
    action = _edit_menu_action(window, "&Find Files…")
    assert {s.toString() for s in action.shortcuts()} == {"Alt+F7", "Ctrl+Alt+F"}
    action.trigger()
    pump()
    dlg = window._find_dialogs[-1]
    assert dlg.scope_list.item(0).checkState() == Qt.CheckState.Checked
    assert str(folder) in dlg.scope_list.item(0).text()
    QTest.keyClicks(dlg.name_edit, "target*.txt")
    QTest.keyClick(dlg.name_edit, Qt.Key.Key_Return)
    assert wait_until(lambda: not dlg.is_running and dlg.table.rowCount() == 1)
    rect = dlg.table.visualItemRect(dlg.table.item(0, 0))
    # A real double-click starts with a press: the view reports a
    # double-click only on the index that press hit.
    QTest.mouseClick(dlg.table.viewport(), Qt.MouseButton.LeftButton, pos=rect.center())
    QTest.mouseDClick(dlg.table.viewport(), Qt.MouseButton.LeftButton, pos=rect.center())
    pane = window._active_pane
    want_dir = str(folder / "projects" / "alpha")
    assert wait_until(lambda: pane.current_path == want_dir and pane.selected_items())
    assert [os.path.basename(p) for p in pane.selected_items()] == ["target-report.txt"]


def test_e2e_find_in_this_folder_from_the_pane_menu(window, folder) -> None:
    pane = window._active_pane
    menu = pane._build_context_menu()
    action = next(a for a in menu.actions() if a.text() == "Find in This Folder…")
    action.trigger()
    pump()
    dlg = window._find_dialogs[-1]
    checked = [dlg.scope_list.item(i) for i in range(dlg.scope_list.count())
               if dlg.scope_list.item(i).checkState() == Qt.CheckState.Checked]
    assert [i.data(Qt.ItemDataRole.UserRole).path for i in checked] == [str(folder)]


def test_e2e_archive_member_opens_the_archive_view(window, folder) -> None:
    _edit_menu_action(window, "&Find Files…").trigger()
    pump()
    dlg = window._find_dialogs[-1]
    dlg.name_edit.setText("target-in-zip.txt")
    dlg.archives_box.setChecked(True)
    _run(dlg)
    assert dlg.table.rowCount() == 1
    with mock.patch.object(window, "open_archive_pane") as opener:
        dlg.table.selectRow(0)
        dlg._activate_current()
        pump()
    opener.assert_called_once_with(str(folder / "bundle.zip"))


def test_e2e_smart_folder_round_trip_through_the_sidebar(window, folder) -> None:
    _edit_menu_action(window, "&Find Files…").trigger()
    pump()
    dlg = window._find_dialogs[-1]
    dlg.name_edit.setText("beta.txt")
    dlg.save_as_smart_folder("Beta files")
    pump()
    dlg.close()
    pump()
    tree = window._bookmark_sidebar._tree
    item = next(tree.topLevelItem(i) for i in range(tree.topLevelItemCount())
                if tree.topLevelItem(i).text(0) == "Beta files")
    window._bookmark_sidebar.show()
    pump()
    before = len(window._find_dialogs)
    rect = tree.visualItemRect(item)
    QTest.mouseClick(tree.viewport(), Qt.MouseButton.LeftButton, pos=rect.center())
    assert wait_until(lambda: len(window._find_dialogs) > before)
    again = window._find_dialogs[-1]
    assert wait_until(lambda: not again.is_running and again.table.rowCount() == 1)
    assert again.table.item(0, 0).text() == "beta.txt"
    # Persisted with the bookmarks.
    assert any(b.is_smart_folder and b.name == "Beta files" for b in BM.BookmarkManager().all())


def test_e2e_a_damaged_smart_folder_says_why_it_cannot_run(window) -> None:
    smart = BM.new_smart_folder("Broken", {"version": 1, "regex": "["})
    window._bookmark_manager.add(smart)
    with mock.patch.object(QMessageBox, "warning") as warn:
        window._navigate_bookmark(smart)
    assert warn.called and "invalid" in str(warn.call_args).lower()


def test_e2e_index_active_folder_from_the_menu(window, folder) -> None:
    from core import metadata_index as MX

    action = _edit_menu_action(window, "&Index Active Folder…")
    with mock.patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes), \
            mock.patch.object(QMessageBox, "information") as info:
        action.trigger()
        assert wait_until(lambda: info.called, 15)
    assert MX.row_count() >= 5
    dlg = window._index_dialog
    assert str(MX.default_db_path()) in dlg.location_label.text()
    dlg.close()


def test_edge_resaving_keeps_a_folder_whose_connection_is_closed(folder) -> None:
    scopes = [
        FD.ScopeChoice(LocalFS(), str(folder)),
        FD.ScopeChoice(None, "/remote", available=False, backend_name="user@box",
                       profile_name="box"),
    ]
    dlg = FD.FindFilesDialog(scopes)
    saved = []
    dlg.save_smart_folder_requested.connect(lambda name, data: saved.append(data))
    dlg.save_as_smart_folder("Again")
    assert saved[0]["scopes"] == [
        {"backend_name": "Local", "profile_name": "", "path": str(folder)},
        {"backend_name": "user@box", "profile_name": "box", "path": "/remote"},
    ]
    dlg.close()


def test_e2e_closing_the_window_stops_running_find_searches(window, tmp_path) -> None:
    root = tmp_path / "many"
    for d in range(40):
        (root / f"d{d}").mkdir(parents=True)
        for f in range(20):
            (root / f"d{d}" / f"f{f}.txt").write_text("x\n")
    window._open_find_files(choices=[FD.ScopeChoice(LocalFS(), str(root))])
    dlg = window._find_dialogs[-1]
    dlg.contains_edit.setText("x")
    dlg.start_search()
    job = dlg._job
    window._abandon_background_threads()
    assert job.cancelling
    assert window._find_dialogs == [] or all(not d.isVisible() for d in window._find_dialogs)


# -- type labels with "&" --------------------------------------------------------------
#
# Reported (README screenshot run): the type boxes read "Keys _certificates"
# and "Disk _VM images". core.file_categories.label() gives the plain text
# ("Keys & certificates"); a QCheckBox reads a single "&" as its shortcut
# marker and swallowed it. The boxes now get the "&" doubled.

import re  # noqa: E402

from core import file_categories as FC  # noqa: E402

_LONE_AMPERSAND = re.compile(r"(?<!&)&(?!&)")


def test_happy_a_type_label_with_an_ampersand_shows_it(tmp_path):
    dlg = FD.FindFilesDialog([])
    try:
        for cid in FC.category_ids():
            text = dlg.category_boxes[cid].text()
            assert not _LONE_AMPERSAND.search(text), text  # no shortcut marker
            assert text.replace("&&", "&") == FC.label(cid)
        keys = next(c for c in FC.category_ids() if "certificates" in FC.label(c))
        assert dlg.category_boxes[keys].text() == "Keys && certificates"
    finally:
        dlg.close()


def test_sad_a_label_without_an_ampersand_is_unchanged(tmp_path):
    dlg = FD.FindFilesDialog([])
    try:
        plain = [c for c in FC.category_ids() if "&" not in FC.label(c)]
        assert plain
        for cid in plain:
            assert dlg.category_boxes[cid].text() == FC.label(cid)
    finally:
        dlg.close()


def test_edge_the_plain_label_stays_single_for_table_cells():
    keys = next(c for c in FC.category_ids() if "certificates" in FC.label(c))
    assert FC.label(keys) == "Keys & certificates"


# -- one folder once in "Look in" -------------------------------------------------------
#
# Reported (README screenshot run): with two local panes on the same folder,
# Find Files offered it twice. _find_scope_choices keyed on id(backend), and
# every local pane has a LocalFS of its own.


def _local_panes_on(window, paths):
    while len(window._panes) < len(paths):
        window._split_pane(Qt.Orientation.Horizontal)
        pump()
    for pane, path in zip(window._panes, paths):
        pane.navigate(str(path))
    pump()


def test_happy_two_local_panes_on_one_folder_offer_it_once(window, folder) -> None:
    _local_panes_on(window, [folder, folder])
    assert len({id(p.backend) for p in window._panes}) >= 2  # separate LocalFS objects
    choices = window._find_scope_choices()
    assert [c.path for c in choices] == [str(folder)]
    assert choices[0].checked


def test_sad_different_folders_are_all_offered(window, folder) -> None:
    other = folder / "projects"
    _local_panes_on(window, [folder, other])
    paths = sorted(c.path for c in window._find_scope_choices())
    assert paths == sorted([str(folder), str(other)])


def test_edge_the_active_pane_keeps_the_tick_when_another_pane_shows_its_folder(window, folder):
    _local_panes_on(window, [folder, folder, folder / "projects"])
    window._set_active_pane(window._panes[1])
    choices = window._find_scope_choices()
    assert [c.path for c in choices].count(str(folder)) == 1
    assert [c.checked for c in choices].count(True) == 1
    assert next(c for c in choices if c.path == str(folder)).checked  # the active pane's
