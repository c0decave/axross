"""UX review round 9: the smaller findings (M1, the arrows, is in
tests/test_theme_contrast.py; M2, the German handbook's dashes, in
tests/test_ux_round8.py).

L1 raw English errors in German messages (a vanished copy destination, an
   S3 profile without a bucket, a WebDAV profile without a URL).
L2 Quick Connect's and the toolbar menu's group headings were invisible.
L3 Ctrl+Z after a permanent delete talked about an undo.
L4 the time left of a transfer was not localised.
L5 "Local" in German windows; the trash window's sizes and its ID column.
L6 Esc in the path bar; Ctrl+L / Ctrl+F between the path and filter fields.
L7 mixed German / English in the handbook; one word family for toolbars.
L8 the empty Transfers panel on a small screen.
Known: German names of the Duplicate Finder and Disk Usage, the scripting
guide's keys and buttons, the memory legend's percent.
"""

from __future__ import annotations

import errno
import json
import os
import re
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])
GERMAN = json.loads((ROOT / "resources/i18n/de.json").read_text(encoding="utf-8"))


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


def wait_for(cond, seconds: float = 10.0) -> bool:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return cond()


@pytest.fixture
def german():
    from core import i18n

    i18n.install("de")
    yield
    i18n.install("en")


def _open_window():
    from core.local_fs import LocalFS
    from ui.main_window import MainWindow

    win = MainWindow()
    win._reconnect_timer.stop()
    win.resize(1280, 800)
    win.show()
    pump()
    while len(win._panes) < 2:
        win._add_pane_to_splitter(win._root_splitter, LocalFS())
    return win


def _close_window(win) -> None:
    win._quit_with_transfers = True
    win.close()
    win.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    pump()


@pytest.fixture
def window():
    win = _open_window()
    yield win
    _close_window(win)


@pytest.fixture
def german_window(german):
    win = _open_window()
    yield win
    _close_window(win)


# --- L1 ---------------------------------------------------------------------


def test_sad_an_s3_profile_without_a_bucket_says_so_in_german(german):
    pytest.importorskip("boto3")
    from core.s3_client import S3Session

    with pytest.raises(OSError) as caught:
        S3Session(bucket="", endpoint="http://127.0.0.1:1")
    from core.user_errors import describe

    text = describe(caught.value)
    assert text.startswith("Das S3-Profil nennt keinen Bucket"), text
    assert "Invalid" not in text and "Bucket names" not in text
    with pytest.raises(OSError) as caught:
        S3Session(bucket="Upper_Case", endpoint="http://127.0.0.1:1")
    assert describe(caught.value).startswith("Ungültiger S3-Bucket-Name „Upper_Case“")


def test_sad_a_webdav_profile_without_a_url_says_so_in_german(german):
    pytest.importorskip("requests")
    pytest.importorskip("defusedxml")
    from core.user_errors import describe
    from core.webdav_client import WebDavSession

    with pytest.raises(OSError) as caught:
        WebDavSession("")
    text = describe(caught.value)
    assert text.startswith("Das WebDAV-Profil hat keine Serveradresse"), text
    assert "No scheme supplied" not in text
    with pytest.raises(OSError) as caught:
        WebDavSession("dav.example.com/remote.php")
    assert caught.value.errno == errno.EINVAL
    assert "ist keine WebDAV-Adresse" in describe(caught.value)


def test_sad_copying_into_a_vanished_folder_has_no_raw_errno(german_window, tmp_path):
    win = german_window
    source, target = win._panes[0], win._panes[1]
    (tmp_path / "a.txt").write_text("x")
    source.navigate(str(tmp_path))
    pump(0.2)
    shown: list[str] = []
    with mock.patch("ui.main_window.QMessageBox.warning",
                    side_effect=lambda _p, _t, text, *a, **k: shown.append(text)):
        win._request_transfer(source, target, [str(tmp_path / "a.txt")],
                              dest_dir=str(tmp_path / "gone"))
        assert wait_for(lambda: shown)
    assert "[Errno" not in shown[0] and "No such file" not in shown[0], shown[0]
    assert "wurde nicht gefunden" in shown[0], shown[0]


# --- L2 ---------------------------------------------------------------------


def _headers(menu):
    from ui.mnemonics import is_header

    return [a for a in menu.actions() if is_header(a)]


def test_happy_quick_connect_headings_are_bold_entries_not_sections(german_window):
    from core.profiles import ConnectionProfile

    win = german_window
    for name in ("alpha", "beta"):
        win._profile_manager.add(
            ConnectionProfile(name=name, protocol="sftp", host="h.invalid", username="u"))
    win._recent_profiles = ["beta"]
    menu = win._build_quick_connect_menu()
    menu.aboutToShow.emit()
    headers = _headers(menu)
    assert [a.text() for a in headers] == ["Zuletzt verwendet", "Alle Profile"]
    for action in headers:
        assert not action.isEnabled() and action.font().bold() and not action.isSeparator()
        assert "&" not in action.text()  # no underlined letter: it is never picked
    # Fusion draws no text for a section: there must be none left.
    assert not [a for a in menu.actions() if a.isSeparator() and a.text()]
    menu.deleteLater()


def test_edge_the_toolbar_menu_heads_its_two_groups(german_window):
    menu = german_window.createPopupMenu()
    menu.aboutToShow.emit()
    texts = [a.text() for a in menu.actions() if a.isVisible()]
    assert texts[0] == "Panels"
    assert "Symbolleisten" in texts
    assert texts.index("Symbolleisten") > texts.index("")  # after the separator
    assert all(a.font().bold() and not a.isEnabled() for a in _headers(menu))
    menu.deleteLater()


def test_sad_a_header_takes_no_mnemonic_and_keeps_an_ampersand():
    from PyQt6.QtWidgets import QMenu

    from ui import mnemonics

    menu = QMenu()
    header = mnemonics.add_header(menu, "Web & Mail")
    entry = menu.addAction("Connect")
    mnemonics.assign(menu)
    assert header.text() == "Web && Mail"
    assert mnemonics.mnemonic_of(entry.text()) == "c"
    menu.deleteLater()


# --- L3 ---------------------------------------------------------------------


def _journal(tmp_path, monkeypatch):
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "ops.jsonl"))
    from core import operation_journal as OJ

    return OJ


def test_sad_ctrl_z_after_a_permanent_delete_names_it_and_offers_nothing(tmp_path, monkeypatch):
    from core.local_fs import LocalFS
    from core.undo import pick_undoable, record_delete, record_skipped, undoable

    OJ = _journal(tmp_path, monkeypatch)
    OJ.finish_operation("op-trash", "trash", status="done", source=str(tmp_path / "t.txt"),
                        backend="Local", details={"trash_id": "abc"})
    record_delete(LocalFS(), [str(tmp_path / "gone.txt")], 1)
    plans = undoable(OJ.read_recent(100))
    assert plans[0].operation == "delete" and not plans[0].reversible
    assert plans[0].reason == "the items were deleted for good, not moved to the trash"
    # Not the trash under it: the delete is said, nothing else offered.
    assert pick_undoable(plans, {"Local"}) is None
    # Once said (journaled as skipped), the next Ctrl+Z reaches the trash.
    record_skipped(plans[0], plans[0].reason)
    plans = undoable(OJ.read_recent(100))
    assert pick_undoable(plans, {"Local"}).operation_id == "op-trash"


def test_happy_the_pane_journals_a_permanent_delete_and_not_a_trash(tmp_path, monkeypatch):
    from core.local_fs import LocalFS
    from ui.file_pane import _run_removal

    OJ = _journal(tmp_path, monkeypatch)
    victim = tmp_path / "victim.txt"
    victim.write_text("x")
    result = _run_removal(LocalFS(), [("victim.txt", str(victim), False)], False,
                          lambda: False, lambda *_a: None)
    assert result.done == 1 and not victim.exists()
    rows = [r for r in OJ.read_recent(100) if r.get("operation") == "delete"]
    assert len(rows) == 1 and rows[0]["source"] == str(victim)
    assert rows[0]["details"]["entries"] == 1


def test_edge_the_undo_box_after_a_delete_and_after_an_undo(german_window, tmp_path, monkeypatch):
    from core.undo import plan_undo, undoable

    OJ = _journal(tmp_path, monkeypatch)
    win = german_window
    delete = plan_undo({"operation_id": "d1", "phase": "finish", "operation": "delete",
                        "status": "done", "source": "/x", "backend": "Local"})
    with mock.patch("ui.main_window.QMessageBox.information") as info:
        win._undo_picked([delete], "done", None)
    text = info.call_args[0][2]
    assert text.startswith("Die letzte Aktion (Endgültiges Löschen) lässt sich nicht")
    assert "Widerrufen lässt sich" not in text
    # Said once: journaled as skipped, so the next Ctrl+Z goes further back.
    assert "d1" not in [p.operation_id for p in undoable(OJ.read_recent(100))
                        if p.operation == "delete"]
    undo = plan_undo({"operation_id": "u1", "phase": "finish", "operation": "undo",
                      "status": "done", "details": {"undone": "x"}})
    with mock.patch("ui.main_window.QMessageBox.information") as info:
        win._undo_picked([undo], "done", None)
    text = info.call_args[0][2]
    assert text.startswith("Nichts mehr rückgängig zu machen"), text
    assert "(Widerrufen)" not in text


# --- L4 ---------------------------------------------------------------------


def test_happy_the_time_left_reads_in_german(german):
    from models.transfer_model import TransferModel

    assert TransferModel._format_eta(7) == "7 s"
    assert TransferModel._format_eta(192) == "3 min 12 s"
    assert TransferModel._format_eta(3900) == "1 Std. 5 min"


def test_edge_the_time_left_in_english_is_unchanged():
    from models.transfer_model import TransferModel

    assert [TransferModel._format_eta(s) for s in (7, 192, 3900)] == ["7s", "3m 12s", "1h 5m"]


# --- L5 ---------------------------------------------------------------------


class _LocalNamed:
    name = "Local"


def test_happy_the_trash_window_says_lokal_and_formats_sizes(german, monkeypatch):
    from core import trash as T
    from models.trash_entry import TrashEntry
    from ui.trash_browser import TrashBrowserDialog

    monkeypatch.setattr(T, "list_trash", lambda _backend: [])
    dialog = TrashBrowserDialog(_LocalNamed())
    try:
        assert dialog.windowTitle() == "Papierkorb – Lokal"
        headers = [dialog._table.horizontalHeaderItem(i).text()
                   for i in range(dialog._table.columnCount())]
        assert "ID" not in headers and headers[-1] == "Typ"
        dialog._fill([TrashEntry(trash_id="1234abcd", original_path="/home/u/a.txt", size=4096),
                      TrashEntry(trash_id="ffff0000", original_path="/home/u/d", is_dir=True)])
        assert dialog._table.item(0, 1).text() == "4,0 KB"
        assert dialog._table.item(0, 3).text() == "Datei"
        assert dialog._table.item(1, 3).text() == "Ordner"
        assert "1234abcd" in dialog._table.item(0, 0).toolTip()
    finally:
        dialog.deleteLater()


def test_sad_properties_show_the_translated_backend(german):
    from models.file_item import FileItem
    from ui.properties_dialog import PropertiesDialog

    with mock.patch("ui.properties_dialog.PropertiesDialog._start_size_walk",
                    create=True):
        dialog = PropertiesDialog(_LocalNamed(), "/x", FileItem(name="x", size=3))
    try:
        assert dialog._compute_field("Backend") == "Lokal"
    finally:
        dialog.deleteLater()


# --- L6 ---------------------------------------------------------------------


def _key(widget, key, mods=Qt.KeyboardModifier.NoModifier) -> None:
    from PyQt6.QtTest import QTest

    QTest.keyClick(widget, key, mods)
    pump(0.05)


def test_happy_esc_in_the_path_bar_goes_back_to_the_list(window, tmp_path):
    pane = window._active_pane
    pane.navigate(str(tmp_path))
    pump(0.2)
    window.activateWindow()
    pane._path_edit.setFocus()
    pane._path_edit.setText("/typed/half")
    _key(pane._path_edit, Qt.Key.Key_Escape)
    assert pane._path_edit.text() == pane.current_path
    assert pane._table.hasFocus() or APP.focusWidget() is pane._table


def test_edge_ctrl_l_and_ctrl_f_move_between_filter_and_path(window):
    pane = window._active_pane
    window.activateWindow()
    pane._filter_edit.setFocus()
    _key(pane._filter_edit, Qt.Key.Key_L, Qt.KeyboardModifier.ControlModifier)
    assert APP.focusWidget() is pane._path_edit
    _key(pane._path_edit, Qt.Key.Key_F, Qt.KeyboardModifier.ControlModifier)
    assert APP.focusWidget() is pane._filter_edit


# --- L7 ---------------------------------------------------------------------


def test_edge_the_german_handbook_has_no_mixed_terms_left():
    text = (ROOT / "docs/USAGE_de.md").read_text(encoding="utf-8")
    for phrase in ("Host / Username / Auth", "Klartext-Credentials", "Window-Geometry",
                   "Splitter-Baum", "Werkzeugleiste", "eine Toolbar", "Not connected —"):
        assert phrase not in text, phrase
    assert "Benutzername" in text and "Zugangsdaten" in text


def test_happy_one_word_family_for_the_toolbars_in_german():
    values = [v for v in GERMAN.values() if isinstance(v, str)]
    assert not [v for v in values if "Werkzeugleiste" in v]
    assert GERMAN["Reset Toolbar Order"] == "Reihenfolge der Symbolleisten zurücksetzen"
    assert GERMAN["Toolbar"] == "Symbolleiste"
    assert (GERMAN["Main Toolbar"], GERMAN["Tools Toolbar"]) == ("Hauptleiste", "Tools-Leiste")


# --- L8 ---------------------------------------------------------------------


def test_edge_the_idle_transfers_panel_is_one_row_high(window):
    dock = window._transfer_dock
    assert dock.idle
    window._fit_transfer_area()
    pump(0.2)
    row = dock._container.minimumSizeHint().height()
    title = dock.titleBarWidget().height() if dock.titleBarWidget() else 0
    # Was 86 px: the scroll area's own 58 px least height around the row.
    assert dock.widget().minimumHeight() == row
    assert dock.minimumSizeHint().height() <= title + row + 2
    for other in window.tabifiedDockWidgets(dock):
        if other.widget().minimumHeight():
            assert other.widget().minimumHeight() == row
    # A job gives the panel - and its neighbours - their own least height back.
    dock._set_idle(False)
    window._fit_transfer_area()
    assert dock.widget().minimumHeight() == 0
    assert all(o.widget().minimumHeight() == 0 for o in window.tabifiedDockWidgets(dock))
    dock._set_idle(True)


# --- known open items -------------------------------------------------------


def test_happy_german_names_for_the_duplicate_finder_and_disk_usage():
    assert GERMAN["&Duplicate Finder…"] == "&Duplikatsuche…"
    assert GERMAN["Dup&licate Finder…"] == "Dup&likatsuche…"
    assert GERMAN["Dis&k Usage…"] == "Speicherbelegun&g…"
    assert GERMAN["Disk Usage"] == "Speicherbelegung"
    values = [v for v in GERMAN.values() if isinstance(v, str)]
    assert not [v for v in values if "Duplicate Finder" in v or "Disk Usage" in v]
    handbook = (ROOT / "docs/USAGE_de.md").read_text(encoding="utf-8")
    assert "Duplicate Finder" not in handbook and "Disk Usage" not in handbook


def test_edge_the_german_view_menu_letters_do_not_clash(german_window):
    from ui.mnemonics import mnemonic_of

    view = next(a.menu() for a in german_window.menuBar().actions()
                if a.text() == "&Ansicht")
    view.aboutToShow.emit()
    letters = [mnemonic_of(a.text()) for a in view.actions()
               if not a.isSeparator() and a.isVisible() and a.text()]
    clashes = {x for x in letters if x and letters.count(x) > 1}
    assert not clashes, clashes


def test_sad_the_german_scripting_guide_uses_the_german_keys_and_buttons():
    text = (ROOT / "docs/SCRIPTING_de.md").read_text(encoding="utf-8")
    assert "Ctrl+Return" not in text and "**Run in Console**" not in text
    assert "| **Ausführen** (Strg+Eingabe) |" in text
    assert GERMAN["Run"] == "Ausführen" and GERMAN["Run in Console"] in text


def test_edge_the_memory_legend_formats_its_percent_per_language():
    source = (ROOT / "ui/system_info_window.py").read_text(encoding="utf-8")
    assert not re.search(r":\.0f\} %\)", source)
    assert "format_percent(100 * value / total)" in source
