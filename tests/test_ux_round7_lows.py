"""UX review round 7, the low findings L1-L8 (English and German).

L1 a declined host key is worded as declined; one German term "Host-Key".
L2 "not supported", "timed out", the sandbox names and the Matrix/XMPP
   hints in German.
L3 one name for the bookmark action, "folder" not "directory", Title Case,
   one separator convention ("→" for menu paths, "–" for dashes).
L5 Settings: room beside the list, the matching setting marked, an empty
   page for a search without a hit, the hidden-files check box in the
   form's column.
L7 an empty Bookmarks sidebar folds away on a small screen.
L8 every entry of the menu bar's submenus has a mnemonic, unique per menu;
   Ctrl+Shift+G has one owner and one name.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])
GERMAN = json.loads((ROOT / "resources/i18n/de.json").read_text(encoding="utf-8"))


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture
def german():
    from core import i18n

    i18n.install("de")
    yield
    i18n.install("en")


@pytest.fixture
def window():
    from ui.main_window import MainWindow

    win = MainWindow()
    win._reconnect_timer.stop()
    win.resize(1280, 800)
    win.show()
    pump(0.2)
    yield win
    win._quit_with_transfers = True
    win.close()
    win.deleteLater()
    pump()


# --- L1 --------------------------------------------------------------------


def _unknown_host_error():
    from core.ssh_client import UnknownHostKeyError

    return UnknownHostKeyError("[srv]:22", "ssh-ed25519", "abc")


def test_happy_a_declined_host_key_says_so():
    from core.user_errors import describe

    error = _unknown_host_error()
    error.declined = True
    text = describe(error)
    assert "You did not trust the host key" in text
    assert "Use Connect" not in text


def test_sad_an_unasked_host_key_still_points_to_connect():
    from core.user_errors import describe

    assert "Use Connect to review its fingerprint" in describe(_unknown_host_error())


def test_happy_saying_no_in_the_window_marks_the_error_declined(window, monkeypatch):
    from PyQt6.QtWidgets import QMessageBox

    monkeypatch.setattr(QMessageBox, "question",
                        staticmethod(lambda *a, **k: QMessageBox.StandardButton.No))
    error = _unknown_host_error()
    assert window._confirm_unknown_host(error) is False
    assert error.declined is True


def test_edge_german_says_host_key_one_way(german):
    from core.user_errors import describe

    error = _unknown_host_error()
    error.declined = True
    assert "Host-Key" in describe(error)
    assert not [v for v in GERMAN.values() if "Host-Schlüssel" in v]


# --- L2 --------------------------------------------------------------------


def test_happy_not_supported_and_timed_out_are_german(german):
    from core import file_type as FT
    from ui.disk_usage_dialog import capacity_cells
    from ui.file_type_dialog import _described

    class Row:
        label, protocol = "imap", "IMAP"
        capacity_total = capacity_used = capacity_free = 0

    assert capacity_cells(Row())["Usage"] == "nicht unterstützt"
    info = FT.FileTypeInfo(path="/x", name="x", kind=FT.KIND_TIMEOUT, description="timed out")
    assert _described(info) == "Zeitüberschreitung"


def test_happy_the_shipped_sandbox_names_are_german_and_ids_stay(german):
    from core.agent_sandbox import default_profiles
    from ui.format_utils import sandbox_label

    names = [p.name for p in default_profiles()]
    assert names == ["Lax", "Normal", "High", "Paranoid"]  # the ids
    assert [sandbox_label(n) for n in names] == ["Locker", "Normal", "Hoch", "Paranoid"]
    assert sandbox_label("my-own") == "my-own"


def test_sad_the_chat_feature_hints_are_german_through():
    for key, value in GERMAN.items():
        if "(Matrix and XMPP chat)" in key:
            assert "Matrix and XMPP chat" not in value, value


# --- L3 --------------------------------------------------------------------


def test_happy_one_name_for_the_bookmark_action(window):
    from ui.file_pane import CONTEXT_COMMANDS

    labels = [a.text().replace("&", "") for a in window._bookmarks_menu.actions()]
    assert "Bookmark This Folder" in labels
    assert CONTEXT_COMMANDS["bookmark"][1] == "F8"  # the key the window menu shows
    source = (ROOT / "ui/file_pane.py").read_text(encoding="utf-8")
    assert 'tr("&Bookmark This Folder")' in source
    for gone in ("Bookmark This Directory", "Add Current Directory"):
        assert gone not in source and gone not in GERMAN


def test_happy_calculate_size_counts_folders_in_words():
    from core.i18n import tr_n

    assert tr_n(1, "Calculate Si&ze ({n} folder)", "Calculate Si&ze ({n} folders)") == \
        "Calculate Si&ze (1 folder)"
    assert "Calculate Si&ze ({count} dirs)" not in GERMAN


_OLD_MENU_PATH = re.compile(r"(?<=[A-Za-z…\)]) > (?=[A-Z]|…)")
_OLD_DASH = re.compile(r"(?<=\S) [-—] (?=\S)")
#: Keys used in files other review agents were editing at the time; their
#: strings follow with those files.
_LATER = {
    "/command - /help lists them",
    "Showing {shown} of {total} messages - search to narrow them down.",
    "Warning: the name mixes letters of several scripts ({scripts}) - a typical look-alike.",
    "stored - leave empty to keep",
}


def test_sad_no_catalogue_key_keeps_the_old_separators():
    old = [k for k in GERMAN
           if (_OLD_MENU_PATH.search(k) or _OLD_DASH.search(k))
           and k not in _LATER and not k.startswith("only in the local cache")]
    assert old == [], old[:10]


def test_edge_english_words_folder_and_title_case():
    keys = set(GERMAN)
    assert "Encrypt with Passphrase…" in keys and "Encrypt with passphrase…" not in keys
    for gone in ("Home directory", "Parent directory", "Directory Size"):
        assert gone not in keys
    assert {"Home folder", "Parent folder", "Folder Size"} <= keys


# --- L5 --------------------------------------------------------------------


def test_happy_the_settings_search_marks_the_matching_setting(window):
    from ui.settings_dialog import SettingsDialog

    dialog = SettingsDialog(window, window=window)
    try:
        dialog.show()
        dialog.filter_edit.setText("hidden")
        pump(0.2)
        assert any("hidden" in t.lower() for t in dialog.marked_texts())
        right = dialog.title_label.parentWidget().layout()
        assert right.contentsMargins().left() > 0  # room beside the list
    finally:
        dialog.deleteLater()


def test_sad_a_search_without_a_hit_shows_an_empty_page_not_the_old_one(window):
    from ui.settings_dialog import SettingsDialog

    dialog = SettingsDialog(window, window=window)
    try:
        dialog.show()
        dialog.filter_edit.setText("zzzqqq")
        pump(0.1)
        assert dialog.stack.currentWidget() is dialog.empty_page
        assert "zzzqqq" in dialog.empty_page.text()
        assert dialog.marked_texts() == []
        dialog.filter_edit.clear()
        pump(0.1)
        assert dialog.stack.currentWidget() is not dialog.empty_page
    finally:
        dialog.deleteLater()


def test_edge_the_hidden_files_box_sits_in_the_page_form(window):
    from PyQt6.QtWidgets import QFormLayout

    from ui.settings_dialog import AppearancePage

    page = AppearancePage(window)
    try:
        form = page.layout_.itemAt(0).layout()
        assert isinstance(form, QFormLayout)
        fields = [form.itemAt(r, QFormLayout.ItemRole.FieldRole) for r in range(form.rowCount())]
        assert any(f is not None and f.widget() is page.highlight_check for f in fields)
    finally:
        page.deleteLater()


# --- L7 --------------------------------------------------------------------


def test_happy_an_empty_sidebar_folds_away_on_a_small_screen(window, monkeypatch):
    sidebar = window._bookmark_sidebar
    sidebar.show()
    monkeypatch.setattr(window._bookmark_manager, "tree", lambda: [])
    monkeypatch.setattr(window, "_small_screen", lambda: True)
    window._first_start_docks_pending = True
    window._size_first_start_docks()
    pump()
    assert not sidebar.isVisible()
    assert "F12" in window.statusBar().currentMessage()
    # the first bookmark brings it back
    monkeypatch.setattr(window._bookmark_manager, "tree", lambda: ["one"])
    monkeypatch.setattr(window, "_populate_bookmarks_menu", lambda: None)
    monkeypatch.setattr(sidebar, "rebuild", lambda: None)
    window._rebuild_bookmarks_menu()
    pump()
    assert sidebar.isVisible()


def test_sad_a_large_screen_or_bookmarks_keep_the_sidebar(window, monkeypatch):
    sidebar = window._bookmark_sidebar
    sidebar.show()
    monkeypatch.setattr(window, "_small_screen", lambda: False)
    window._first_start_docks_pending = True
    window._size_first_start_docks()
    pump()
    assert sidebar.isVisible()


def test_edge_hidden_by_the_user_stays_hidden_after_a_bookmark(window, monkeypatch):
    sidebar = window._bookmark_sidebar
    sidebar.show()
    monkeypatch.setattr(window._bookmark_manager, "tree", lambda: [])
    monkeypatch.setattr(window, "_small_screen", lambda: True)
    window._first_start_docks_pending = True
    window._size_first_start_docks()
    sidebar.toggleViewAction().trigger()  # the user: shown
    sidebar.toggleViewAction().trigger()  # the user: hidden again
    monkeypatch.setattr(window._bookmark_manager, "tree", lambda: ["one"])
    monkeypatch.setattr(window, "_populate_bookmarks_menu", lambda: None)
    monkeypatch.setattr(sidebar, "rebuild", lambda: None)
    window._rebuild_bookmarks_menu()
    pump()
    assert not sidebar.isVisible()


# --- L8 --------------------------------------------------------------------


def test_happy_with_mnemonic_takes_a_free_word_start():
    from ui.mnemonics import mnemonic_of, with_mnemonic

    assert with_mnemonic("Show Trash…", {"s"}) == "Show &Trash…"
    assert with_mnemonic("Duplicate Index && History…", set()) == "&Duplicate Index && History…"
    assert mnemonic_of("Duplicate Index && History…") is None
    assert with_mnemonic("abc", {"a", "b", "c"}) == "abc"


def _menu_entries(menu, path, out):
    from ui.mnemonics import mnemonic_of

    menu.aboutToShow.emit()
    pump(0.02)
    actions = [a for a in menu.actions() if not a.isSeparator() and a.text() and a.isVisible()]
    out.append((path, [(a.text(), mnemonic_of(a.text())) for a in actions]))
    for action in actions:
        if action.menu() is not None:
            _menu_entries(action.menu(), path + [action.text()], out)


@pytest.mark.parametrize("language", ["en", "de"])
def test_happy_every_submenu_entry_has_a_unique_mnemonic(language):
    from core import i18n
    from ui.main_window import MainWindow

    i18n.install(language)
    win = MainWindow()
    try:
        win._reconnect_timer.stop()
        menus = []
        for top in win.menuBar().actions():
            if top.menu() is not None:
                _menu_entries(top.menu(), [top.text()], menus)
        missing, clashes = [], []
        for path, entries in menus:
            letters = [m for _t, m in entries if m]
            if len(letters) != len(set(letters)):
                clashes.append((path, entries))
            # every entry has one, unless the menu's letters ran out
            for text, letter in entries:
                plain = set(text.replace("&", "").lower())
                if letter is None and plain - set(letters) - set(" ….()-–→,'0123456789"):
                    missing.append((path, text))
        assert clashes == []
        assert missing == []
    finally:
        i18n.install("en")
        win._quit_with_transfers = True
        win.close()
        win.deleteLater()
        pump()


def test_edge_ctrl_shift_g_has_one_name(window):
    from PyQt6.QtGui import QAction, QKeySequence

    owners = {a.text().replace("&", "") for a in window.findChildren(QAction)
              if QKeySequence("Ctrl+Shift+G") in a.shortcuts()}
    assert owners == {"Thumbnail View"}
    pane = window._active_pane
    names = [a.text().replace("&", "") for a in pane._build_context_menu().findChildren(QAction)
             if a.property("axCommand") == "view-mode"]
    assert names and set(names) == {"Thumbnail View"}
