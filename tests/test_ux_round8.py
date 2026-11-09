"""UX review round 8: the findings and the smaller ones.

M1 the pane's right-click menu, Quick Connect and the toolbar's right-click
   menu: every entry gets an underlined letter when the menu opens.
M2 a second connection never replaces the last local pane.
M3 "Save in keyring" is the answer: no question after connecting.
M4 a checked menu entry with an icon looks checked, in every theme.
M5 the settings search marks the matched widget, a group box its title.
Lows: "&" in names, toolbar titles, View > Show Trash… letter, wrapped
shortcut descriptions, sandbox names, a declined host key, German key and
number forms, the MCP page, the tour offer, the Connect button, the proxy
box, the German handbook's dashes.
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

from PyQt6.QtCore import QEvent, QItemSelectionModel  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMenu  # noqa: E402

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


@pytest.fixture(params=["en", "de"])
def any_language_window(request):
    from core import i18n

    i18n.install(request.param)
    try:
        win = _open_window()
        yield win
        _close_window(win)
    finally:
        i18n.install("en")


def _shown(menu: QMenu) -> None:
    """What opening *menu* and each of its submenus does."""
    menu.aboutToShow.emit()
    for action in menu.actions():
        if action.menu() is not None and action.isVisible():
            _shown(action.menu())


def _letters(menu: QMenu, path: str = "") -> tuple[list, list]:
    from ui.mnemonics import mnemonic_of

    missing, clashes = [], []
    seen: dict[str, str] = {}
    for action in menu.actions():
        if action.isSeparator() or not action.isVisible() or not action.text():
            continue
        letter = mnemonic_of(action.text())
        if letter is None:
            missing.append((path, action.text()))
        elif letter in seen:
            clashes.append((path, action.text(), seen[letter]))
        else:
            seen[letter] = action.text()
        if action.menu() is not None:
            more_missing, more_clashes = _letters(action.menu(), path + ">" + action.text())
            missing += more_missing
            clashes += more_clashes
    return missing, clashes


def _select(pane, name: str) -> None:
    proxy = pane._table.model()
    selection = pane._table.selectionModel()
    selection.clearSelection()
    for row in range(proxy.rowCount()):
        if proxy.index(row, 0).data() == name:
            selection.select(proxy.index(row, 0),
                             QItemSelectionModel.SelectionFlag.Select
                             | QItemSelectionModel.SelectionFlag.Rows)


# --- M1 -------------------------------------------------------------------


def test_happy_every_pane_menu_entry_gets_a_unique_letter_when_shown(any_language_window,
                                                                     tmp_path):
    (tmp_path / "notes.txt").write_text("x")
    pane = any_language_window._active_pane
    pane.navigate(str(tmp_path))
    pump(0.2)
    for name in ("notes.txt", None):
        if name is None:
            pane._table.clearSelection()
        else:
            _select(pane, name)
        menu = pane._build_context_menu()
        _shown(menu)
        missing, clashes = _letters(menu)
        assert missing == [] and clashes == [], (name, missing, clashes)
        menu.deleteLater()


def test_happy_quick_connect_and_toolbar_menus_get_letters(any_language_window):
    from core.profiles import ConnectionProfile

    win = any_language_window
    for name in ("alpha", "beta", "Web & Mail"):
        win._profile_manager.add(
            ConnectionProfile(name=name, protocol="sftp", host="h.invalid", username="u"))
    menu = win._build_quick_connect_menu()
    _shown(menu)
    assert _letters(menu) == ([], [])
    profile_menu = menu.build_profile_menu(win._profile_manager.get("alpha"))
    _shown(profile_menu)
    assert _letters(profile_menu) == ([], [])
    popup = win.createPopupMenu()
    _shown(popup)
    assert _letters(popup) == ([], [])


def test_edge_a_name_with_an_ampersand_is_shown_as_it_is(window):
    from core.profiles import ConnectionProfile
    from ui.mnemonics import mnemonic_of

    window._profile_manager.add(
        ConnectionProfile(name="Web & Mail", protocol="sftp", host="h.invalid", username="u"))
    menu = window._build_quick_connect_menu()
    _shown(menu)
    entry = next(a for a in menu.actions() if "Mail" in a.text())
    assert "Web && Mail" in entry.text()  # Qt shows "&&" as "&"
    assert "Web _Mail" not in entry.text() and mnemonic_of(entry.text()) is not None


def test_sad_a_menu_built_but_not_shown_keeps_its_labels(window, tmp_path):
    """Letters are given when the menu opens: a menu that is only built
    keeps the labels it was given (a caller can look an entry up by them)."""
    (tmp_path / "a.txt").write_text("x")
    pane = window._active_pane
    pane.navigate(str(tmp_path))
    pump(0.2)
    _select(pane, "a.txt")
    menu = pane._build_context_menu()
    before, _clashes = _letters(menu)
    assert any(text == "Pack as ZIP" for _path, text in before)  # no letter before it opens
    _shown(menu)
    assert _letters(menu) == ([], [])


def test_edge_view_menu_show_trash_has_a_letter(window):
    from ui.mnemonics import mnemonic_of

    assert mnemonic_of(window._trash_action.text()) == "t"
    view = next(a.menu() for a in window.menuBar().actions() if a.text() == "&View")
    _shown(view)
    missing, clashes = _letters(view)
    assert ("", window._trash_action.text()) not in missing
    assert not [c for c in clashes if c[0] == ""]


# --- M2 -------------------------------------------------------------------


def _connect(win, monkeypatch, name):
    from core.local_fs import LocalFS
    from core.profiles import ConnectionProfile

    remote = type("RemoteFS", (LocalFS,), {})()
    monkeypatch.setattr(win, "_run_connect_async",
                        lambda profile, pw, kp, ok, fail: ok(remote))
    win._quick_connect_profile(
        ConnectionProfile(name=name, protocol="sftp", host="h", username="u"))
    pump(0.1)
    return remote


@pytest.fixture
def first_start(window, monkeypatch):
    from core import credentials
    from core.local_fs import LocalFS

    home = LocalFS().home()
    for pane in window._panes:
        pane.navigate(home)
        pane._history = [pane.current_path]
        pane._history_pos = 0
    window._set_active_pane(window._panes[0])
    pump(0.2)
    monkeypatch.setattr(credentials, "get_password", lambda name: "pw")
    return window


def test_happy_a_second_connection_keeps_the_last_local_pane(first_start, monkeypatch):
    from ui.main_window import LocalFS

    win = first_start
    first = _connect(win, monkeypatch, "one")
    assert len(win._panes) == 2  # the untouched target was taken
    second = _connect(win, monkeypatch, "two")
    local = [p for p in win._panes
             if isinstance(p.backend, LocalFS) and p not in win._pane_profiles]
    servers = [p for p in win._panes if p.backend in (first, second)]
    assert len(local) == 1 and len(servers) == 2
    assert len(win._panes) == 3


def test_sad_the_last_local_pane_is_no_spare(first_start, monkeypatch):
    win = first_start
    _connect(win, monkeypatch, "one")
    assert win._untouched_target_pane() is None


def test_edge_with_two_local_panes_left_the_target_is_still_taken(first_start, monkeypatch):
    from core.local_fs import LocalFS

    win = first_start
    win._add_pane_to_splitter(win._root_splitter, LocalFS())
    pump(0.1)
    target = win._target_pane
    assert win._untouched_target_pane() is target


# --- M3 -------------------------------------------------------------------


class _Dialog:
    """The Connection Manager, answered: OK with *profile* and a password."""

    profile = None

    class DialogCode:
        Accepted = 1

    def __init__(self, *_a, **_k):
        self.result_profile = _Dialog.profile
        self.result_password = "secret"
        self.result_key_passphrase = ""
        self.result_new_pane = False

    def exec(self):
        return 1

    def deleteLater(self):
        pass


@pytest.fixture
def connect_dialog(window, monkeypatch):
    from core.local_fs import LocalFS
    from ui import connection_dialog

    monkeypatch.setattr(connection_dialog, "ConnectionDialog", _Dialog)
    remote = type("RemoteFS", (LocalFS,), {})()
    monkeypatch.setattr(window, "_run_connect_async",
                        lambda profile, pw, kp, ok, fail: ok(remote))
    boxes: list[tuple] = []
    from PyQt6.QtWidgets import QMessageBox

    for kind in ("question", "warning", "information", "critical"):
        monkeypatch.setattr(
            QMessageBox, kind,
            staticmethod(lambda *a, kind=kind, **k: boxes.append((kind, *a[1:3]))
                         or QMessageBox.StandardButton.Yes))
    return boxes


def _profile(store: bool):
    from core.profiles import ConnectionProfile

    return ConnectionProfile(name="srv", protocol="sftp", host="h", username="u",
                             store_password=store)


def test_happy_unticked_keyring_box_asks_nothing(window, connect_dialog):
    _Dialog.profile = _profile(False)
    window._on_connect()
    pump(0.1)
    assert [b for b in connect_dialog if b[0] == "question"] == []
    assert connect_dialog == []


def test_happy_ticked_box_saves_without_a_question(window, connect_dialog, monkeypatch):
    from core import credentials

    stored: dict[str, str] = {}
    monkeypatch.setattr(credentials, "is_keyring_available", lambda: True)
    monkeypatch.setattr(credentials, "get_password", lambda name: stored.get(name))
    monkeypatch.setattr(credentials, "store_password",
                        lambda name, pw: stored.__setitem__(name, pw) or True)
    _Dialog.profile = _profile(True)
    window._on_connect()
    pump(0.1)
    assert connect_dialog == []
    assert stored == {"srv": "secret"}


def test_sad_no_keyring_is_explained_not_asked(window, connect_dialog, monkeypatch):
    from core import credentials

    monkeypatch.setattr(credentials, "is_keyring_available", lambda: False)
    monkeypatch.setattr(credentials, "keyring_status_message", lambda: "No usable keyring X")
    _Dialog.profile = _profile(True)
    window._on_connect()
    pump(0.1)
    assert [b[0] for b in connect_dialog] == ["warning"]
    assert connect_dialog[0][2] == "No usable keyring X"


def test_edge_the_keyring_hint_is_german(german):
    from core import credentials

    key = next(k for k in GERMAN if k.startswith("No usable system keyring"))
    assert "{backend}" in key and "{backend}" in GERMAN[key]
    import inspect

    assert "tr(" in inspect.getsource(credentials.keyring_status_message)


# --- M4 -------------------------------------------------------------------


@pytest.mark.parametrize("theme", ["modern-dark", "modern-light", "classic", "default",
                                   "hacker", "amber"])
def test_happy_a_checked_icon_entry_looks_different(theme):
    from PyQt6.QtGui import QColor, QIcon, QPixmap

    from ui import themes

    before = APP.styleSheet()
    APP.setStyleSheet(themes.stylesheet_for(theme, None))
    try:
        images = []
        for checked in (True, False):
            menu = QMenu()
            pixmap = QPixmap(16, 16)
            pixmap.fill(QColor("#808080"))
            action = menu.addAction(QIcon(pixmap), "Transfers")
            action.setCheckable(True)
            action.setChecked(checked)
            menu.adjustSize()
            images.append(menu.grab().toImage())
            menu.deleteLater()
        on, off = images
        assert on.size() == off.size()
        assert on != off, theme
    finally:
        APP.setStyleSheet(before)


def test_edge_the_check_frame_has_contrast_in_every_theme():
    from ui import themes

    for key, (_edge, base, fill, _mark) in themes._INDICATOR_COLOURS.items():
        css = themes._menu_check_css(key)
        assert "QMenu::icon:checked" in css and fill in css
        if base.startswith("#") and fill.startswith("#"):
            assert themes.contrast_ratio(fill, base) >= 3.0, key


# --- M5 -------------------------------------------------------------------


def test_happy_the_search_marks_a_group_box_title_only(window):
    from PyQt6.QtWidgets import QGroupBox, QLineEdit

    from ui.settings_dialog import SettingsDialog

    dialog = SettingsDialog(window, window=window)
    dialog.show()
    try:
        dialog.filter_edit.setText("proxy")
        pump(0.3)
        boxes = [w for w in dialog._marked if isinstance(w, QGroupBox)]
        assert boxes, dialog.marked_texts()
        box = boxes[0]
        field = next(e for e in box.findChildren(QLineEdit) if e.isVisible())
        marked = field.grab().toImage()
        dialog.filter_edit.setText("")
        pump(0.3)
        assert field.grab().toImage() == marked  # the field inside is not coloured
        assert "::title" in SettingsDialog._match_sheet(box, "")
    finally:
        dialog.close()
        dialog.deleteLater()


def test_edge_a_bare_own_style_keeps_working_with_the_mark():
    from PyQt6.QtWidgets import QLabel

    from ui.settings_dialog import SettingsDialog

    label = QLabel("x")
    sheet = SettingsDialog._match_sheet(label, "color: red;")
    assert sheet.startswith("* { color: red; }")
    assert '[axSearchHit="true"]' in sheet


# --- lows -----------------------------------------------------------------


def test_happy_the_toolbars_have_german_titles(german):
    win = _open_window()
    try:
        from PyQt6.QtWidgets import QToolBar

        titles = {tb.objectName(): tb.windowTitle() for tb in win.findChildren(QToolBar)}
        assert titles["axMainToolbar"] == "Hauptleiste"
        assert titles["axToolsToolbar"] == "Tools-Leiste"
    finally:
        _close_window(win)


def test_happy_german_shortcut_descriptions_wrap_and_have_tips(german):
    from ui.shortcuts_dialog import ShortcutsDialog

    dialog = ShortcutsDialog()
    dialog.show()
    pump(0.3)
    try:
        tree = dialog.tree
        width = tree.columnWidth(1)
        metrics = tree.fontMetrics()
        long_rows = 0
        for i in range(tree.topLevelItemCount()):
            section = tree.topLevelItem(i)
            for j in range(section.childCount()):
                item = section.child(j)
                assert item.toolTip(1) == item.text(1)
                if metrics.horizontalAdvance(item.text(1)) > width - 8:
                    long_rows += 1
                    rect = tree.visualItemRect(item)
                    assert rect.height() >= 2 * metrics.height(), item.text(1)
        assert long_rows >= 1
    finally:
        dialog.close()
        dialog.deleteLater()


def test_happy_a_shipped_sandbox_shows_its_german_name_once(german):
    from ui.agent_settings_dialog import _sandbox_entry

    assert _sandbox_entry("Lax", "lax") == "Locker"
    assert _sandbox_entry("High", "high") == "Hoch"
    assert _sandbox_entry("mine", "high") == "mine  (Hoch)"


def test_sad_an_edit_keeps_the_shipped_sandbox_translated(german, tmp_path):
    from tests.test_agent_settings_dialog import _dialog

    dialog = _dialog(tmp_path / "agent.json")
    try:
        row = next(i for i, p in enumerate(dialog.settings.sandboxes) if p.name == "Lax")
        dialog.sandbox_list.setCurrentRow(row)
        pump()
        assert dialog.name_edit.text() == "Locker"
        dialog.image_edit.setText("img")  # an edit stores the profile
        pump()
        assert dialog.sandbox_list.item(row).text() == "Locker"
        assert dialog.settings.sandboxes[row].name == "Lax"  # the id stays
    finally:
        dialog.close()
        dialog.deleteLater()


def test_happy_a_declined_host_key_is_a_note_not_a_failure(window, monkeypatch):
    from PyQt6.QtWidgets import QMessageBox

    from core.ssh_client import UnknownHostKeyError

    shown: list[tuple] = []
    for kind in ("information", "critical"):
        monkeypatch.setattr(QMessageBox, kind, staticmethod(
            lambda *a, kind=kind, **k: shown.append((kind, a[1], a[2]))))
    error = UnknownHostKeyError("example.org", "ssh-ed25519", "SHA256:abc")
    error.declined = True
    window._report_connect_failure(error)
    assert shown[0][0] == "information" and shown[0][1] == "Not Connected"
    assert "check the fingerprint" in shown[0][2] and "compare" not in shown[0][2]
    shown.clear()
    window._report_connect_failure(OSError("boom"))
    assert shown[0][0] == "critical"


def test_happy_german_says_eingabe_for_the_enter_key():
    for key, value in GERMAN.items():
        if "Carriage" in value:
            continue
        assert not re.search(r"\b(Enter|Return)\b", value), (key, value)
    text = (ROOT / "docs/USAGE_de.md").read_text(encoding="utf-8")
    assert not re.search(r"(?<!Carriage )\b(Enter|Return)\b", text)


def test_happy_german_percentages_have_a_narrow_space(german):
    from core.i18n import format_percent, percent_sign

    assert format_percent(87) == "87 %"
    assert format_percent(2.94, 1) == "2,9 %"
    assert percent_sign() == " %"
    for key, value in GERMAN.items():
        assert not re.search(r"(\d|\})[  ]?%(?![hp])", value.replace(" %", "")), value


def test_edge_english_percentages_stay_unspaced():
    from core.i18n import format_percent

    assert format_percent(87) == "87%"
    assert format_percent(2.94, 1) == "2.9%"


def test_happy_the_mcp_timeout_shows_a_german_decimal(german, tmp_path):
    from tests.test_agent_settings_dialog import _dialog

    dialog = _dialog(tmp_path / "agent.json")
    try:
        dialog.server_timeout_spin.setValue(1.0)
        assert dialog.server_timeout_spin.text() == "1,00 s"
        assert dialog.server_empty_label.isHidden() == bool(dialog.settings.mcp_servers)
    finally:
        dialog.close()
        dialog.deleteLater()


def test_happy_the_tour_offer_buttons_keep_their_width(window, tmp_path, monkeypatch):
    from PyQt6.QtWidgets import QPushButton, QWidget

    from core import open_limits as OL

    monkeypatch.setattr(OL, "SETTINGS_PATH", tmp_path / "settings.json")
    assert window.offer_getting_started_tour() is True
    pump(0.2)
    notice = window.findChild(QWidget, "axTourOffer")
    for name in ("axTourOfferTake", "axTourOfferDismiss"):
        button = notice.findChild(QPushButton, name)
        assert button.width() <= button.sizeHint().width() + 4, (name, button.width())
    window._dismiss_tour_offer()


def test_happy_the_connection_manager_says_connect_and_folds_the_proxy(window):
    from PyQt6.QtWidgets import QDialogButtonBox

    from ui.connection_dialog import ConnectionDialog

    dialog = ConnectionDialog(window._profile_manager, parent=window)
    try:
        box = dialog.findChild(QDialogButtonBox)
        assert box.button(QDialogButtonBox.StandardButton.Ok).text() == "Connect"
        dialog._proxy_group.setChecked(False)
        assert dialog._proxy_group.isFlat()
        dialog._proxy_group.setChecked(True)
        assert not dialog._proxy_group.isFlat()
    finally:
        dialog.deleteLater()


def test_edge_the_german_handbook_uses_one_dash_in_prose():
    text = (ROOT / "docs/USAGE_de.md").read_text(encoding="utf-8")
    fence = False
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("```"):
            fence = not fence
            continue
        if fence:
            continue
        prose = re.sub(r"``.*?``|`[^`]*`", "x", line)
        assert not re.search(r"\S (-|—) \S", prose), (number, line)
