"""Edit > Settings… (Ctrl+,): one dialog with every setting by category.

Operator: *„das settings menu ebenfalls komplett ueberarbeiten, sauber
sortiert in kategorien, prüfen ob alle settings wirklich funktionieren"*.
This file holds the dialog itself - categories, navigation, the old menu
entries that lead into it, the filter, and the OK / Apply / Cancel rule.
Whether each setting really works is tests/test_settings_matrix.py.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QPoint, Qt  # noqa: E402
from PyQt6.QtGui import QAction, QKeySequence  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QDialogButtonBox, QLabel, QWidget  # noqa: E402

from tests.settings_testkit import app, isolate  # noqa: E402

APP = app()

CATEGORIES = [
    "General", "Appearance", "Toolbar", "Files & Panes", "Network & Proxy", "LLM Profiles",
    "Analysis (sift)", "Agent", "Voice", "Audio", "Metadata", "Search", "Security",
    "Extensions", "Updates",
]


@pytest.fixture
def stores(tmp_path, monkeypatch):
    s = isolate(tmp_path, monkeypatch)
    yield s
    s.restore()


@pytest.fixture
def win(stores):
    return stores.make_window()


def _menu(win, title: str):
    return next(a.menu() for a in win.menuBar().actions() if a.text() == title)


def _entry(menu, label: str) -> QAction:
    def plain(text: str) -> str:  # "&&" is a literal "&", a single "&" the mnemonic
        return text.replace("&&", "\0").replace("&", "").replace("\0", "&")

    return next(a for a in menu.actions() if plain(a.text()) == label)


def _top_titles(dialog) -> list[str]:
    tree = dialog.tree
    return [tree.topLevelItem(i).text(0) for i in range(tree.topLevelItemCount())]


def _button(dialog, which):
    return dialog.buttons.button(which)


def _opened_by(win, trigger) -> list[str]:
    """The page the Settings dialog opens on when *trigger* runs."""
    from ui.settings_dialog import SettingsDialog

    pages = []

    def fake_exec(dialog) -> int:
        pages.append(dialog.current_page_id())
        return 0

    with mock.patch.object(SettingsDialog, "exec", fake_exec):
        trigger()
    return pages


# --- happy -----------------------------------------------------------------


def test_happy_edit_menu_has_settings_with_ctrl_comma(win) -> None:
    action = _entry(_menu(win, "&Edit"), "Settings…")
    assert action.shortcut() == QKeySequence("Ctrl+,")
    assert action.menuRole() == QAction.MenuRole.PreferencesRole
    assert _opened_by(win, action.trigger) == ["general"]


def test_happy_the_categories_are_sorted_and_agent_has_its_pages(stores, win) -> None:
    dialog = stores.settings_dialog(win)
    assert _top_titles(dialog) == CATEGORIES
    agent = dialog.tree.topLevelItem(CATEGORIES.index("Agent"))
    assert [agent.child(i).text(0) for i in range(agent.childCount())] == [
        "General", "Profiles", "Prompts", "Access", "Sandboxes", "MCP Servers",
        "MCP Sources", "Sessions"]
    assert dialog.current_page_id() == "general"


@pytest.mark.parametrize(
    "opener, page",
    [
        (lambda w: _entry(_menu(w, "&Tools"), "Network & Proxy…").trigger(), "network"),
        (lambda w: _entry(_menu(w, "&Tools"), "LLM Profiles…").trigger(), "llm"),
        (lambda w: _entry(_menu(w, "&Tools"), "Agent Settings…").trigger(), "agent"),
        (lambda w: _entry(_menu(w, "&Tools"), "Metadata Settings…").trigger(), "metadata"),
        (lambda w: _entry(w.extensions_menu, "Manage Extensions…").trigger(), "extensions"),
        (lambda w: w._analysis_dock.settings_button.click(), "llm"),
        (lambda w: w._manage_ext_action.trigger(), "extensions"),
    ],
)
def test_happy_old_entries_open_the_settings_on_their_page(win, opener, page) -> None:
    assert _opened_by(win, lambda: opener(win)) == [page]


def test_happy_ok_saves_the_changed_pages_and_closes(stores, win) -> None:
    from core import open_limits as OL

    dialog = stores.settings_dialog(win)
    dialog.page("appearance").compact_check.setChecked(True)
    dialog.page("files").open_limit_spin.setValue(77)
    _button(dialog, QDialogButtonBox.StandardButton.Ok).click()
    assert dialog.result() == dialog.DialogCode.Accepted
    assert win._compact_mode is True
    assert json.loads(stores.session.read_text())["window"]["compact"] is True
    assert OL.max_open_mb() == 77


def test_happy_apply_saves_and_stays_open(stores, win) -> None:
    dialog = stores.settings_dialog(win)
    dialog.show()
    dialog.page("search").parallel_spin.setValue(9)
    _button(dialog, QDialogButtonBox.StandardButton.Apply).click()
    assert dialog.isVisible()
    from core import remote_sweep as RW

    assert RW.parallel_hosts() == 9
    assert dialog.dirty_page_ids() == []  # what was applied is the new baseline


def test_happy_the_title_follows_the_category(stores, win) -> None:
    dialog = stores.settings_dialog(win)
    for title in CATEGORIES:
        item = dialog.tree.findItems(title, Qt.MatchFlag.MatchExactly)[0]
        dialog.tree.setCurrentItem(item)
        assert dialog.title_label.text() == title
        scroll = dialog.stack.currentWidget()
        assert scroll.widget() is dialog.page(dialog.current_page_id())


def test_happy_language_shows_the_stored_choice_not_the_running_one(stores, win) -> None:
    # Before: View > Language checked the running language and never
    # "Automatic" - with Deutsch stored for the next start it said English.
    from core import i18n

    assert stores.settings_dialog(win).page("general").language_combo.currentData() == ""
    i18n.store_language("de")
    combo = stores.settings_dialog(win).page("general").language_combo
    assert combo.currentData() == "de" and combo.currentText() == "Deutsch"


# --- sad -------------------------------------------------------------------


def test_sad_cancel_discards_every_page(stores, win) -> None:
    before = stores.files()
    dialog = stores.settings_dialog(win)
    dialog.page("appearance").monochrome_check.setChecked(True)
    dialog.page("security").paranoid_check.setChecked(True)
    dialog.page("search").parallel_spin.setValue(12)
    _button(dialog, QDialogButtonBox.StandardButton.Cancel).click()
    from core import security_mode as SM
    from ui.icon_provider import is_monochrome

    assert stores.files() == before
    assert not is_monochrome() and not SM.is_paranoid()


def test_sad_the_close_corner_discards_too(stores, win) -> None:
    from PyQt6.QtWidgets import QToolButton

    before = stores.files()
    dialog = stores.settings_dialog(win)
    dialog.page("search").parallel_spin.setValue(12)
    dialog.findChild(QToolButton, "axCloseCorner").click()
    assert stores.files() == before


def test_sad_a_page_with_a_problem_stops_every_save(stores, win) -> None:
    from core import remote_sweep as RW

    dialog = stores.settings_dialog(win)
    dialog.page("search").parallel_spin.setValue(9)  # a valid change elsewhere
    proxy = dialog.page("network")
    proxy._type.setCurrentIndex(1)  # SOCKS5 without a host
    _button(dialog, QDialogButtonBox.StandardButton.Ok).click()
    assert dialog.result() != dialog.DialogCode.Accepted
    assert dialog.current_page_id() == "network"
    assert "Network & Proxy" in dialog.error_text() and "host" in dialog.error_text()
    assert RW.parallel_hosts() == RW.DEFAULT_PARALLEL  # nothing at all was saved
    assert not stores.proxy.exists()
    proxy._host.setText("socks.example")
    _button(dialog, QDialogButtonBox.StandardButton.Ok).click()
    assert dialog.result() == dialog.DialogCode.Accepted
    assert RW.parallel_hosts() == 9 and stores.proxy.exists()


def test_sad_an_llm_profile_without_a_name_is_named_on_its_page(stores, win) -> None:
    dialog = stores.settings_dialog(win, "general")
    llm = dialog.page("llm")
    llm.add_profile()  # a new profile with no name
    assert not dialog.apply()
    assert dialog.current_page_id() == "llm"
    assert "LLM Profiles" in dialog.error_text()
    assert not stores.llm.exists()


def test_sad_a_save_that_fails_keeps_the_dialog_open_on_that_page(stores, win) -> None:
    from core import open_limits as OL
    from core import remote_sweep as RW

    dialog = stores.settings_dialog(win)
    dialog.page("appearance").compact_check.setChecked(True)  # saved before Search
    dialog.page("search").parallel_spin.setValue(9)
    real = OL.write_setting

    def failing(key, value):
        if key == RW.PARALLEL_SETTING:
            raise OSError("disk full")
        real(key, value)

    with mock.patch.object(OL, "write_setting", failing):
        _button(dialog, QDialogButtonBox.StandardButton.Ok).click()
    assert dialog.result() != dialog.DialogCode.Accepted
    assert dialog.current_page_id() == "search"
    assert "disk full" in dialog.error_text()
    assert win._compact_mode is True  # the page before it is saved
    assert dialog.dirty_page_ids() == ["search"]


def test_sad_paranoid_that_cannot_be_stored_is_in_force_and_says_so(stores, win) -> None:
    # Switching it on is the safe direction: it applies now; the dialog says
    # it will not come back on the next start.
    from core import security_mode as SM

    dialog = stores.settings_dialog(win)
    dialog.page("security").paranoid_check.setChecked(True)
    with mock.patch.object(SM, "store_mode", side_effect=OSError("read-only file system")):
        assert not dialog.apply()
    assert SM.is_paranoid()
    assert dialog.current_page_id() == "security"
    assert "read-only file system" in dialog.error_text()


# --- edge ------------------------------------------------------------------


def test_edge_ok_without_changes_writes_nothing(stores, win) -> None:
    before = stores.files()
    dialog = stores.settings_dialog(win)
    assert dialog.dirty_page_ids() == []
    _button(dialog, QDialogButtonBox.StandardButton.Ok).click()
    assert dialog.result() == dialog.DialogCode.Accepted
    assert stores.files() == before


def test_edge_the_filter_finds_settings_by_name(stores, win) -> None:
    dialog = stores.settings_dialog(win)
    dialog.filter_edit.setText("sudo")
    assert dialog.visible_page_ids() == ["security"]
    assert dialog.current_page_id() == "security"
    dialog.filter_edit.setText("Open Size")
    assert dialog.visible_page_ids() == ["files"]
    dialog.filter_edit.setText("MONOCHROME")
    assert dialog.visible_page_ids() == ["appearance"]
    dialog.filter_edit.setText("no such setting at all")
    assert dialog.visible_page_ids() == []
    assert not dialog.no_match_label.isHidden()
    dialog.filter_edit.clear()
    assert len(dialog.visible_page_ids()) == len(CATEGORIES)
    assert dialog.no_match_label.isHidden()


def test_edge_agent_sub_pages_and_tabs_stay_in_step(stores, win) -> None:
    dialog = stores.settings_dialog(win)
    dialog.show_page("agent", "mcp")
    agent = dialog.page("agent")
    assert dialog.current_page_id() == "agent"
    assert agent.tabs.tabText(agent.tabs.currentIndex()) == "MCP Servers"
    agent.tabs.setCurrentIndex(3)  # General, Profiles, Prompts, Access, ...
    assert dialog.tree.currentItem().text(0) == "Access"


def test_edge_a_new_llm_profile_is_offered_to_agent_tabs_before_it_is_saved(stores, win) -> None:
    dialog = stores.settings_dialog(win)
    llm = dialog.page("llm")
    llm.add_profile()
    llm.name_edit.setText("local-qwen")
    dialog.show_page("agent", "general")
    combo = dialog.page("agent").profile_combo
    assert combo.findData("local-qwen") >= 0
    combo.setCurrentIndex(combo.findData("local-qwen"))
    _button(dialog, QDialogButtonBox.StandardButton.Ok).click()
    assert dialog.result() == dialog.DialogCode.Accepted
    from core import agent_settings as S
    from core import llm_profiles as LP

    assert LP.LLMSettings.load().active == "local-qwen"
    assert S.AgentSettings.load().profile == "local-qwen"


def test_edge_paranoid_on_the_security_page_is_previewed_on_extensions(stores, win) -> None:
    dialog = stores.settings_dialog(win)
    blocked = dialog.page("extensions")._blocked
    assert blocked.isHidden()
    dialog.page("security").paranoid_check.setChecked(True)
    assert not blocked.isHidden()
    dialog.page("security").paranoid_check.setChecked(False)
    assert blocked.isHidden()


def test_edge_a_registered_page_takes_the_voice_slot(stores, win) -> None:
    from ui import settings_dialog as SD

    saved = []

    class VoicePage(QWidget):
        def __init__(self, parent=None):
            super().__init__(parent)
            self.label = QLabel("Speech to text model", self)
            self.dirty = False

        def is_dirty(self):
            return self.dirty

        def save(self):
            saved.append(1)
            return True

    SD.register_page("voice", "Voice", lambda parent, window: VoicePage(parent))
    try:
        dialog = stores.settings_dialog(win)
        titles = _top_titles(dialog)
        assert titles.index("Voice") == titles.index("Agent") + 1
        dialog.filter_edit.setText("speech to text")
        assert dialog.visible_page_ids() == ["voice"]
        dialog.page("voice").dirty = True
        assert dialog.apply() and saved == [1]
    finally:
        SD.unregister_page("voice")
    assert "Voice" not in _top_titles(stores.settings_dialog(win))


def test_edge_built_in_ids_cannot_be_replaced_and_broken_pages_are_contained(
    stores, win, caplog
) -> None:
    from ui import settings_dialog as SD

    with pytest.raises(ValueError):
        SD.register_page("security", "Mine", lambda parent, window: QWidget(parent))

    def broken(parent, window):
        raise RuntimeError("boom")

    SD.register_page("broken", "Broken", broken)
    SD.register_page("plain", "Plain", lambda parent, window: QWidget(parent))
    try:
        dialog = stores.settings_dialog(win)
        titles = _top_titles(dialog)
        assert titles[-2:] == ["Broken", "Plain"]  # after the built-in pages
        assert isinstance(dialog.page("broken"), QLabel)
        assert "boom" in caplog.text
        assert dialog.apply()  # a page without the protocol is never dirty
    finally:
        SD.unregister_page("broken")
        SD.unregister_page("plain")


def test_e2e_menu_navigate_change_ok_with_mouse_clicks(stores, win) -> None:
    """The real window: Edit > Settings…, a click on Appearance in the list, a
    click on Compact mode, a click on OK - the window is compact and the
    choice is in session.json."""
    from ui.settings_dialog import SettingsDialog

    win.show()

    def drive(dialog) -> int:
        dialog.show()
        APP.processEvents()
        item = dialog.tree.findItems("Appearance", Qt.MatchFlag.MatchExactly)[0]
        QTest.mouseClick(
            dialog.tree.viewport(), Qt.MouseButton.LeftButton,
            pos=dialog.tree.visualItemRect(item).center(),
        )
        assert dialog.current_page_id() == "appearance"
        APP.processEvents()  # the page is laid out once it is shown
        page = dialog.page("appearance")
        assert page.compact_check.isVisible()
        box = page.compact_check
        # On the indicator: a check box stretched across the form reacts to
        # its box and text only, not to the empty rest of the row.
        QTest.mouseClick(box, Qt.MouseButton.LeftButton, pos=QPoint(8, box.height() // 2))
        assert box.isChecked()
        QTest.mouseClick(
            _button(dialog, QDialogButtonBox.StandardButton.Ok), Qt.MouseButton.LeftButton
        )
        return dialog.result()

    with mock.patch.object(SettingsDialog, "exec", drive):
        result = win.open_settings()
    assert result == SettingsDialog.DialogCode.Accepted
    assert win._compact_mode is True
    assert json.loads(stores.session.read_text())["window"]["compact"] is True


def test_e2e_ctrl_comma_opens_the_settings(stores, win) -> None:
    win.show()
    win.activateWindow()
    APP.processEvents()
    pane = win._active_pane
    pane._table.setFocus()
    pages = _opened_by(
        win,
        lambda: QTest.keyClick(pane._table, Qt.Key.Key_Comma, Qt.KeyboardModifier.ControlModifier),
    )
    assert pages == ["general"]
