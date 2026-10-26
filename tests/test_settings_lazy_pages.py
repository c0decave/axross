"""Edit > Settings… builds a page when it is first needed, not all fifteen
when the dialog opens.

Measured 2026-10-25 (scripts/ui_bench.py ``settings_open``): ~300 ms of GUI
CPU to open the dialog - SettingsDialog._build_pages built every page, put it
into a scroll area and read its texts for the filter, though one page is
shown. Now a page is built when it is shown, asked for (``page()``) or
searched (the first letter typed into "Find a setting" builds the rest, so
the filter matches exactly what it matched before). OK / Apply / Cancel
work on the pages that exist: a page never built holds no change.
tests/test_settings_matrix.py stays the contract for every setting.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt, QTimer  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QDialogButtonBox, QLabel, QWidget  # noqa: E402

from tests.settings_testkit import app, isolate  # noqa: E402

APP = app()


@pytest.fixture
def stores(tmp_path, monkeypatch):
    s = isolate(tmp_path, monkeypatch)
    yield s
    s.restore()


@pytest.fixture
def win(stores):
    return stores.make_window()


@pytest.fixture
def built(monkeypatch):
    """page id -> how often its factory ran (built-in and registered pages)."""
    from ui import settings_dialog as SD

    counts: dict[str, int] = {}

    def counting(page_id, factory):
        def make(parent, window):
            counts[page_id] = counts.get(page_id, 0) + 1
            return factory(parent, window)
        return make

    monkeypatch.setattr(SD, "_BUILTIN", {
        pid: (title, counting(pid, factory), keywords, subs)
        for pid, (title, factory, keywords, subs) in SD._BUILTIN.items()})
    monkeypatch.setattr(SD, "_REGISTERED", {
        pid: SD._Registered(reg.title, counting(pid, reg.factory), reg.keywords, reg.sub_pages)
        for pid, reg in SD._REGISTERED.items()})
    return counts


def _eager(stores, win):
    """A dialog with every page built before anything else - what the
    dialog was before it built pages lazily."""
    dialog = stores.settings_dialog(win)
    for page_id in dialog.page_ids():
        dialog.page(page_id)
    return dialog


# --- happy -------------------------------------------------------------------


def test_happy_opening_builds_only_the_page_shown(stores, win, built) -> None:
    dialog = stores.settings_dialog(win)
    assert built == {"general": 1}
    assert dialog.current_page_id() == "general"
    assert len(dialog.page_ids()) >= 14  # every category is listed all the same
    assert dialog.tree.topLevelItemCount() == len(dialog.page_ids())


def test_happy_a_page_is_built_once_when_it_is_first_shown(stores, win, built) -> None:
    dialog = stores.settings_dialog(win)
    dialog.show_page("network")
    dialog.show_page("general")
    dialog.show_page("network")
    assert built == {"general": 1, "network": 1}
    assert dialog.stack.currentWidget().widget() is dialog.page("network")
    assert dialog.title_label.text() == "Network & Proxy"


def test_happy_the_filter_matches_what_the_eager_dialog_matched(stores, win, built) -> None:
    eager = _eager(stores, win)
    lazy = stores.settings_dialog(win)
    for needle in ("proxy", "paranoid", "theme", "hidden", "sudo password", "mcp servers",
                   "open size limit", "exif", "extensions", "zzz-nothing", "a", ""):
        eager.filter_edit.setText(needle)
        lazy.filter_edit.setText(needle)
        assert lazy.visible_page_ids() == eager.visible_page_ids(), needle
        assert lazy.no_match_label.isHidden() == eager.no_match_label.isHidden(), needle
        assert lazy.current_page_id() == eager.current_page_id(), needle


def test_happy_apply_saves_a_built_page_and_builds_no_other(stores, win, built) -> None:
    from core import remote_sweep as RW

    dialog = stores.settings_dialog(win)
    dialog.page("search").parallel_spin.setValue(7)
    assert dialog.dirty_page_ids() == ["search"]
    assert dialog.apply()
    assert RW.parallel_hosts() == 7
    assert set(built) == {"general", "search"}


# --- sad ---------------------------------------------------------------------


def test_sad_a_page_that_cannot_be_built_is_a_note_when_shown(stores, win, built,
                                                               monkeypatch) -> None:
    from ui import settings_dialog as SD

    def broken(parent, window):
        raise RuntimeError("no page today")

    title, _factory, keywords, subs = SD._BUILTIN["metadata"]
    monkeypatch.setitem(SD._BUILTIN, "metadata", (title, broken, keywords, subs))
    dialog = stores.settings_dialog(win)
    dialog.show_page("metadata")
    page = dialog.page("metadata")
    assert isinstance(page, QLabel) and "could not be opened" in page.text()
    dialog.show_page("search")  # the others still work
    assert dialog.page("search").parallel_spin is not None
    assert dialog.apply()


def test_sad_an_unknown_page_is_a_key_error_and_builds_nothing(stores, win, built) -> None:
    dialog = stores.settings_dialog(win)
    with pytest.raises(KeyError):
        dialog.page("warp-drive")
    with pytest.raises(KeyError):
        dialog.show_page("warp-drive")
    assert built == {"general": 1}


def test_sad_cancel_closes_without_building_or_saving(stores, win, built) -> None:
    before = stores.files()
    dialog = stores.settings_dialog(win)
    dialog.page("appearance").monochrome_check.setChecked(True)
    dialog.buttons.button(QDialogButtonBox.StandardButton.Cancel).click()
    assert stores.files() == before
    assert set(built) == {"general", "appearance"}


# --- edge --------------------------------------------------------------------


def test_edge_pages_save_in_the_order_of_the_list_not_the_order_built(stores, win,
                                                                      monkeypatch) -> None:
    dialog = stores.settings_dialog(win)
    saved: list[str] = []
    dialog.page("security").paranoid_check.setChecked(False)  # built first
    dialog.page("search").parallel_spin.setValue(5)
    dialog.page("appearance").monochrome_check.setChecked(True)  # built last
    for page_id in ("security", "search", "appearance"):
        page = dialog.page(page_id)
        original = page.save
        monkeypatch.setattr(page, "save",
                            lambda pid=page_id, save=original: (saved.append(pid), save())[1])
    assert dialog.dirty_page_ids() == ["appearance", "search"]
    assert dialog.apply()
    assert saved == ["appearance", "search"]


def test_edge_paranoid_is_previewed_on_extensions_whichever_is_built_first(stores, win) -> None:
    first = stores.settings_dialog(win)
    first.page("security").paranoid_check.setChecked(True)  # extensions not built yet
    assert first.page("extensions")._blocked.isVisibleTo(first.page("extensions"))
    second = stores.settings_dialog(win)
    blocked = second.page("extensions")._blocked
    assert not blocked.isVisibleTo(second.page("extensions"))
    second.page("security").paranoid_check.setChecked(True)
    assert blocked.isVisibleTo(second.page("extensions"))
    second.page("security").paranoid_check.setChecked(False)
    assert not blocked.isVisibleTo(second.page("extensions"))


def test_edge_the_agent_page_offers_the_unsaved_llm_profiles(stores, win) -> None:
    dialog = stores.settings_dialog(win)
    llm = dialog.page("llm")
    names = llm.profile_names()
    dialog.show_page("agent")
    combo = dialog.page("agent").profile_combo
    assert [combo.itemData(i) for i in range(1, combo.count())] == names
    fresh = stores.settings_dialog(win)
    fresh.show_page("agent")  # the LLM page is built for its names, as before
    combo = fresh.page("agent").profile_combo
    assert [combo.itemData(i) for i in range(1, combo.count())] == fresh.page(
        "llm").profile_names()


def test_edge_a_sub_page_entry_builds_its_page_and_shows_the_tab(stores, win, built) -> None:
    dialog = stores.settings_dialog(win)
    dialog.show_page("agent", "mcp")
    assert "agent" in built
    page = dialog.page("agent")
    assert page.tabs.currentIndex() == [s for s, _t in __import__(
        "ui.agent_settings_dialog", fromlist=["AGENT_TABS"]).AGENT_TABS].index("mcp")
    page.tabs.setCurrentIndex(0)  # the page's own tabs move the list along
    assert dialog.tree.currentItem().parent() is dialog._items["agent"]
    assert dialog.tree.currentItem() is dialog._items["agent"].child(0)


def test_edge_closing_shuts_down_the_built_pages_only(stores, win, built, monkeypatch) -> None:
    dialog = stores.settings_dialog(win)
    calls: list[str] = []
    page = dialog.page("audio")
    if hasattr(page, "shutdown"):
        original = page.shutdown
        monkeypatch.setattr(page, "shutdown", lambda: (calls.append("audio"), original())[1])
    dialog.reject()
    assert set(built) == {"general", "audio"}  # closing builds nothing
    assert calls == (["audio"] if hasattr(page, "shutdown") else [])


def test_edge_a_registered_page_is_built_lazily_too(stores, win, monkeypatch) -> None:
    from ui import settings_dialog as SD

    made = []

    def factory(parent, window):
        made.append(1)
        return QWidget(parent)

    monkeypatch.setattr(SD, "_REGISTERED", dict(SD._REGISTERED))
    SD.register_page("lazytest", "Lazy Test", factory, keywords=("frobnicate",))
    dialog = stores.settings_dialog(win)
    assert made == [] and "lazytest" in dialog.page_ids()
    dialog.filter_edit.setText("frobnicate")
    assert dialog.visible_page_ids() == ["lazytest"] and made == [1]


# --- e2e ---------------------------------------------------------------------


def test_e2e_the_real_window_opens_one_page_finds_and_saves_through_ok(stores, win,
                                                                       built) -> None:
    """Edit > Settings… as the menu opens it: modal, on the page asked for;
    typing into the filter finds a page that was never built, a click shows
    it, a value changed there is stored by OK."""
    from core import remote_sweep as RW
    from ui.settings_dialog import SettingsDialog

    seen: dict = {}

    def drive() -> None:
        try:
            dialog = next(w for w in APP.topLevelWidgets()
                          if isinstance(w, SettingsDialog) and w.isVisible())
            seen["built_at_open"] = set(built)
            QTest.keyClicks(dialog.filter_edit, "parallel")
            seen["visible"] = dialog.visible_page_ids()
            item = dialog._items["search"]
            rect = dialog.tree.visualItemRect(item)
            QTest.mouseClick(dialog.tree.viewport(), Qt.MouseButton.LeftButton,
                             pos=rect.center())
            seen["current"] = dialog.current_page_id()
            spin = dialog.page("search").parallel_spin
            spin.setValue(11)
            QTest.mouseClick(dialog.buttons.button(QDialogButtonBox.StandardButton.Ok),
                             Qt.MouseButton.LeftButton)
        except BaseException as exc:  # handed to the test after exec()
            seen["error"] = exc
            for w in APP.topLevelWidgets():
                if isinstance(w, SettingsDialog) and w.isVisible():
                    w.reject()

    QTimer.singleShot(200, drive)
    result = win.open_settings("audio")
    if "error" in seen:
        raise seen["error"]
    assert seen["built_at_open"] == {"general", "audio"}
    assert seen["visible"] == ["search"]
    assert seen["current"] == "search"
    assert result == 1
    assert RW.parallel_hosts() == 11
