"""The window's gaps found by the feature/icon/menu audit (2026-11-08).

* Menu entries that open a window or panel showed no icon, though the
  toolbar and the windows themselves have one (Tools: Start Agent, MCP
  Servers, Network & Proxy ...; View: Duplicate Finder, Scheduled Jobs;
  File: Quick Connect; Help: Handbook, Tours ...).
* View > Panels: Transfers, Log, Bookmark Sidebar and Ask the Agent had no
  icon, and the mail docks were not listed at all - a closed mail dock came
  back only through Tools > Mail Docks… > Show.
* The Diagnostics and Recovery Scan reports were a blank page (the ``file``
  icon of every text window) and F1 in them opened the contents.
* F1 did nothing in the tool windows (Find in Index, Duplicate Finder, Disk
  Usage, Scheduled Jobs, System Information, Arcade, Agent Stats, the agent's
  sub-dialogs): the main window's F1 is a shortcut of the main window only.
"""

from __future__ import annotations

import ast
import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QDialog, QMenu  # noqa: E402

from core import handbook as H  # noqa: E402
from core import mail_dock as MD  # noqa: E402
from tests.settings_testkit import app, isolate  # noqa: E402

APP = app()


def pump(seconds: float = 0.1) -> None:
    end = time.time() + seconds
    while True:
        APP.processEvents()
        if time.time() >= end:
            return
        time.sleep(0.005)


def wait_until(cond, timeout: float = 10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return bool(cond())


class FakeRunner:
    """A mail dock runner that never connects anywhere."""

    def __init__(self, dock, *, ask_send, on_log, on_event=lambda event: None):
        self.dock = dock
        self.cancel = None

    def run_once(self):
        return ""

    def close(self):
        pass


@pytest.fixture(scope="module")
def window(tmp_path_factory):
    from _pytest.monkeypatch import MonkeyPatch

    patch = MonkeyPatch()
    tmp = tmp_path_factory.mktemp("audit-window")
    stores = isolate(tmp, patch)
    win = stores.make_window()
    win._mail_docks.store = MD.MailDockStore(tmp / "mail_docks.json")
    win._mail_docks.runner_factory = FakeRunner
    win.resize(1400, 800)
    win.show()
    pump(0.3)
    try:
        yield win
    finally:
        for widget in APP.topLevelWidgets():
            if widget is not win and widget.isVisible():
                widget.close()
        win._quit_with_transfers = True
        stores.close_windows()
        stores.restore()
        patch.undo()


def _menu_actions(menu: QMenu) -> dict[tuple[str, str], object]:
    """(menu title, entry text) -> action, through the submenus."""
    out = {}
    for action in menu.actions():
        out[(menu.title(), action.text())] = action
        if action.menu() is not None:
            out.update(_menu_actions(action.menu()))
    return out


#: (menu, entry) -> the icon of what it opens.
MENU_ICONS = {
    ("&File", "Quic&k Connect…"): "quick-connect",
    ("&File", "Connection &Manager…"): "connection-manager",
    ("&View", "Vie&w Selected Media…"): "media-view",
    ("&View", "&Duplicate Finder…"): "duplicates",
    ("&View", "Duplicate Index && History…"): "duplicates",
    ("&View", "Scheduled &Jobs…"): "clock",
    ("&Tools", "&Find on Network Hosts (SMB)…"): "globe",
    ("&Tools", "Run Active Pane &Diagnostics…"): "diagnostics",
    ("&Tools", "&Recovery Scan…"): "recovery",
    ("&Tools", "Text &Editor"): "edit",
    ("&Tools", "&Network && Proxy…"): "vpn",
    ("&Tools", "&LLM Profiles…"): "bot",
    ("&Tools", "Start &Agent"): "agent",
    ("&Tools", "New Agent W&indow"): "agent",
    ("&Tools", "New Agent Tab from &Profile"): "agent",
    ("&Tools", "A&gent Settings…"): "agent",
    ("&Tools", "M&CP Servers…"): "mcp",
    ("&Tools", "&Metadata Settings…"): "metadata",
    ("&Help", "&Handbook"): "book",
    ("&Help", "T&ours…"): "compass",
    ("&Help", "&Keyboard Shortcuts"): "keyboard",
    ("&Help", "&Scripting Guide"): "scripts",
}


def test_happy_the_menu_entries_show_the_icon_of_what_they_open(window):
    found = {}
    for top in window.menuBar().actions():
        if top.menu() is not None:
            found.update(_menu_actions(top.menu()))
    wrong = []
    for key, name in MENU_ICONS.items():
        action = found.get(key)
        assert action is not None, key  # the entry is still there
        if action.property("axIcon") != name or action.icon().isNull():
            wrong.append((key, action.property("axIcon"), name))
    assert wrong == []


def test_happy_the_panel_toggles_of_view_panels_have_their_icons(window):
    window._populate_dock_view_menu()
    actions = window._dock_view_menu.actions()
    expected = {
        window._transfer_dock.toggleViewAction(): "download",
        window._log_dock.toggleViewAction(): "log",
        window._bookmark_sidebar.toggleViewAction(): "bookmark",
        window._focus_agent_action: "agent",
    }
    for action, name in expected.items():
        assert action in actions, action.text()
        assert action.property("axIcon") == name and not action.icon().isNull(), action.text()


def test_happy_a_mail_dock_is_in_view_panels_and_its_toggle_brings_it_back(window):
    docks = window._mail_docks
    dock = MD.MailDockConfig(name="Inbox Watch", mailbox_profile="imap-work", enabled=False)
    docks.store.save([dock])
    docks._open(dock)
    ext, _panel = docks.panels[dock.dock_id]
    pump()
    menu = window._dock_view_menu
    menu.aboutToShow.emit()
    toggles = [a for a in menu.actions() if a.text() == "Mail: Inbox Watch"]
    assert len(toggles) == 1
    assert toggles[0].property("axIcon") == "mail" and not toggles[0].icon().isNull()
    ext.close()
    pump()
    assert not ext.isVisible()
    toggles[0].trigger()
    assert wait_until(ext.isVisible)
    # opening the menu again does not list it twice
    menu.aboutToShow.emit()
    assert [a.text() for a in menu.actions()].count("Mail: Inbox Watch") == 1


def test_sad_a_removed_mail_dock_leaves_view_panels(window):
    docks = window._mail_docks
    dock = MD.MailDockConfig(name="Gone Soon", mailbox_profile="imap-work", enabled=False)
    docks.store.save(docks.store.load() + [dock])
    docks._open(dock)
    menu = window._dock_view_menu
    menu.aboutToShow.emit()
    assert "Mail: Gone Soon" in [a.text() for a in menu.actions()]
    docks.remove(dock.dock_id)
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    pump()
    menu.aboutToShow.emit()
    assert "Mail: Gone Soon" not in [a.text() for a in menu.actions()]
    window._populate_dock_view_menu()  # a full rebuild keeps the others
    assert [a.text() for a in menu.actions()].count("Mail: Inbox Watch") <= 1


def _report(window, title: str):
    for widget in APP.topLevelWidgets() + window.findChildren(QDialog):
        if isinstance(widget, QDialog) and widget.windowTitle() == title and widget.isVisible():
            return widget
    return None


@pytest.mark.parametrize("run, title, icon", [
    ("_run_recovery_scan", "Recovery Scan", "recovery"),
    ("_run_active_pane_diagnostics", "Diagnostics", "diagnostics"),
])
def test_happy_the_diagnostics_and_recovery_reports_have_their_icon_and_section(
        window, tmp_path, run, title, icon):
    from ui.handbook import help_topic_of
    from ui.icon_provider import WINDOW_ICON_PROPERTY

    window._active_pane.navigate(str(tmp_path))
    pump(0.2)
    getattr(window, run)()
    assert wait_until(lambda: _report(window, title) is not None)
    report = _report(window, title)
    assert report.property(WINDOW_ICON_PROPERTY) == icon
    assert help_topic_of(report) == "diagnostics"
    report.close()


# --- F1 in the tool windows ----------------------------------------------------------------

#: file::class -> the help topic F1 opens in it.
WINDOW_TOPICS = {
    "ui/metadata_search_dialog.py::MetadataSearchDialog": "index",
    "ui/cas_dialog.py::CasDuplicatesDialog": "duplicates",
    "ui/cas_history_dialog.py::CasHistoryDialog": "duplicates",
    "ui/disk_usage_dialog.py::DiskUsageDialog": "disk-usage",
    "ui/scheduler_dialog.py::SchedulerDialog": "scheduler",
    "ui/system_info_window.py::SystemInfoWindow": "system-info",
    "ui/arcade_window.py::ArcadeWindow": "arcade",
    "resources/extensions/agent_stats.py::StatsWindow": "agent-stats",
    "ui/agent_access_dialog.py::SessionAccessDialog": "agent",
    "ui/agent_profile_dialog.py::ProfilePickerDialog": "agent",
    "ui/work_prompts_dialog.py::WorkPromptsDialog": "agent",
    "ui/mcp_catalog_dialog.py::McpCatalogDialog": "agent",
    "ui/mail_docks.py::MailDockDialog": "mail",
}


def _help_topic_in_init(rel: str, name: str) -> str | None:
    tree = ast.parse((ROOT / rel).read_text(encoding="utf-8"))
    cls = next(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == name)
    init = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "__init__")
    for call in ast.walk(init):
        if isinstance(call, ast.Call) and getattr(call.func, "id", getattr(call.func, "attr", "")) \
                == "install_help_key" and len(call.args) == 2 and isinstance(call.args[1], ast.Constant):
            return call.args[1].value
    return None


@pytest.mark.parametrize("where", sorted(WINDOW_TOPICS))
def test_happy_each_tool_window_takes_f1_to_its_section(where):
    rel, name = where.split("::")
    topic = _help_topic_in_init(rel, name)
    assert topic == WINDOW_TOPICS[where]
    assert H.SECTIONS[topic] in H.outline((ROOT / "docs" / "USAGE.md").read_text(encoding="utf-8"))


def test_happy_f1_in_disk_usage_opens_the_disk_usage_section(window):
    from ui.disk_usage_dialog import DiskUsageDialog
    from ui.handbook import HandbookDialog

    def no_hosts(backends):
        raise OSError("no hosts in this test")

    dialog = DiskUsageDialog([], parent=window, snapshot_fn=no_hosts)
    dialog.show()
    pump()
    dialog.activateWindow()
    dialog.setFocus()
    pump()
    QTest.keyClick(dialog, Qt.Key.Key_F1)
    pump(0.2)
    books = [w for w in APP.allWidgets() if isinstance(w, HandbookDialog) and w.isVisible()]
    try:
        assert [b.current_heading() for b in books] == [H.SECTIONS["disk-usage"]]
    finally:
        for book in books:
            book.close()
        dialog.close()
        dialog.deleteLater()
