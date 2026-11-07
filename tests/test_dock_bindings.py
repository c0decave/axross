"""Docks shown only on one workspace.

Operator's request: extensions like the Agent dock or the media player are
always on all workspaces and cannot be bound to one - build it in. Every
dock of the dock area (the built-in ones - Agent, Log, Transfers ... - and
extension panels) gets *Show Only on Workspace ▸* from the pin of its title
bar or a right click: it stays a dock, but shows only while its workspace
is on screen. Opening it elsewhere brings its workspace; closing the
workspace frees it; a restart keeps it (ui/dock_bindings.py).
"""

from __future__ import annotations

import json
import os
import sys
import textwrap
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6 import sip  # noqa: E402
from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMenu  # noqa: E402

from core import extensions as EX  # noqa: E402

APP = QApplication.instance() or QApplication([])

PANEL = """
from PyQt6.QtWidgets import QLabel

def activate(api):
    api.add_dock("Panel", QLabel("panel body"))
"""


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)


@pytest.fixture(autouse=True)
def own_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    from ui import main_window as MW

    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", home / "session.json")
    return home


def new_window():
    from ui.main_window import MainWindow

    win = MainWindow()
    win._reconnect_timer.stop()
    win.resize(1200, 800)
    win.show()
    pump()
    return win


def close_window(win) -> None:
    if win is None or sip.isdeleted(win):
        return
    win.close()
    win.deleteLater()
    pump()


@pytest.fixture
def window():
    win = new_window()
    yield win
    close_window(win)


def two_workspaces(win):
    a = win.current_workspace()
    b = win.new_workspace("B")
    pump()
    win.switch_workspace(a)
    pump()
    return a, b


def log_dock(win):
    dock = win._log_dock
    dock.show()
    pump()
    assert dock.isVisible()
    return dock


def actions(menu: QMenu) -> dict:
    menu.aboutToShow.emit()
    return {a.text().replace("&", ""): a for a in menu.actions() if not a.isSeparator()}


def load_panel(win):
    folder = EX.extensions_dir()
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "panel.py").write_text(
        'EXTENSION = {"name": "Panel", "version": "1.0", "description": "test"}\n\n'
        + textwrap.dedent(PANEL))
    EX.set_enabled("user:panel", True)
    win.extension_host.set_enabled("user:panel", True)
    (dock,) = win.extension_host.docks("user:panel")
    return dock


# -- happy ----------------------------------------------------------------------------------


def test_happy_a_bound_dock_shows_only_on_its_workspace(window):
    a, b = two_workspaces(window)
    dock = log_dock(window)
    bar = dock.titleBarWidget()
    assert not bar._pin_btn.isChecked()
    assert window.bind_dock_to_workspace(dock, b)
    pump()
    assert window.dock_workspace(dock) is b
    assert bar._pin_btn.isChecked() and "B" in bar._pin_btn.toolTip()
    assert not dock.isVisible()  # A is on screen
    window.switch_workspace(b)
    pump()
    assert dock.isVisible()
    window.switch_workspace(a)
    pump()
    assert not dock.isVisible()
    # still a dock, not laid out in the workspace
    assert dock.parentWidget() is window


def test_happy_the_title_bar_menu_binds_and_brings_the_workspace(window):
    a, b = two_workspaces(window)
    dock = log_dock(window)
    menu = dock.titleBarWidget().binding_menu()
    entries = actions(menu)
    assert entries["All Workspaces"].isChecked()
    assert "New Workspace" in entries and "2: B" in [t.split("  ")[0] for t in entries] \
        or any(t.endswith("B") for t in entries)
    target = next(act for text, act in entries.items() if text.endswith("B"))
    target.trigger()
    pump()
    assert window.dock_workspace(dock) is b
    assert window.current_workspace() is b and dock.isVisible()


def test_happy_opening_it_elsewhere_brings_its_workspace(window):
    a, b = two_workspaces(window)
    dock = log_dock(window)
    window.bind_dock_to_workspace(dock, b)
    pump()
    assert window.current_workspace() is a and not dock.isVisible()
    dock.toggleViewAction().trigger()  # View > Panels > Log
    pump()
    assert window.current_workspace() is b and dock.isVisible()


def test_happy_back_on_all_workspaces(window):
    a, b = two_workspaces(window)
    dock = log_dock(window)
    window.bind_dock_to_workspace(dock, b)
    pump()
    assert not dock.isVisible()
    window.bind_dock_to_workspace(dock, None)
    pump()
    assert dock.isVisible() and window.dock_workspace(dock) is None
    assert not dock.titleBarWidget()._pin_btn.isChecked()
    window.switch_workspace(b)
    pump()
    assert dock.isVisible()


def test_happy_the_agent_dock_and_extension_panels_can_be_bound(window):
    a, b = two_workspaces(window)
    assert window._agent_dock in window.bindable_docks()
    panel = load_panel(window)
    pump()
    assert panel in window.bindable_docks()
    menu = panel.titleBarWidget().context_menu()
    titles = [a.menu().title() for a in menu.actions() if a.menu() is not None]
    assert "Send to Workspace" in titles and "Show Only on Workspace" in titles
    panel.show()
    window.bind_dock_to_workspace(panel, b)
    pump()
    assert not panel.isVisible()
    window.switch_workspace(b)
    pump()
    assert panel.isVisible() and panel.parentWidget() is window


def test_happy_a_restart_keeps_the_binding(own_home):
    win = new_window()
    try:
        a, b = two_workspaces(win)
        dock = log_dock(win)
        win.bind_dock_to_workspace(dock, b)
        terminal = win._terminal_dock
        terminal.show()
        win.bind_dock_to_workspace(terminal, a)
        terminal.hide()  # closed on its own workspace
        pump()
    finally:
        close_window(win)
    data = json.loads((own_home / "session.json").read_text())
    saved = data["window"]["dock_workspaces"]
    assert saved["axLogDock"] == {"ws": 1, "open": True}
    assert saved["axTerminalDock"] == {"ws": 0, "open": False}

    win = new_window()
    try:
        assert win.restore_layout_on_start()
        pump(0.2)
        a, b = win.workspaces()
        dock = win._log_dock
        assert win.dock_workspace(dock) is b
        win.switch_workspace(a)
        pump()
        assert not dock.isVisible() and not win._terminal_dock.isVisible()
        win.switch_workspace(b)
        pump()
        assert dock.isVisible()
        assert dock.titleBarWidget()._pin_btn.isChecked()
    finally:
        close_window(win)


# -- sad ------------------------------------------------------------------------------------


def test_sad_closed_on_its_workspace_stays_closed(window):
    a, b = two_workspaces(window)
    dock = log_dock(window)
    window.bind_dock_to_workspace(dock, a)
    pump()
    assert dock.isVisible()
    dock.close()  # the user closes it
    window.switch_workspace(b)
    pump()
    window.switch_workspace(a)
    pump()
    assert not dock.isVisible()


def test_sad_what_cannot_be_bound(window):
    a, b = two_workspaces(window)
    dock = log_dock(window)
    assert not window.bind_dock_to_workspace(None, b)
    assert not window.bind_dock_to_workspace(window._active_pane, b)  # no dock
    assert window.bind_dock_to_workspace(dock, b)
    assert not window.bind_dock_to_workspace(dock, b)  # already there

    class Stranger:
        name = "stranger"
        window = None

    assert not window.bind_dock_to_workspace(dock, Stranger())


def test_sad_a_broken_session_entry_is_left_out(window):
    a, b = two_workspaces(window)
    window.restore_dock_bindings({"axLogDock": {"ws": 7}, "axTerminalDock": "B",
                                  5: {"ws": 0}, "axConsoleDock": {"ws": True},
                                  "axTransferDock": {"ws": 1, "open": False}})
    assert window.dock_workspace(window._log_dock) is None
    assert window.dock_workspace(window._terminal_dock) is None
    assert window.dock_workspace(window._transfer_dock) is b
    window.restore_dock_bindings("garbage")
    assert window.dock_workspace(window._transfer_dock) is None


# -- edge -----------------------------------------------------------------------------------


def test_edge_closing_the_workspace_frees_the_dock(window):
    a, b = two_workspaces(window)
    dock = log_dock(window)
    window.bind_dock_to_workspace(dock, b)
    pump()
    assert not dock.isVisible()
    assert window.close_workspace(b, ask=False)
    pump()
    assert window.dock_workspace(dock) is None
    assert dock.isVisible()  # it was open: on all workspaces again
    assert not dock.titleBarWidget()._pin_btn.isChecked()


def test_edge_new_workspace_from_the_menu(window):
    window.current_workspace()
    dock = log_dock(window)
    entries = actions(dock.titleBarWidget().binding_menu())
    entries["New Workspace"].trigger()
    pump()
    ws = window.dock_workspace(dock)
    assert ws is not None and ws in window.workspaces() and len(window.workspaces()) == 2
    assert window.current_workspace() is ws and dock.isVisible()


def test_edge_a_detached_workspace_shows_its_docks_while_current(window):
    """A detached workspace is not a tab of the window: its docks show
    while it is the current workspace - the one whose pane has the focus,
    which the window manager may hand back to it at any time."""
    a, b = two_workspaces(window)
    dock = log_dock(window)
    window.bind_dock_to_workspace(dock, b)
    window.detach_workspace(b, activate=False)
    pump(0.2)
    assert b.window is not None
    window.switch_workspace(b)
    pump()
    assert dock.isVisible()
    for ws in (a, b, a):
        window.switch_workspace(ws)
        pump(0.2)
        assert dock.isVisible() == (window.current_workspace() is b)
    assert window._shown_workspace(b) == (window.current_workspace() is b)


def test_edge_the_title_stays_short_enough(window):
    """The pin made every title bar 28 px wider; the title gives way so the
    panels do not raise the window's minimum width."""
    bar = window._log_dock.titleBarWidget()
    assert bar._title_label.minimumWidth() == 40
    assert bar._title_label.minimumSizeHint().width() >= 0


def test_edge_an_extension_switched_off_and_on_keeps_its_panel_bound(window):
    """Switching an extension off and on makes a new panel under the old
    name. The binding was hooked by name, so the new panel got no watcher
    and the old one's "hidden by its binding" stuck to it: it showed on
    the wrong workspace, and opening it there did not bring its own."""
    a, b = two_workspaces(window)
    panel = load_panel(window)
    panel.show()
    window.bind_dock_to_workspace(panel, b)
    pump()
    assert not panel.isVisible()
    window.extension_host.set_enabled("user:panel", False)
    pump()
    window.extension_host.set_enabled("user:panel", True)
    pump()
    (again,) = window.extension_host.docks("user:panel")
    assert again is not panel
    assert window.current_workspace() is a  # switching it on brings no workspace
    assert not again.isVisible()  # not on A: it is bound to B
    again.toggleViewAction().trigger()  # Extensions > Panel
    pump(0.2)
    assert window.current_workspace() is b and again.isVisible()
    window.switch_workspace(a)
    pump()
    assert not again.isVisible()


def test_edge_a_restart_keeps_the_binding_after_the_tabs_were_moved(own_home):
    """The session file lists the workspaces in tab order (the user can
    drag the tabs), detached ones last; the bindings were saved by the
    position in the window's own list, which dragging does not change - a
    restart bound the dock to another workspace."""
    win = new_window()
    try:
        a, b = two_workspaces(win)
        a.name, b.name = "Alpha", "Beta"
        win._workspace_tabs.tabBar().moveTab(1, 0)  # Beta first
        pump()
        dock = log_dock(win)
        win.bind_dock_to_workspace(dock, a)
        pump()
    finally:
        close_window(win)

    win = new_window()
    try:
        assert win.restore_layout_on_start()
        pump(0.2)
        ws = win.dock_workspace(win._log_dock)
        assert ws is not None and ws.name == "Alpha"
    finally:
        close_window(win)
