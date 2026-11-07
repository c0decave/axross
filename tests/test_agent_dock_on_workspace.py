"""The Agent dock laid out on a workspace, like an extension panel.

Operator's request: the Agent dock was always on all workspaces and could
not be bound to one. Besides *Show Only on Workspace* (tests/
test_dock_bindings.py) the Agent dock now moves *into* a workspace as a
pane, as extension panels do: its title bar's Send to Workspace, or
Workspace > Add Extension Panel. There it shows only with its workspace,
its [x] takes it out (View > Panels puts it back), Ctrl+Shift+A brings its
workspace, and a restart puts it back.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6 import sip  # noqa: E402
from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMenu, QSplitter  # noqa: E402

APP = QApplication.instance() or QApplication([])


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


def in_layout(dock) -> bool:
    return isinstance(dock.parentWidget(), QSplitter)


def test_happy_the_agent_dock_moves_into_a_workspace(window):
    a, b = two_workspaces(window)
    agent = window._agent_dock
    assert agent in window.extension_panels()
    bar = agent.titleBarWidget()
    assert hasattr(bar, "move_button")  # Send to Workspace, as on extension panels
    assert window.move_extension_panel(agent, b)
    pump()
    assert in_layout(agent) and window.workspace_of(agent) is b
    assert agent.pane_mode and bar.pane_mode
    assert window.current_workspace() is b and agent.isVisible()
    window.switch_workspace(a)
    pump()
    assert not agent.isVisible()  # it goes with its workspace
    # the conversations still work
    assert agent.current_tab() is not None


def test_happy_add_extension_panel_lists_the_agent(window):
    a, b = two_workspaces(window)
    menu = QMenu()
    window.fill_add_extension_panel_menu(menu, b)
    entries = {act.text().replace("&", ""): act for act in menu.actions()}
    assert "Agent" in entries
    entries["Agent"].trigger()
    pump()
    assert window.workspace_of(window._agent_dock) is b


def test_happy_ask_the_agent_brings_its_workspace(window):
    a, b = two_workspaces(window)
    agent = window._agent_dock
    window.move_extension_panel(agent, b)
    window.switch_workspace(a)
    pump()
    window._focus_agent()  # Ctrl+Shift+A
    pump()
    assert window.current_workspace() is b and agent.isVisible()


def test_happy_x_takes_it_out_and_view_panels_puts_it_back(window):
    a, b = two_workspaces(window)
    agent = window._agent_dock
    window.move_extension_panel(agent, b)
    pump()
    agent.close()  # its [x]
    pump(0.1)
    assert not in_layout(agent) and not agent.isVisible()
    window.switch_workspace(a)
    pump()
    agent.toggleViewAction().trigger()  # View > Panels > Agent
    pump(0.1)
    assert in_layout(agent) and window.workspace_of(agent) is b
    assert window.current_workspace() is b and agent.isVisible()


def test_happy_back_on_all_workspaces(window):
    a, b = two_workspaces(window)
    agent = window._agent_dock
    window.move_extension_panel(agent, b)
    pump()
    assert window.move_extension_panel(agent, None)
    pump()
    assert not in_layout(agent) and not agent.pane_mode and agent.isVisible()
    window.switch_workspace(a)
    pump()
    assert agent.isVisible()


def test_happy_a_restart_puts_it_back_on_its_workspace(own_home):
    win = new_window()
    try:
        a, b = two_workspaces(win)
        win.move_extension_panel(win._agent_dock, b)
        pump()
    finally:
        close_window(win)
    data = json.loads((own_home / "session.json").read_text())
    assert "axAgentDock" in json.dumps(data["workspaces"][1])

    win = new_window()
    try:
        assert win.restore_layout_on_start()
        pump(0.2)
        a, b = win.workspaces()
        assert win.workspace_of(win._agent_dock) is b and in_layout(win._agent_dock)
    finally:
        close_window(win)


def test_sad_a_lone_agent_dock_has_no_owner_and_lays_out_nothing():
    from ui.agent_dock import AgentDock

    dock = AgentDock(None)
    try:
        assert dock.owner() is None
        assert dock.widget() is not None  # its tabs, in the panel's frame
    finally:
        dock.deleteLater()
        pump()


def test_edge_closing_its_workspace_parks_it_in_the_dock_area(window):
    a, b = two_workspaces(window)
    agent = window._agent_dock
    window.move_extension_panel(agent, b)
    pump()
    assert window.close_workspace(b, ask=False)
    pump(0.1)
    assert not in_layout(agent) and not agent.pane_mode
    assert agent in window.bindable_docks()
