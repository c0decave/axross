"""Starting the agent: Tools > Start Agent and "New Agent Tab Here".

Operator punch list item 46: "ich sehe nur die option send to agent aber
nicht start agent...fehlt da noch was?". Before, the Agent dock opened only
from View > Panels > Agent, "Ask the Agent" (Ctrl+Shift+A, in the same
submenu) or as a side effect of Send to Agent; the Tools menu held only
Agent Settings… and LLM Profiles…, the pane menu only Send to Agent.

Now Tools > Start Agent opens the dock with a new tab for the active pane's
folder, and the pane's right-click menu has New Agent Tab Here next to Send
to Agent.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QMenu  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.1) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture(scope="module")
def folder(tmp_path_factory):
    base = tmp_path_factory.mktemp("agentwork")
    (base / "a.txt").write_text("a")
    (base / "sub").mkdir()
    return base


@pytest.fixture(scope="module")
def win(folder):
    from ui.main_window import MainWindow

    w = MainWindow()
    w._reconnect_timer.stop()
    w.resize(1000, 650)
    w.show()
    pump()
    w._active_pane.navigate(str(folder))
    pump()
    # These tests count one new tab per start; the dock's own untouched
    # first tab (taken over by the first start) has tests of its own below.
    w._agent_dock._placeholder = None
    yield w
    w._agent_dock.shutdown()
    w.close()
    w.deleteLater()
    pump()


def _tools_menu(win) -> QMenu:
    for action in win.menuBar().actions():
        if action.text().replace("&", "") == "Tools":
            return action.menu()
    raise AssertionError("no Tools menu")


def _find(menu: QMenu, text: str):
    return next((a for a in menu.actions() if a.text().replace("&", "") == text), None)


# --- happy -----------------------------------------------------------------


def test_happy_tools_start_agent_opens_a_new_tab_for_the_active_folder(win, folder) -> None:
    dock = win._agent_dock
    dock.hide()
    pump()
    before = dock.tabs.count()
    action = _find(_tools_menu(win), "Start Agent")
    assert action is not None, [a.text() for a in _tools_menu(win).actions()]
    action.trigger()
    pump(0.3)
    assert dock.isVisible()
    assert dock.tabs.count() == before + 1
    tab = dock.current_tab()
    assert tab.root_edit.text() == str(folder)
    assert tab.input.hasFocus() or APP.focusWidget() is tab.input


def test_happy_e2e_new_agent_tab_here_sits_next_to_send_to_agent(win, folder) -> None:
    pane = win._active_pane
    menu = pane._build_context_menu()
    texts = [a.text() for a in menu.actions()]
    assert "New Agent Tab Here" in texts
    assert texts.index("New Agent Tab Here") == texts.index("Send to Agent") + 1
    dock = win._agent_dock
    dock.hide()
    pump()
    before = dock.tabs.count()
    _find(menu, "New Agent Tab Here").trigger()
    pump(0.3)
    assert dock.isVisible() and dock.tabs.count() == before + 1
    assert dock.current_tab().root_edit.text() == str(folder)
    assert dock.current_tab().session.folder == str(folder)


# --- sad -------------------------------------------------------------------


def test_sad_a_remote_pane_starts_the_agent_in_the_local_home(win, monkeypatch) -> None:
    """The agent's folder is local; a remote pane's path is no local folder."""
    pane = win._active_pane
    dock = win._agent_dock
    before = dock.tabs.count()
    monkeypatch.setattr(win, "_agent_root", lambda: os.path.expanduser("~"))
    pane.new_agent_tab_requested.emit("")  # what a remote pane sends
    pump(0.2)
    assert dock.tabs.count() == before + 1
    assert dock.current_tab().root_edit.text() == os.path.expanduser("~")


def test_sad_without_an_agent_dock_nothing_happens(win, monkeypatch) -> None:
    monkeypatch.setattr(win, "_agent_dock", None)
    assert win._new_agent_tab() is None  # no exception, no dock to open


# --- edge ------------------------------------------------------------------


def test_edge_each_start_is_a_tab_of_its_own_and_is_saved(win) -> None:
    dock = win._agent_dock
    before = dock.tabs.count()
    first = win._new_agent_tab()
    second = win._new_agent_tab()
    pump()
    assert first is not second
    assert dock.tabs.count() == before + 2
    stored = {s.id for s in dock.store.all()}
    assert {first.session.id, second.session.id} <= stored


def test_edge_the_entry_says_what_it_does(win) -> None:
    pane = win._active_pane
    menu = pane._build_context_menu()
    action = _find(menu, "New Agent Tab Here")
    assert action is not None and action.isEnabled()
    assert action.toolTip()


# --- the dock's own first tab (found while recording the feature video:
# Start Agent left the empty first tab beside its new one, and that tab
# followed the other pane's folder) --------------------------------------------


@pytest.fixture
def fresh(tmp_path, monkeypatch):
    from core import agent_session as AS
    from ui.main_window import MainWindow

    # Its own session store: the tabs of the tests above would come back.
    monkeypatch.setattr(AS, "sessions_dir", lambda: tmp_path / "sessions")
    docs, projects = tmp_path / "Documents", tmp_path / "Projects"
    docs.mkdir()
    projects.mkdir()
    w = MainWindow()
    w._reconnect_timer.stop()
    w.show()
    pump()
    w._active_pane.navigate(str(docs))
    pump()
    yield w, docs, projects
    w._agent_dock.shutdown()
    w.close()
    w.deleteLater()
    pump()


def test_happy_start_agent_takes_over_the_untouched_first_tab(fresh) -> None:
    w, docs, _projects = fresh
    dock = w._agent_dock
    assert dock.tabs.count() == 1
    tab = w._new_agent_tab()
    pump()
    assert dock.tabs.count() == 1 and dock.current_tab() is tab
    assert tab.root_edit.text() == str(docs) and tab.session.folder == str(docs)
    assert tab.session.id in {s.id for s in dock.store.all()}


def test_sad_a_first_tab_with_typed_text_is_left_alone(fresh) -> None:
    w, docs, _projects = fresh
    dock = w._agent_dock
    first = dock.current_tab()
    first.input.setPlainText("my half-written task")
    tab = w._new_agent_tab()
    pump()
    assert dock.tabs.count() == 2 and tab is not first
    assert first.input.toPlainText() == "my half-written task"


def test_edge_start_agent_then_new_agent_tab_here_keeps_both_folders(fresh) -> None:
    w, docs, projects = fresh
    dock = w._agent_dock
    first = w._new_agent_tab()
    second = w._new_agent_tab(str(projects))
    pump()
    assert dock.tabs.count() == 2 and first is not second
    assert first.root_edit.text() == str(docs)
    assert second.root_edit.text() == str(projects)
    w._active_pane.navigate(str(projects))  # a taken-over tab keeps its folder
    pump()
    dock.tabs.setCurrentWidget(first)
    pump()
    assert first.root_edit.text() == str(docs)
