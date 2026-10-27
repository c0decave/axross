"""Agent conversations as panels of their own: a tab of the Agent dock is
detached into a panel (tab menu "Detach as Panel" or dragged out of the tab
bar), the panel is laid out like an extension panel (All Workspaces, a
workspace, moved like a pane), attached back ("Attach to Agent Dock") and
comes back after a restart. "New Agent Window" opens a fresh conversation
as such a panel.

Operator: several agent windows, each with its own contents, or single
conversations detached as panes of their own and attached again.

The panel carries the live AgentTab: a running task keeps going, there is
no second session object, confirmations still work, and every integration
of the dock (agent events to extensions, the voice, the link lamp, settings
changes) reaches detached conversations too. The model is the scripted fake
LLM of test_agent_loop.
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
from PyQt6.QtCore import QEvent, QPoint, QPointF, Qt  # noqa: E402
from PyQt6.QtGui import QMouseEvent  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMenu, QMessageBox, QSplitter  # noqa: E402

from core import agent_settings as AGS  # noqa: E402
from core import extensions as EX  # noqa: E402
from core import llm_profiles as LP  # noqa: E402
from core.agent_session import AgentSession, SessionStore  # noqa: E402
from tests.test_agent_loop import _call, _Fake  # noqa: E402
from tests.test_agent_tabs import Env, say, wait_idle  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)


def wait(cond, timeout: float = 10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return cond()


def menu_action(menu: QMenu, text: str):
    menu.aboutToShow.emit()
    for action in menu.actions():
        if action.text().replace("&", "") == text:
            return action
    raise AssertionError(f"{text!r} not in {[a.text() for a in menu.actions()]}")


def saved(store_dir: Path, session_id: str) -> dict:
    return json.loads((store_dir / f"{session_id}.json").read_text())


@pytest.fixture(autouse=True)
def _no_proxy(monkeypatch):
    for name in ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY",
                 "ALL_PROXY"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    yield e
    for dock in e.docks:
        for panel in list(dock.panels()):
            if not sip.isdeleted(panel):
                panel.deleteLater()
    e.close()


# -- the session keeps where its conversation is ---------------------------------------------


def test_happy_a_session_keeps_its_detached_place():
    session = AgentSession(detached="workspace")
    back = AgentSession.from_dict(session.to_dict())
    assert back.detached == "workspace"
    assert AgentSession.from_dict(AgentSession(detached="all").to_dict()).detached == "all"


@pytest.mark.parametrize("value", [7, "elsewhere", None, ["all"], True])
def test_sad_a_broken_detached_entry_reads_as_a_tab(value):
    data = AgentSession().to_dict()
    data["detached"] = value
    assert AgentSession.from_dict(data).detached == ""


def test_edge_a_tab_writes_no_detached_entry():
    assert "detached" not in AgentSession().to_dict()


# -- the dock on its own -----------------------------------------------------------------------


def test_happy_detach_moves_the_same_tab_and_session_into_a_panel(env):
    env.fake({"content": "One."})
    dock = env.dock()
    tab = dock.current_tab()
    say(tab, "first question")
    session = tab.session
    panel = dock.detach_tab(tab)
    pump()
    assert panel is not None and panel.widget() is tab and panel.tab is tab
    assert tab.session is session and dock.panel_of(tab) is panel
    assert dock.tabs.indexOf(tab) < 0
    assert tab in dock.all_tabs() and dock.panels() == [panel]
    assert session in dock.sessions()
    assert "One." in tab.transcript.toPlainText()
    assert saved(env.store_dir, session.id)["detached"] == "all"
    assert panel.objectName() == f"agent-conversation-{session.id}"


def test_happy_a_running_task_keeps_going_in_the_detached_panel_and_asks(env):
    target = env.root / "todo.txt"
    server = env.fake(
        {"tool_calls": [_call("write_file", {"path": str(target), "content": "renew"})],
         "_delay": 0.8},
        {"content": "Written."},
    )
    dock = env.dock()
    events = []
    dock.agent_event.connect(lambda sid, event: events.append((sid, event.get("type"))))
    tab = dock.current_tab()
    tab.allow_write.setChecked(True)
    tab.input.setPlainText("write the todo")
    tab.send()
    assert wait(lambda: server.requests)
    assert tab.busy()
    thread = tab._thread
    panel = dock.detach_tab(tab)
    assert panel is not None and tab.busy() and tab._thread is thread  # nothing restarted
    wait_idle(tab)
    assert [n for n, _ in env.asked] == ["write_file"]  # the confirmation still came
    assert target.read_text() == "renew"
    assert "Written." in tab.transcript.toPlainText()
    assert len(server.requests) == 2
    assert {sid for sid, _t in events} == {tab.session.id}
    kinds = [t for _s, t in events]
    assert kinds.count("run_started") == 1 and kinds.count("run_finished") == 1
    assert "confirmation" in kinds


def test_happy_attach_puts_the_conversation_back_as_a_tab(env):
    env.fake({"content": "One."})
    dock = env.dock()
    tab = dock.current_tab()
    say(tab, "question")
    panel = dock.detach_tab(tab)
    back = dock.attach_panel(panel)
    pump()
    assert back is tab and dock.tabs.indexOf(tab) >= 0 and dock.current_tab() is tab
    assert dock.panels() == [] and sip.isdeleted(panel)
    assert dock.panel_of(tab) is None
    assert "detached" not in saved(env.store_dir, tab.session.id)
    assert "One." in tab.transcript.toPlainText()


def test_edge_detaching_the_last_tab_leaves_a_fresh_one_and_attach_takes_its_place(env):
    env.fake({"content": "One."})
    dock = env.dock()
    tab = dock.current_tab()
    say(tab, "question")
    panel = dock.detach_tab(tab)
    assert dock.tabs.count() == 1  # a fresh, untouched tab: the dock is never empty
    fresh = dock.current_tab()
    assert fresh is not tab and not fresh.session.transcript
    dock.attach_panel(panel)
    pump()
    # The untouched tab the dock made by itself goes again.
    assert dock.all_tabs() == [tab]
    assert sip.isdeleted(fresh) or dock.tabs.indexOf(fresh) < 0


def test_edge_attach_keeps_a_tab_somebody_typed_into(env):
    env.fake({"content": "One."})
    dock = env.dock()
    tab = dock.current_tab()
    say(tab, "question")
    panel = dock.detach_tab(tab)
    fresh = dock.current_tab()
    fresh.input.setPlainText("half a question")
    dock.attach_panel(panel)
    assert dock.all_tabs() == [fresh, tab]


def test_sad_closing_a_panel_with_a_conversation_asks_and_no_keeps_it(env, monkeypatch):
    env.fake({"content": "One."})
    dock = env.dock()
    tab = dock.current_tab()
    say(tab, "question")
    panel = dock.detach_tab(tab)
    asked = []
    monkeypatch.setattr(QMessageBox, "question",
                        lambda *a, **k: asked.append(a[2]) or QMessageBox.StandardButton.No)
    panel.close()
    pump()
    assert asked and "conversation" in asked[0]
    assert not sip.isdeleted(panel) and panel.isVisible() and tab in dock.all_tabs()
    assert (env.store_dir / f"{tab.session.id}.json").exists()
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    panel.close()
    pump()
    assert sip.isdeleted(panel) and dock.panels() == []
    assert not (env.store_dir / f"{tab.session.id}.json").exists()


def test_edge_an_empty_detached_conversation_closes_without_asking(env, monkeypatch):
    env.fake()
    dock = env.dock()
    dock.new_tab()
    tab = dock.current_tab()
    panel = dock.detach_tab(tab)
    asked = []  # (a failure raised inside the slot would abort the process)
    monkeypatch.setattr(QMessageBox, "question",
                        lambda *a, **k: asked.append(a) or QMessageBox.StandardButton.No)
    panel.close()
    pump()
    assert asked == [] and sip.isdeleted(panel) and tab not in dock.all_tabs()


def test_sad_detach_and_attach_refuse_what_is_not_theirs(env):
    env.fake()
    dock = env.dock()
    other = env.dock()
    assert dock.detach_tab(other.current_tab()) is None
    assert dock.detach_tab(None) is None
    panel = other.detach_tab(other.current_tab())
    assert dock.attach_panel(panel) is None
    assert dock.attach_panel(None) is None
    assert other.panels() == [panel]


def test_happy_new_window_opens_a_fresh_conversation_as_a_panel(env):
    env.fake()
    dock = env.dock()
    before = dock.tabs.count()
    panel = dock.new_window(folder=str(env.root))
    pump()
    assert panel is not None and dock.tabs.count() == before
    assert panel.tab.session.folder == str(env.root)
    assert dock.panels() == [panel]
    assert saved(env.store_dir, panel.tab.session.id)["detached"] == "all"


def test_happy_settings_and_profiles_reach_detached_conversations(env):
    from core.agent_sandbox import SandboxProfile

    server = env.fake()
    dock = env.dock()
    panel = dock.detach_tab(dock.current_tab())
    tab = panel.tab
    env.llm = LP.LLMSettings(
        [LP.LLMProfile(name="local", provider="lmstudio", endpoint=server.url, model="tiny"),
         LP.LLMProfile(name="second", provider="lmstudio", endpoint=server.url, model="t2")],
        "local")
    dock.refresh_profiles()
    assert tab.model_combo.findData("second") >= 0
    env.settings.sandboxes = [*env.settings.sandboxes, SandboxProfile(name="Box")]
    dock.reload_settings()
    assert any(tab.sandbox_combo.itemData(i) == "Box" for i in range(tab.sandbox_combo.count()))


def test_happy_voice_text_goes_to_the_detached_conversation_it_listens_for(env):
    env.fake()
    dock = env.dock()
    docked = dock.current_tab()
    panel = dock.new_window()
    dock.voice_tab = panel.tab
    dock._on_voice_text("hello there")
    assert panel.tab.input.toPlainText() == "hello there"
    assert docked.input.toPlainText() == ""


def test_edge_without_a_listening_tab_the_voice_follows_the_focused_conversation(env):
    env.fake()
    dock = env.dock()
    docked = dock.current_tab()
    panel = dock.new_window()
    dock.voice_tab = None
    dock._on_focus_changed(None, panel.tab.input)
    dock._on_voice_text("to the panel")
    assert panel.tab.input.toPlainText() == "to the panel"
    dock._on_focus_changed(panel.tab.input, docked.input)
    dock._on_voice_text("to the dock")
    assert docked.input.toPlainText() == "to the dock"
    # Focus outside any conversation leaves it where it was.
    dock._on_focus_changed(docked.input, None)
    dock._on_voice_text("again")
    assert docked.input.toPlainText().endswith("again")


def test_edge_a_voice_tab_that_was_closed_falls_back(env, monkeypatch):
    env.fake()
    dock = env.dock()
    docked = dock.current_tab()
    panel = dock.new_window()
    dock.voice_tab = panel.tab
    panel.close()  # empty: no question
    pump()
    dock._on_voice_text("still heard")
    assert docked.input.toPlainText() == "still heard"


def test_happy_the_panel_has_its_own_link_lamp(env):
    env.fake({"content": "One."})
    dock = env.dock()
    panel = dock.new_window()
    say(panel.tab, "question")
    pump()
    assert panel.tab.link.state == "online"
    assert panel.lamp.state == "online"
    assert panel.titleBarWidget().isAncestorOf(panel.lamp)


def test_e2e_the_tab_menu_detaches_and_the_title_bar_attaches(env):
    env.fake({"content": "One."})
    dock = env.dock()
    tab = dock.current_tab()
    say(tab, "question")
    menu = dock.tab_menu(dock.tabs.indexOf(tab))
    menu_action(menu, "Detach as Panel").trigger()
    pump()
    panel = dock.panel_of(tab)
    assert panel is not None and panel.widget() is tab
    bar = panel.titleBarWidget()
    QTest.mouseClick(bar.attach_button, Qt.MouseButton.LeftButton)
    pump()
    assert dock.tabs.indexOf(tab) >= 0 and dock.panels() == []


def test_e2e_dragging_a_tab_out_of_the_tab_bar_detaches_it(env):
    env.fake()
    dock = env.dock()
    dock.new_tab()
    dock.resize(500, 400)
    dock.show()
    pump()
    bar = dock.tabs.tabBar()
    tab = dock.tabs.widget(1)
    start = bar.tabRect(1).center()
    QTest.mousePress(bar, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, start)
    for dy in (5, 20, 60, 140):
        pos = QPointF(start.x(), start.y() + dy)
        APP.sendEvent(bar, QMouseEvent(QEvent.Type.MouseMove, pos, bar.mapToGlobal(pos),
                                       Qt.MouseButton.NoButton, Qt.MouseButton.LeftButton,
                                       Qt.KeyboardModifier.NoModifier))
        pump(0.02)
    QTest.mouseRelease(bar, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier,
                       QPoint(start.x(), start.y() + 140))
    pump()
    assert dock.panel_of(tab) is not None
    assert dock.tabs.count() == 1


def test_edge_a_short_drag_along_the_tab_bar_only_moves_the_tab(env):
    env.fake()
    dock = env.dock()
    dock.new_tab()
    dock.resize(500, 400)
    dock.show()
    pump()
    bar = dock.tabs.tabBar()
    start = bar.tabRect(0).center()
    QTest.mousePress(bar, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, start)
    pos = QPointF(start.x() + 8, start.y() + 2)
    APP.sendEvent(bar, QMouseEvent(QEvent.Type.MouseMove, pos, bar.mapToGlobal(pos),
                                   Qt.MouseButton.NoButton, Qt.MouseButton.LeftButton,
                                   Qt.KeyboardModifier.NoModifier))
    QTest.mouseRelease(bar, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier,
                       pos.toPoint())
    pump()
    assert dock.panels() == [] and dock.tabs.count() == 2


# -- in the main window ------------------------------------------------------------------------


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    from ui import main_window as MW

    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", home / "session.json")
    return home


class Win:
    """A real MainWindow on a fake LLM; the confirmation dialog is the real
    code path up to the dialog itself (ui.agent_dock._ask_call)."""

    def __init__(self, monkeypatch, server_box):
        from ui import agent_dock as AD
        from ui.main_window import MainWindow

        self.asked = []
        monkeypatch.setattr(AD, "_ask_call",
                            lambda parent, name, args: self.asked.append(name) or True)
        self.server_box = server_box
        self.win = MainWindow()
        self.win._reconnect_timer.stop()
        self.win.resize(1200, 800)
        self.win.show()
        self.dock = self.win._agent_dock
        self.dock.key_lookup = lambda name: ""
        self.dock.confirm_remote = lambda p, h: True
        self.use_llm()

    def use_llm(self):
        server = self.server_box[0]
        llm = LP.LLMSettings(
            [LP.LLMProfile(name="local", provider="lmstudio", endpoint=server.url, model="tiny")],
            "local")
        self.dock.llm_settings = lambda: llm
        for tab in self.dock.all_tabs():
            tab.refresh_choices()

    def close(self):
        if sip.isdeleted(self.win):
            return
        self.win.close()
        self.win.deleteLater()
        pump(0.1)


@pytest.fixture
def server_box():
    box = [_Fake([])]
    yield box
    for server in box:
        server.close()


@pytest.fixture
def mw(home, monkeypatch, server_box):
    w = Win(monkeypatch, server_box)
    pump()
    yield w
    w.close()


def two_workspaces(win):
    a = win.current_workspace()
    b = win.new_workspace("B")
    pump()
    win.switch_workspace(a)
    pump()
    return a, b


def in_layout(panel) -> bool:
    return isinstance(panel.parentWidget(), QSplitter)


def test_e2e_detach_a_running_task_move_it_to_a_workspace_and_attach_it_back(mw, server_box):
    win, dock = mw.win, mw.dock
    target = Path(os.environ["HOME"]) / "note.txt"
    server_box[0].replies = [
        {"tool_calls": [_call("write_file", {"path": str(target), "content": "hi"})],
         "_delay": 1.0},
        {"content": "Wrote the note."},
    ]
    win._focus_agent_action.trigger()
    pump()
    tab = dock.current_tab()
    tab.root_edit.setText(str(target.parent))
    tab.allow_write.setChecked(True)
    tab.input.setPlainText("write a note")
    tab.send()
    assert wait(lambda: server_box[0].requests)
    a, b = two_workspaces(win)
    menu_action(dock.tab_menu(dock.tabs.indexOf(tab)), "Detach as Panel").trigger()
    pump()
    panel = dock.panel_of(tab)
    assert panel is not None and tab.busy()
    assert win.dockWidgetArea(panel) == Qt.DockWidgetArea.RightDockWidgetArea
    assert win.extension_panel_workspace(panel) is None and panel.isVisible()
    # Moved like an extension panel: the title bar's Send to Workspace menu.
    menu_action(panel.titleBarWidget().move_menu, "2: B").trigger()
    pump()
    assert in_layout(panel) and win.extension_panel_workspace(panel) is b
    assert win.current_workspace() is b and panel.isVisible()
    wait_idle(tab)
    assert mw.asked == ["write_file"] and target.read_text() == "hi"
    assert "Wrote the note." in tab.transcript.toPlainText()
    win.switch_workspace(a)
    pump()
    assert not panel.isVisible()  # hides with its workspace
    win.switch_workspace(b)
    pump()
    menu_action(panel.titleBarWidget().context_menu(), "Attach to Agent Dock").trigger()
    pump()
    assert dock.tabs.indexOf(tab) >= 0 and dock.panels() == []
    assert dock.isVisible() and dock.current_tab() is tab
    assert b in win.workspaces()  # B keeps its file pane


def test_e2e_a_panel_takes_and_gives_pane_drops_and_counts_as_a_pane(mw):
    win, dock = mw.win, mw.dock
    a, b = two_workspaces(win)
    panel = dock.new_window()
    pump()
    win.move_extension_panel(panel, b)
    pump()
    (pane,) = win._widgets_of(b)[0]
    win._on_pane_drop(str(id(panel)), pane, "left")
    pump()
    holder = panel.parentWidget()
    assert holder is pane.parentWidget() and holder.indexOf(panel) == 0
    # The file pane leaves: the panel keeps workspace B alive.
    win.move_pane_to_workspace(pane, a)
    pump()
    assert b in win.workspaces() and win.extension_panel_workspace(panel) is b


def test_e2e_new_agent_window_from_the_tools_menu(mw):
    win, dock = mw.win, mw.dock
    before = len(dock.all_tabs())
    win._new_agent_window_action.trigger()
    pump()
    (panel,) = dock.panels()
    assert panel.isVisible() and len(dock.all_tabs()) == before + 1
    assert win.dockWidgetArea(panel) == Qt.DockWidgetArea.RightDockWidgetArea
    assert panel.tab.session.folder  # the active pane's folder or home


def test_e2e_closing_a_workspace_keeps_its_agent_panel_on_screen(mw, monkeypatch):
    win, dock = mw.win, mw.dock
    server_box = mw.server_box
    server_box[0].replies = [{"content": "Kept."}]
    a, b = two_workspaces(win)
    panel = dock.new_window()
    say(panel.tab, "question")
    win.move_extension_panel(panel, b)
    pump()
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    assert win.close_workspace(b)
    pump()
    assert not sip.isdeleted(panel) and panel.isVisible()
    assert win.extension_panel_workspace(panel) is None
    assert "Kept." in panel.tab.transcript.toPlainText()


def test_e2e_the_close_button_asks_and_deletes_the_conversation(mw, monkeypatch, home):
    dock = mw.dock
    mw.server_box[0].replies = [{"content": "One."}]
    panel = dock.new_window()
    say(panel.tab, "question")
    sid = panel.tab.session.id
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.No)
    QTest.mouseClick(panel.titleBarWidget()._close_btn, Qt.MouseButton.LeftButton)
    pump()
    assert not sip.isdeleted(panel) and panel.isVisible()
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    QTest.mouseClick(panel.titleBarWidget()._close_btn, Qt.MouseButton.LeftButton)
    pump()
    assert sip.isdeleted(panel) and dock.panels() == []
    assert sid not in {s.id for s in SessionStore().all()}


def test_e2e_restart_brings_detached_panels_back_on_their_workspace_and_all_workspaces(
        home, monkeypatch, server_box):
    server_box[0].replies = [{"content": "Answer B."}, {"content": "Answer all."}]
    w = Win(monkeypatch, server_box)
    try:
        pump()
        win, dock = w.win, w.dock
        a, b = two_workspaces(win)
        on_b = dock.new_window()
        say(on_b.tab, "for B")
        win.move_extension_panel(on_b, b)
        everywhere = dock.new_window()
        say(everywhere.tab, "for all")
        pump()
        ids = on_b.tab.session.id, everywhere.tab.session.id
    finally:
        w.close()
    w = Win(monkeypatch, server_box)
    try:
        win, dock = w.win, w.dock
        assert win.restore_layout_on_start()
        pump(0.2)
        panels = {p.tab.session.id: p for p in dock.panels()}
        assert set(panels) == set(ids)
        b = win.workspaces()[1]
        assert win.extension_panel_workspace(panels[ids[0]]) is b
        assert win.extension_panel_workspace(panels[ids[1]]) is None
        assert panels[ids[1]].isVisible()
        assert "Answer B." in panels[ids[0]].tab.transcript.toPlainText()
        assert "Answer all." in panels[ids[1]].tab.transcript.toPlainText()
        assert all(dock.tabs.indexOf(p.tab) < 0 for p in panels.values())
    finally:
        w.close()


def test_e2e_a_detached_panel_without_its_layout_entry_comes_back_as_a_tab(
        home, monkeypatch, server_box, caplog):
    server_box[0].replies = [{"content": "Answer."}]
    w = Win(monkeypatch, server_box)
    try:
        pump()
        win, dock = w.win, w.dock
        a, b = two_workspaces(win)
        panel = dock.new_window()
        say(panel.tab, "question")
        win.move_extension_panel(panel, b)
        pump()
        sid = panel.tab.session.id
    finally:
        w.close()
    (home / "session.json").unlink()  # the layout entry is gone
    w = Win(monkeypatch, server_box)
    try:
        win, dock = w.win, w.dock
        assert not win.restore_layout_on_start()
        pump()
        assert dock.panels() == []
        tab = next(t for t in dock.all_tabs() if t.session.id == sid)
        assert dock.tabs.indexOf(tab) >= 0 and "Answer." in tab.transcript.toPlainText()
    finally:
        w.close()


def test_sad_a_layout_entry_of_a_conversation_that_is_gone_is_skipped(
        home, monkeypatch, server_box):
    w = Win(monkeypatch, server_box)
    try:
        pump()
        win, dock = w.win, w.dock
        a, b = two_workspaces(win)
        panel = dock.new_window()
        panel.tab.input.setPlainText("x")
        win.move_extension_panel(panel, b)
        pump()
        sid = panel.tab.session.id
    finally:
        w.close()
    SessionStore().delete(sid)  # the conversation file is gone
    w = Win(monkeypatch, server_box)
    try:
        win, dock = w.win, w.dock
        assert win.restore_layout_on_start()
        pump()
        assert dock.panels() == []
        assert not win._panel_homes  # no place kept for it: nothing comes back there
        assert len(win.workspaces()) == 2
    finally:
        w.close()


def test_sad_a_broken_detached_entry_in_the_session_file_comes_back_as_a_tab(
        home, monkeypatch, server_box):
    store = SessionStore()
    session = AgentSession(title="Broken place")
    session.transcript = [{"who": "You:", "text": "kept", "muted": False}]
    store.save(session)
    path = store.path(session.id)
    data = json.loads(path.read_text())
    data["detached"] = {"where": "nowhere"}
    path.write_text(json.dumps(data))
    w = Win(monkeypatch, server_box)
    try:
        pump()
        dock = w.dock
        assert dock.panels() == []
        tab = next(t for t in dock.all_tabs() if t.session.id == session.id)
        assert dock.tabs.indexOf(tab) >= 0
    finally:
        w.close()


AGENT_EVENTS = """
EVENTS = []

def activate(api):
    api.on_agent_event(lambda session, event: EVENTS.append((session, event.get("type"))))
"""


def test_e2e_agent_events_of_a_detached_conversation_reach_extensions(mw):
    from tests.test_extension_host import write_ext

    win, dock = mw.win, mw.dock
    mw.server_box[0].replies = [{"content": "Hello."}]
    write_ext("listener", AGENT_EVENTS)
    EX.set_enabled("user:listener", True)
    win.extension_host.reload()
    module = win.extension_host.module("user:listener")
    panel = dock.new_window()
    say(panel.tab, "hi")
    pump()
    sessions = {s for s, _t in module.EVENTS}
    assert sessions == {panel.tab.session.id}
    assert ("run_finished" in [t for _s, t in module.EVENTS])


def test_e2e_voice_follows_the_focused_conversation_in_the_window(mw):
    win, dock = mw.win, mw.dock
    win._focus_agent_action.trigger()
    pump()
    docked = dock.current_tab()
    panel = dock.new_window()
    pump()
    win.activateWindow()
    panel.tab.input.setFocus()
    pump()
    dock.voice_tab = None
    dock._on_voice_text("spoken")
    assert panel.tab.input.toPlainText() == "spoken"
    docked.input.setFocus()
    pump()
    dock._on_voice_text("again")
    assert docked.input.toPlainText() == "again"


def test_e2e_settings_saved_reach_a_detached_conversation(mw):
    win, dock = mw.win, mw.dock
    panel = dock.new_window()
    tab = panel.tab
    settings = AGS.AgentSettings.load()
    settings.allow_bypass = True
    settings.save()
    win.refresh_agent_settings()
    assert tab.mode_combo.findData("bypass") >= 0


def test_edge_close_all_in_the_dock_area_attaches_conversations_back_without_asking(
        mw, monkeypatch):
    win, dock = mw.win, mw.dock
    mw.server_box[0].replies = [{"content": "Kept."}]
    win._focus_agent_action.trigger()
    panel = dock.new_window()
    say(panel.tab, "question")
    tab = panel.tab
    pump()
    asked = []
    monkeypatch.setattr(QMessageBox, "question",
                        lambda *a, **k: asked.append(a) or QMessageBox.StandardButton.No)
    # "Close all panels in this area (reopen via View > Panels)": the
    # conversation goes back into the Agent dock, which closes with it.
    dock.titleBarWidget()._close_all()
    pump()
    assert asked == []
    assert sip.isdeleted(panel) and dock.panels() == []
    assert dock.tabs.indexOf(tab) >= 0 and not dock.isVisible()
    assert "Kept." in tab.transcript.toPlainText()


def test_e2e_a_panel_on_a_detached_workspace_comes_back_there_after_a_restart(
        home, monkeypatch, server_box):
    w = Win(monkeypatch, server_box)
    try:
        pump()
        win, dock = w.win, w.dock
        a, b = two_workspaces(win)
        panel = dock.new_window()
        panel.tab.input.setPlainText("draft")
        win.move_extension_panel(panel, b)
        pump()
        window = win.detach_workspace(b)
        pump()
        assert window is not None and window.isAncestorOf(panel) and panel.isVisible()
        sid = panel.tab.session.id
    finally:
        w.close()
    w = Win(monkeypatch, server_box)
    try:
        win, dock = w.win, w.dock
        assert win.restore_layout_on_start()
        pump()
        (panel,) = dock.panels()
        b = win.workspaces()[1]
        assert panel.tab.session.id == sid
        assert b.window is not None and b.window.isAncestorOf(panel)
    finally:
        w.close()


def test_edge_a_closed_focused_tab_does_not_break_switching_tabs(env):
    env.fake()
    dock = env.dock()
    first = dock.current_tab()
    second = dock.new_tab()
    dock._on_focus_changed(None, second.input)
    assert dock.focus_tab is second
    dock.close_tab(dock.tabs.indexOf(second))  # empty: no question
    pump()
    assert sip.isdeleted(second)
    third = dock.new_tab()
    dock.tabs.setCurrentWidget(first)  # currentChanged with a dead focus tab
    pump()
    assert dock.focus_tab is first
    dock._on_voice_text("heard")
    assert first.input.toPlainText() == "heard" and third.input.toPlainText() == ""


def test_edge_focus_in_a_dialog_of_the_dock_keeps_the_conversation(env):
    from PyQt6.QtWidgets import QDialog, QLineEdit

    env.fake()
    dock = env.dock()
    panel = dock.new_window()
    dock._on_focus_changed(None, panel.tab.input)
    dialog = QDialog(dock)  # a confirmation is a window of its own over the dock
    field = QLineEdit(dialog)
    dock._on_focus_changed(panel.tab.input, field)
    assert dock.focus_tab is panel.tab
    dialog.deleteLater()


def test_edge_the_panel_title_follows_the_conversation(env):
    env.fake({"content": "One."})
    dock = env.dock()
    panel = dock.new_window()
    say(panel.tab, "disk report")
    assert panel.tab.session.title == "disk report"
    assert panel.windowTitle() == "Agent: disk report"
    assert panel.titleBarWidget()._title_label.text() == "disk report"


def test_edge_attaching_the_only_pane_of_a_workspace_closes_the_workspace(mw):
    win, dock = mw.win, mw.dock
    panel = dock.new_window()
    pump()
    ws = win.move_extension_panel_to_new_workspace(panel)
    pump()
    assert ws in win.workspaces() and win.extension_panel_workspace(panel) is ws
    dock.attach_panel(panel)
    pump()
    assert ws not in win.workspaces()


def test_e2e_restore_last_session_keeps_the_live_panel_on_its_workspace(mw, monkeypatch):
    win, dock = mw.win, mw.dock
    mw.server_box[0].replies = [{"content": "Still here."}]
    a, b = two_workspaces(win)
    panel = dock.new_window()
    say(panel.tab, "question")
    tab = panel.tab
    win.move_extension_panel(panel, b)
    pump()
    win._save_session()
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: None)
    win._restore_session()  # File > Restore Last Session
    pump(0.2)
    assert dock.panels() == [panel] and panel.tab is tab and not sip.isdeleted(tab)
    b = win.workspaces()[1]
    assert win.extension_panel_workspace(panel) is b
    assert "Still here." in tab.transcript.toPlainText()
