"""The agent through extensions: an extension can start agent tasks, give
the agent tools of its own, add topics (prepared tasks) and follow every
agent event. And the bundled "Agent Stats" extension: a small window that
can be moved anywhere and counts what the agent does."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt  # noqa: E402

from core import extensions as EX  # noqa: E402
from core import llm_profiles as LP  # noqa: E402
from tests.test_agent_loop import _call, _Fake, _tool_messages  # noqa: E402
from tests.test_extension_host import pump, wait_until, write_ext  # noqa: E402


@pytest.fixture(autouse=True)
def own_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    for name in (
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
    ):
        monkeypatch.delenv(name, raising=False)


class _Env:
    def __init__(self, win):
        self.win = win
        self.servers = []
        self.asked = []
        self.answer = True
        dock = win._agent_dock
        dock.key_lookup = lambda name: ""
        dock.confirm_remote = lambda p, h: True
        dock.confirm_call = lambda n, a: self.asked.append(n) or self.answer

    def fake(self, *replies):
        server = _Fake(replies)
        self.servers.append(server)
        llm = LP.LLMSettings([LP.LLMProfile(name="local", provider="lmstudio", endpoint=server.url,
                                            model="tiny")], "local")
        self.win._agent_dock.llm_settings = lambda: llm
        for tab in self.win._agent_dock.all_tabs():
            tab.refresh_choices()
        return server

    def load(self, name, body):
        write_ext(name, body)
        EX.set_enabled(f"user:{name}", True)
        self.win.extension_host.reload()
        assert self.win.extension_host.error(f"user:{name}") == ""
        return self.win.extension_host.module(f"user:{name}")


@pytest.fixture
def env(request):
    from core import agent_settings as AGS
    from ui.main_window import MainWindow

    # axross functions (extension tools among them) are off by default
    # (core.agent_access); these tests are about the tools, so on - except
    # where a test says "closed".
    if "closed" not in request.node.name:
        AGS.AgentSettings(access=AGS.Access(axross_functions=True)).save()
    win = MainWindow()
    win._reconnect_timer.stop()
    win.show()
    pump()
    e = _Env(win)
    yield e
    win._agent_dock.shutdown()
    win.close()
    win.deleteLater()
    pump()
    for server in e.servers:
        server.close()


def _idle(dock):
    assert wait_until(lambda: not dock.busy(), timeout=30)
    pump(0.1)


TOOLED = """
CALLS = []
DONE = []
EVENTS = []

def activate(api):
    api.add_agent_tool("echo", "Echo the text back.",
                       lambda args: CALLS.append(args) or {"echo": args["text"]},
                       parameters={"text": {"type": "string"}}, required=("text",))
    api.add_agent_tool("wipe", "Delete everything.",
                       lambda args: CALLS.append(("wipe", args)) or "wiped", writes=True)
    api.add_agent_tool("boom", "Fails.", lambda args: 1 / 0)
    api.add_agent_topic("Disk check", "Check the disk usage of {folder}.", description="df and du")
    api.on_agent_event(lambda session, event: EVENTS.append((session, event.get("type"))))
    api.add_menu_action(
        "Run it", lambda: api.run_agent("echo hello", on_done=lambda a, e: DONE.append((a, e)))
    )
"""


# -- happy ---------------------------------------------------------------------


def test_happy_an_extension_runs_the_agent_with_its_own_tool(env):
    server = env.fake(
        {"tool_calls": [_call("ext_tooled__echo", {"text": "hello"})]}, {"content": "It echoed."}
    )
    module = env.load("tooled", TOOLED)
    dock = env.win._agent_dock
    session_id = module.api_session = None
    next(a for a in env.win.extensions_menu.actions() if a.text() == "Run it").trigger()
    _idle(dock)
    assert module.CALLS == [{"text": "hello"}]
    assert module.DONE == [("It echoed.", "")]
    assert json.loads(_tool_messages(server.requests[1])[0]["content"]) == {"echo": "hello"}
    tab = dock.current_tab()
    assert "ext:user:tooled" in tab.session.groups and session_id is None


def test_sad_closed_by_default_the_extensions_tool_is_not_offered(env):
    server = env.fake(
        {"tool_calls": [_call("ext_tooled__echo", {"text": "hello"})]}, {"content": "no"}
    )
    module = env.load("tooled", TOOLED)
    next(a for a in env.win.extensions_menu.actions() if a.text() == "Run it").trigger()
    _idle(env.win._agent_dock)
    assert module.CALLS == []
    assert "ext_tooled__echo" not in {
        t["function"]["name"] for t in server.requests[0].get("tools", [])
    }
    assert "not available" in _tool_messages(server.requests[1])[0]["content"]


def test_happy_an_extension_sees_every_agent_event(env):
    env.fake({"tool_calls": [_call("ext_tooled__echo", {"text": "x"})]}, {"content": "ok"})
    module = env.load("tooled", TOOLED)
    next(a for a in env.win.extensions_menu.actions() if a.text() == "Run it").trigger()
    _idle(env.win._agent_dock)
    kinds = [k for _s, k in module.EVENTS]
    assert kinds[0] == "run_started" and "tool_call" in kinds and kinds[-1] == "run_finished"
    assert len({s for s, _k in module.EVENTS}) == 1


def test_happy_a_topic_fills_the_task(env):
    env.fake({"content": "ok"})
    env.load("tooled", TOOLED)
    tab = env.win._agent_dock.current_tab()
    titles = [t.title for t in tab.dock.topics()]
    assert "Disk check" in titles
    tab.use_topic(next(t for t in tab.dock.topics() if t.title == "Disk check"))
    assert tab.input.toPlainText() == f"Check the disk usage of {tab.root_edit.text()}."


def test_happy_open_agent_tab_prefills_without_running(env):
    server = env.fake({"content": "never"})
    module = env.load(
        "opener",
        """
SID = []
def activate(api):
    api.add_menu_action(
        "Open", lambda: SID.append(api.open_agent_tab("look at this", folder="/srv"))
    )
""",
    )
    before = len(env.win._agent_dock.all_tabs())
    next(a for a in env.win.extensions_menu.actions() if a.text() == "Open").trigger()
    pump(0.2)
    dock = env.win._agent_dock
    assert len(dock.all_tabs()) == before + 1
    tab = dock.current_tab()
    assert tab.input.toPlainText() == "look at this" and tab.root_edit.text() == "/srv"
    assert module.SID == [tab.session.id] and server.requests == []


# -- sad -----------------------------------------------------------------------


def test_sad_a_failing_tool_is_an_error_for_the_model_not_a_crash(env):
    server = env.fake({"tool_calls": [_call("ext_tooled__boom", {})]}, {"content": "it failed"})
    module = env.load("tooled", TOOLED)
    env.win._agent_dock.current_tab()
    module_api_run = next(a for a in env.win.extensions_menu.actions() if a.text() == "Run it")
    module_api_run.trigger()
    _idle(env.win._agent_dock)
    content = _tool_messages(server.requests[1])[0]["content"]
    assert content.startswith("error") and "ZeroDivisionError" in content
    assert module.DONE == [("it failed", "")]


def test_sad_a_changing_tool_asks_and_a_no_stops_it(env):
    env.fake({"tool_calls": [_call("ext_tooled__wipe", {})]}, {"content": "not allowed"})
    module = env.load("tooled", TOOLED)
    env.answer = False
    next(a for a in env.win.extensions_menu.actions() if a.text() == "Run it").trigger()
    _idle(env.win._agent_dock)
    assert env.asked == ["ext_tooled__wipe"]
    assert not any(c[0] == "wipe" for c in module.CALLS if isinstance(c, tuple))


def test_sad_bad_registrations_are_refused(env):
    write_ext("bad", """
def activate(api):
    api.add_agent_tool("no spaces allowed", "x", lambda a: 1)
""")
    EX.set_enabled("user:bad", True)
    env.win.extension_host.reload()
    assert "name" in env.win.extension_host.error("user:bad")


# -- edge ----------------------------------------------------------------------


def test_edge_switching_an_extension_off_takes_its_tools_and_topics(env):
    env.fake({"content": "ok"})
    env.load("tooled", TOOLED)
    dock = env.win._agent_dock
    tab = dock.current_tab()
    assert "ext:user:tooled" in [tab.groups.item(i).text() for i in range(tab.groups.count())]
    env.win.extension_host.set_enabled("user:tooled", False)
    pump(0.1)
    assert "ext:user:tooled" not in [tab.groups.item(i).text() for i in range(tab.groups.count())]
    assert "Disk check" not in [t.title for t in dock.topics()]
    assert dock.extension_tools(["user:tooled"]) == []


def test_edge_the_stats_window_counts_and_moves(env):
    env.fake({"tool_calls": [_call("read_file", {"path": "/nonexistent/x", "encoding": "text"})]},
             {"content": "done"})
    EX.set_enabled("bundled:agent_stats", True)
    env.win.extension_host.reload()
    host = env.win.extension_host
    assert host.error("bundled:agent_stats") == ""
    module = host.module("bundled:agent_stats")
    window = module.WINDOW
    assert window.windowFlags() & Qt.WindowType.Tool
    assert window.windowFlags() & Qt.WindowType.WindowStaysOnTopHint
    next(a for a in env.win.extensions_menu.actions() if a.text() == "Agent Stats").trigger()
    pump(0.1)
    assert window.isVisible()
    tab = env.win._agent_dock.current_tab()
    tab.input.setPlainText("read it")
    tab.send()
    _idle(env.win._agent_dock)
    stats = window.stats()
    assert stats["runs"] == 1 and stats["tool_calls"] == 1 and stats["errors"] == 1
    assert stats["answers"] == 1
    window.move(40, 50)
    pump(0.05)
    assert (window.x(), window.y()) == (40, 50)
    env.win.extension_host.set_enabled("bundled:agent_stats", False)
    pump(0.1)
    from PyQt6 import sip

    assert module.WINDOW is None and (sip.isdeleted(window) or not window.isVisible())


def test_edge_a_tool_held_by_a_running_task_stops_with_its_extension(env):
    env.fake({"content": "ok"})
    env.load("tooled", TOOLED)
    (tool,) = [
        t for t in env.win.extension_host.agent_tools(["user:tooled"]) if t.name.endswith("__echo")
    ]
    assert tool.call({"text": "a"})[0] == "ok"
    env.win.extension_host.set_enabled("user:tooled", False)
    outcome, text = tool.call({"text": "a"})
    assert outcome == "error" and "switched off" in text
