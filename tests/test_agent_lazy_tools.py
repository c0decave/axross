"""An agent builds its tools at its first task, on the task's thread.

Measured 2026-10-25 (perf/llm-agent): the first Send of a session blocked the
GUI thread for 88-108 ms, because AgentTab._send constructed core.agent.Agent
there and Agent() built its MCP tools at once - importing core.archive (py7zr)
and core.mcp_server (jsonschema) the first time. Now Agent() only notes the
config; the tools are built on first use, which is the task's run thread.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import agent as A  # noqa: E402
from core.llm_profiles import LLMProfile  # noqa: E402
from tests.test_agent_loop import _call, _no_proxy, fake  # noqa: E402,F401


def _config(server, root, **kw):
    profile = LLMProfile(name="local", provider="lmstudio", endpoint=server.url, model="tiny")
    return A.AgentConfig(profile=profile, root=str(root), **kw)


@pytest.fixture
def builds(monkeypatch):
    """Every build_tools call: the thread it ran on."""
    seen: list[threading.Thread] = []
    original = A.build_tools

    def counted(*args, **kwargs):
        seen.append(threading.current_thread())
        return original(*args, **kwargs)

    monkeypatch.setattr(A, "build_tools", counted)
    return seen


# -- happy ------------------------------------------------------------------------------------


def test_happy_a_new_agent_builds_no_tools_until_its_first_task(fake, tmp_path, builds):
    (tmp_path / "a.txt").write_text("hi\n")
    server = fake({"tool_calls": [_call("list_dir", {"path": str(tmp_path)})]},
                  {"content": "One file."}, {"content": "Still one."})
    agent = A.Agent(_config(server, tmp_path))
    assert builds == [], "constructing an agent builds nothing"
    assert agent.run("what is here?").answer == "One file."
    assert len(builds) == 1
    assert "a.txt" in server.requests[1]["messages"][-1]["content"]
    offered = {t["function"]["name"] for t in server.requests[0]["tools"]}
    assert {"list_dir", "read_file", "stat"} <= offered
    agent.run("and now?")
    assert len(builds) == 1, "built once per agent"


def test_happy_the_tools_are_there_when_asked_for(fake, tmp_path, builds):
    server = fake()
    agent = A.Agent(_config(server, tmp_path, allow_write=True))
    names = {t.name for t in agent._tool_list}
    assert {"read_file", "write_file"} <= names
    assert set(agent._tools) == names
    assert len(builds) == 1


def test_happy_e2e_the_first_send_of_a_tab_builds_the_tools_off_the_gui_thread(
        monkeypatch, tmp_path, builds):
    from PyQt6.QtWidgets import QApplication

    from tests.test_agent_tabs import Env, say

    QApplication.instance() or QApplication([])
    env = Env(tmp_path)
    try:
        (env.root / "notes.txt").write_text("Friday\n")
        env.fake({"tool_calls": [_call("read_file", {"path": str(env.root / "notes.txt"),
                                                    "encoding": "text"})]},
                 {"content": "On Friday."})
        dock = env.dock()
        tab = dock.current_tab()
        say(tab, "when?")
        assert "On Friday." in tab.transcript.toPlainText()
        assert "read_file: ok" in tab.transcript.toPlainText()
        assert builds, "the tools were built"
        assert all(t is not threading.main_thread() for t in builds), \
            "never on the GUI thread"
    finally:
        env.close()


# -- sad --------------------------------------------------------------------------------------


def test_sad_tools_that_cannot_be_built_fail_the_task_not_the_constructor(
        fake, tmp_path, monkeypatch):
    def broken(*_a, **_k):
        raise ValueError("extra_roots need a root")

    monkeypatch.setattr(A, "build_tools", broken)
    server = fake({"content": "never"})
    agent = A.Agent(_config(server, tmp_path))  # no error here
    with pytest.raises(ValueError, match="extra_roots need a root"):
        agent.run("go")
    assert server.requests == [], "nothing was sent"


def test_sad_e2e_a_tab_says_why_its_tools_could_not_be_built(monkeypatch, tmp_path):
    from PyQt6.QtWidgets import QApplication

    from tests.test_agent_tabs import Env, say

    QApplication.instance() or QApplication([])

    def broken(*_a, **_k):
        raise ValueError("the tools are broken")

    monkeypatch.setattr(A, "build_tools", broken)
    env = Env(tmp_path)
    try:
        server = env.fake({"content": "never"})
        dock = env.dock()
        tab = dock.current_tab()
        say(tab, "go")
        assert "ValueError: the tools are broken" in tab.transcript.toPlainText()
        assert not tab.busy() and tab.send_button.isEnabled()
        assert server.requests == []
    finally:
        env.close()


# -- edge -------------------------------------------------------------------------------------


def test_edge_two_threads_asking_at_once_build_once(fake, tmp_path, monkeypatch):
    original = A.build_tools
    calls: list[int] = []
    gate = threading.Event()

    def slow(*args, **kwargs):
        calls.append(1)
        gate.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(A, "build_tools", slow)
    agent = A.Agent(_config(fake(), tmp_path))
    got: list = []
    threads = [threading.Thread(target=lambda: got.append(agent._tools)) for _ in range(2)]
    for t in threads:
        t.start()
    time.sleep(0.1)
    gate.set()
    for t in threads:
        t.join(5)
    assert len(calls) == 1
    assert len(got) == 2 and got[0] is got[1]


def test_edge_a_changed_tool_table_stays_changed(fake, tmp_path):
    agent = A.Agent(_config(fake(), tmp_path))
    marker = object()
    agent._tools["marker"] = marker
    assert agent._tools["marker"] is marker
    replaced = {"only": marker}
    agent._tools = replaced
    assert agent._tools is replaced
    tools = list(agent._tool_list)
    agent._tool_list = tools[:1]
    assert agent._tool_list == tools[:1]


def test_edge_a_cancelled_task_before_the_first_step_builds_nothing(fake, tmp_path, builds):
    server = fake({"content": "never"})
    agent = A.Agent(_config(server, tmp_path))
    agent.cancel.set()
    result = agent.run("go")
    assert result.stopped == "cancelled"
    assert server.requests == []
    assert builds == []
