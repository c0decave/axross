"""Topics (prepared operative tasks) and the agent's conversation tools:
ask_user (a question back to the user) and update_plan (a checklist the
tab shows). Both are axross's own and work on every sandbox level."""

from __future__ import annotations

import pytest

from core import agent_sandbox as SB
from core.agent_topics import BUILTIN_TOPICS, Topic
from tests.test_agent_loop import _call, _tool_messages
from tests.test_agent_tabs import Env, say


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    yield e
    e.close()


def _topic(title):
    return next(t for t in BUILTIN_TOPICS if t.title == title)


# -- topics --------------------------------------------------------------------


def test_happy_the_operative_topics_are_there():
    titles = {t.title for t in BUILTIN_TOPICS}
    assert {"System inventory", "Install or update software", "Service status", "Collect logs",
            "Disk usage", "Read data out"} <= titles
    assert _topic("Install or update software").mode == "plan"


def test_happy_a_topic_fills_the_task_with_the_folder(env):
    env.fake({"content": "ok"})
    tab = env.dock().current_tab()
    tab.use_topic(_topic("Disk usage"))
    assert str(env.root) in tab.input.toPlainText()
    titles = [a.text() for a in (tab._fill_topics_menu() or tab.topics_menu.actions()) if a.text()]
    assert "System inventory" in titles


def test_happy_an_install_topic_switches_to_plan(env):
    env.fake({"content": "ok"})
    tab = env.dock().current_tab()
    tab.use_topic(_topic("Install or update software"))
    assert tab.mode_combo.currentData() == "plan"
    assert "remote commands" in tab.transcript.toPlainText()  # what it still needs


def test_edge_braces_in_a_task_stay_as_they_are():
    topic = Topic("x", "awk '{print $1}' in {folder} on {backend}")
    assert topic.render("/srv", "") == "awk '{print $1}' in /srv on the remote host"


# -- ask_user / update_plan ------------------------------------------------------


def test_happy_the_agent_asks_the_user_and_gets_the_answer(env):
    server = env.fake(
        {"tool_calls": [_call("ask_user", {"question": "Which colour?"})]},
        {"content": "Blue it is."},
    )
    dock = env.dock()
    asked = []
    dock.ask_user = lambda question: asked.append(question) or "blue"
    tab = dock.current_tab()
    say(tab, "paint it")
    assert asked == ["Which colour?"]
    assert _tool_messages(server.requests[1])[0]["content"] == "blue"
    assert "Which colour?" in tab.transcript.toPlainText()


def test_happy_the_plan_is_shown(env):
    steps = [
        {"text": "Look at the disks", "done": True},
        {"text": "Write the report", "done": False},
    ]
    env.fake({"tool_calls": [_call("update_plan", {"steps": steps})]}, {"content": "planned"})
    tab = env.dock().current_tab()
    say(tab, "plan")
    assert (
        "☑ Look at the disks" in tab.plan_label.text()
        and "☐ Write the report" in tab.plan_label.text()
    )
    assert tab.plan_label.isVisibleTo(tab)


def test_sad_no_answer_is_said_to_the_model(env):
    server = env.fake({"tool_calls": [_call("ask_user", {"question": "?"})]}, {"content": "ok"})
    dock = env.dock()
    dock.ask_user = lambda question: None
    say(dock.current_tab(), "ask me")
    assert "did not answer" in _tool_messages(server.requests[1])[0]["content"]


def test_edge_the_conversation_tools_work_in_a_paranoid_sandbox(env):
    env.settings.sandboxes = [SB.SandboxProfile(name="P", level="paranoid")]
    server = env.fake({"tool_calls": [_call("ask_user", {"question": "Sure?"})]}, {"content": "ok"})
    dock = env.dock()
    dock.ask_user = lambda question: "yes"
    tab = dock.current_tab()
    tab.sandbox_combo.setCurrentIndex(tab.sandbox_combo.findData("P"))
    original = SB.SandboxedAgent.__init__

    def plain(
        self, *args, **kw
    ):  # the worker process without bubblewrap: same channel, same checks
        kw["command"] = SB.worker_argv()
        original(self, *args, **kw)

    SB.SandboxedAgent.__init__ = plain
    try:
        say(tab, "ask")
    finally:
        SB.SandboxedAgent.__init__ = original
    assert _tool_messages(server.requests[1])[0]["content"] == "yes"
