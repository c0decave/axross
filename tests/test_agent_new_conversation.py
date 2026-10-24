"""New conversation in the Agent dock, then the next task typed on the keyboard.

The symptom: after "New conversation" the tab could not be used for the
next task, while a new tab (Ctrl+T) worked.

Reproduced offscreen with the real dock and the scripted fake LLM: a
click on "New conversation" left the keyboard focus on that button
(QPushButton takes the focus on a click); the task typed next and its
Ctrl+Enter went to the button, the task field stayed empty and nothing
was sent. Ctrl+T works because AgentDock.new_tab puts the focus into the
new tab's task field. The same happened after a click on Send or Stop:
Qt hands the focus of a button that is disabled to the next widget (the
tab bar, the microphone), so the next task was lost as well.

New conversation also left the old conversation behind: its agent was
dropped before _close_agent() could close it (Agent.close releases the
remote connections the agent opened), and the old plan and run status
stayed shown.

Every test types like a person: each key goes to the widget that has
the focus at that moment (QApplication.focusWidget()), buttons are
clicked with the mouse.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.agent_session import AgentSession  # noqa: E402
from tests.test_agent_loop import _call  # noqa: E402
from tests.test_agent_tabs import APP, Env, wait_idle  # noqa: E402,F401


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    yield e
    e.close()


def pump(seconds: float = 0.05) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.005)


def wait_until(cond, seconds: float = 10.0) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        if cond():
            return
        time.sleep(0.01)
    raise AssertionError("condition not reached")


def keyboard(text: str, *, send: bool = True) -> None:
    """Type *text* (and Ctrl+Enter): every key to whatever has the focus now."""
    for ch in text:
        QTest.keyClick(QApplication.focusWidget(), ch)
    if send:
        QTest.keyClick(QApplication.focusWidget(), Qt.Key.Key_Return,
                       Qt.KeyboardModifier.ControlModifier)


def click(button) -> None:
    QTest.mouseClick(button, Qt.MouseButton.LeftButton)
    pump()


def shown(env):
    dock = env.dock()
    dock.resize(800, 640)
    dock.show()
    dock.activateWindow()
    assert QTest.qWaitForWindowActive(dock)
    pump(0.1)
    return dock


def first_task(tab, text: str) -> None:
    """The first task as a person starts it: click into the field, type, Ctrl+Enter."""
    QTest.mouseClick(tab.input.viewport(), Qt.MouseButton.LeftButton)
    keyboard(text)
    wait_idle(tab)


def user_texts(request) -> list[str]:
    return [m["content"] for m in request["messages"] if m["role"] == "user"]


# -- happy ----------------------------------------------------------------------


def test_happy_three_new_conversations_each_take_the_typed_task(env):
    server = env.fake({"content": "answer 0"}, {"content": "answer 1"}, {"content": "answer 2"},
                      {"content": "answer 3"})
    tab = shown(env).current_tab()
    first_task(tab, "task 0")
    assert "answer 0" in tab.transcript.toPlainText()
    for i in (1, 2, 3):
        click(tab.new_button)
        assert QApplication.focusWidget() is tab.input
        assert tab.transcript.toPlainText() == "" and tab.session.messages == []
        keyboard(f"task {i}")
        wait_idle(tab)
        assert len(server.requests) == i + 1
        assert tab.transcript.toPlainText() == f"You: task {i}\nAgent: answer {i}"
        # A new conversation: the model sees only the new task.
        assert [t.endswith(f"task {i}") for t in user_texts(server.requests[-1])] == [True]


def test_happy_a_task_sent_with_the_send_button_leaves_the_field_ready(env):
    server = env.fake({"content": "first"}, {"content": "second"})
    tab = shown(env).current_tab()
    QTest.mouseClick(tab.input.viewport(), Qt.MouseButton.LeftButton)
    keyboard("task one", send=False)
    click(tab.send_button)
    assert QApplication.focusWidget() is tab.input  # also while it runs
    wait_idle(tab)
    assert QApplication.focusWidget() is tab.input
    keyboard("task two")
    wait_idle(tab)
    assert len(server.requests) == 2
    assert "Agent: second" in tab.transcript.toPlainText()


def test_happy_new_conversation_closes_the_old_agent(env, monkeypatch):
    from core import agent as A

    closed = []
    monkeypatch.setattr(A.Agent, "close", lambda self: closed.append(self))
    env.fake({"content": "one"}, {"content": "two"})
    tab = shown(env).current_tab()
    first_task(tab, "task one")
    old = tab._agent
    assert old is not None and closed == []
    click(tab.new_button)
    assert closed == [old] and tab._agent is None
    keyboard("task two")
    wait_idle(tab)
    assert tab._agent is not None and tab._agent is not old and closed == [old]



# -- sad ------------------------------------------------------------------------


def test_sad_new_conversation_while_running_waits_then_works(env):
    server = env.fake({"content": "slow", "_delay": 1.0}, {"content": "after"})
    tab = shown(env).current_tab()
    QTest.mouseClick(tab.input.viewport(), Qt.MouseButton.LeftButton)
    keyboard("slow task")
    wait_until(tab.busy)
    assert not tab.new_button.isEnabled()
    click(tab.new_button)  # disabled: the running conversation stays
    assert tab.busy() and "slow task" in tab.transcript.toPlainText()
    wait_idle(tab)
    assert "Agent: slow" in tab.transcript.toPlainText()
    click(tab.new_button)
    assert tab.transcript.toPlainText() == ""
    keyboard("next task")
    wait_idle(tab)
    assert len(server.requests) == 2
    assert tab.transcript.toPlainText() == "You: next task\nAgent: after"


def test_sad_after_an_error_answer_new_conversation_works(env):
    server = env.fake(500, {"content": "recovered"})
    tab = shown(env).current_tab()
    first_task(tab, "fails")
    assert "HTTP 500" in tab.transcript.toPlainText()
    click(tab.new_button)
    keyboard("again")
    wait_idle(tab)
    assert len(server.requests) == 2
    assert tab.transcript.toPlainText() == "You: again\nAgent: recovered"


def test_sad_after_stop_new_conversation_works(env):
    loop = {"tool_calls": [_call("stat", {"path": str(env.root)})], "_delay": 0.2}
    server = env.fake(*[loop] * 30)
    tab = shown(env).current_tab()
    QTest.mouseClick(tab.input.viewport(), Qt.MouseButton.LeftButton)
    keyboard("loop")
    wait_until(lambda: tab._tool_calls >= 1)
    click(tab.stop_button)
    wait_idle(tab)
    assert "Stopped." in tab.transcript.toPlainText()
    # The Stop button that had the focus is disabled now: the field has it.
    assert QApplication.focusWidget() is tab.input
    server.replies[:] = [{"content": "fresh"}]
    click(tab.new_button)
    keyboard("fresh task")
    wait_idle(tab)
    assert tab.transcript.toPlainText() == "You: fresh task\nAgent: fresh"


# -- edge -----------------------------------------------------------------------


def test_edge_new_conversation_clears_the_old_plan_and_status(env):
    plan = {"tool_calls": [_call("update_plan", {"steps": [{"text": "old step", "done": False}]})]}
    env.fake(plan, {"content": "planned"})
    tab = shown(env).current_tab()
    first_task(tab, "make a plan")
    assert not tab.plan_label.isHidden() and "old step" in tab.plan_label.text()
    assert tab.status_label.text().startswith("Done")
    click(tab.new_button)
    assert tab.plan_label.isHidden() and tab.plan_label.text() == ""
    assert tab.status_label.text() == ""


def test_edge_a_finishing_run_does_not_take_the_focus_from_a_field(env):
    env.fake({"content": "slow", "_delay": 0.5})
    tab = shown(env).current_tab()
    QTest.mouseClick(tab.input.viewport(), Qt.MouseButton.LeftButton)
    keyboard("slow task")
    wait_until(tab.busy)
    tab.root_edit.setFocus()  # the user types a folder meanwhile
    pump()
    wait_idle(tab)
    assert QApplication.focusWidget() is tab.root_edit


def test_edge_a_topic_after_new_conversation_is_sent(env):
    server = env.fake({"content": "one"}, {"content": "topic answer"})
    tab = shown(env).current_tab()
    first_task(tab, "task one")
    click(tab.new_button)
    tab._fill_topics_menu()
    topic = next(a for a in tab.topics_menu.actions() if a.text() and "\t/" in a.text())
    topic.trigger()
    pump()
    assert tab.input.toPlainText().strip()
    keyboard("", send=True)
    wait_idle(tab)
    assert len(server.requests) == 2 and "Agent: topic answer" in tab.transcript.toPlainText()


def test_edge_a_restored_conversation_can_be_replaced(env):
    from core.agent_session import SessionStore

    old = AgentSession(title="old task", folder=str(env.root),
                       transcript=[{"who": "You:", "text": "old task"},
                                   {"who": "Agent:", "text": "old answer"}],
                       messages=[{"role": "user", "content": "old task"},
                                 {"role": "assistant", "content": "old answer"}])
    SessionStore(env.store_dir).save(old)
    server = env.fake({"content": "new answer"})
    tab = shown(env).current_tab()
    assert tab.session.id == old.id and "old answer" in tab.transcript.toPlainText()
    click(tab.new_button)
    assert QApplication.focusWidget() is tab.input
    keyboard("new task")
    wait_idle(tab)
    assert user_texts(server.requests[0])[-1].endswith("new task")
    assert "old task" not in str(server.requests[0]["messages"])
    saved = SessionStore(env.store_dir).all()
    assert [s.id for s in saved] == [old.id]
    assert [e["text"] for e in saved[0].transcript] == ["new task", "new answer"]


def test_edge_ctrl_t_still_opens_a_tab_ready_for_typing(env):
    server = env.fake({"content": "one"}, {"content": "two"})
    dock = shown(env)
    tab = dock.current_tab()
    first_task(tab, "task one")
    click(tab.new_button)
    QTest.keyClick(QApplication.focusWidget(), Qt.Key.Key_T, Qt.KeyboardModifier.ControlModifier)
    pump()
    other = dock.current_tab()
    assert other is not tab and QApplication.focusWidget() is other.input
    keyboard("task two")
    wait_idle(other)
    assert len(server.requests) == 2 and "Agent: two" in other.transcript.toPlainText()


def test_edge_in_the_main_window_new_conversation_takes_the_typed_task(env, tmp_path, monkeypatch):
    """The same in the real MainWindow: the dock's focus is the window's."""
    from core import llm_profiles as LP

    server = env.fake({"content": "one"}, {"content": "two"}, {"content": "three"})
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(LP.LLMSettings, "load", classmethod(lambda cls, *a, **k: env.llm))
    from ui.main_window import MainWindow

    win = MainWindow()
    try:
        win._reconnect_timer.stop()
        win.resize(1300, 800)
        win.show()
        win.activateWindow()
        assert QTest.qWaitForWindowActive(win)
        win._focus_agent()
        pump(0.2)
        tab = win._agent_dock.current_tab()
        assert QApplication.focusWidget() is tab.input
        keyboard("task one", send=False)
        click(tab.send_button)
        wait_idle(tab)
        for i, word in ((2, "two"), (3, "three")):
            click(tab.new_button)
            assert QApplication.focusWidget() is tab.input
            keyboard(f"task {word}")
            wait_idle(tab)
            assert len(server.requests) == i
            assert tab.transcript.toPlainText() == f"You: task {word}\nAgent: {word}"
    finally:
        win._agent_dock.shutdown()
        win.close()
        win.deleteLater()
        pump(0.1)
