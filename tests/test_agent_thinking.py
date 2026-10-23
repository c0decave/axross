"""The Agent dock tells a model's thinking from its answer.

Reported with Qwen on a MacBook (LM Studio / MLX): in the Agent
dock's transcript the thinking could not be told from the answer, and it
could not be collapsed or expanded.

Measured against that LM Studio (qwen3.6-35b-a3b-mlx@4bit and
qwen3.8-27b-mlx@8bit, 2026-10-23): every answer carries its thinking in
``reasoning_content`` beside ``content`` - also the steps that call a tool
(``content: "\\n\\n"``). core.agent read ``content`` only and used
``reasoning_content`` just when ``content`` was empty, then as the answer
itself. Other servers (llama.cpp ``--reasoning-format none``, LM Studio
without "separate reasoning_content") send it inline as
``<think>...</think>`` in ``content``, which went into the transcript as
the answer.

Now every message's thinking is a "reasoning" event, shown as a grey,
italic "Thinking" block collapsed to one line, which a click opens and
closes; the answer stays a normal line and is all that is spoken.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt, QUrl  # noqa: E402
from PyQt6.QtGui import QTextCursor, QTextDocument  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import agent as A  # noqa: E402
from core.agent_session import AgentSession, SessionStore  # noqa: E402
from core.llm_profiles import LLMProfile  # noqa: E402
from tests.test_agent_loop import _call, _no_proxy, fake  # noqa: E402,F401
from tests.test_agent_tabs import env, say  # noqa: E402,F401

APP = QApplication.instance() or QApplication([])

LONG_THINKING = (
    "The user asks what the folder holds.\n"
    "I should call list_dir first.\n"
    "Then count the files and answer briefly."
)


def _agent(server, root):
    profile = LLMProfile(name="local", provider="lmstudio", endpoint=server.url, model="tiny")
    events: list[dict] = []
    agent = A.Agent(A.AgentConfig(profile=profile, root=str(root)), on_event=events.append)
    return agent, events


def _kinds(events):
    return [e["type"] for e in events if e["type"] in ("reasoning", "assistant", "notice")]


# -- core.agent.split_reasoning ---------------------------------------------------------------


def test_happy_reasoning_content_beside_content_is_split():
    assert A.split_reasoning({"content": "\n\n17 times 3 equals 51.",
                              "reasoning_content": "17*3 = 51.\n"}) == \
        ("17*3 = 51.", "\n\n17 times 3 equals 51.")


def test_happy_the_reasoning_field_of_ollama_and_vllm_is_split_too():
    assert A.split_reasoning({"content": "Two.", "reasoning": "count them"}) == \
        ("count them", "Two.")


def test_happy_inline_think_tags_are_split_out_of_the_content():
    assert A.split_reasoning({"content": "<think>\nadd them\n</think>\n\nIt is 5."}) == \
        ("add them", "It is 5.")


def test_happy_a_closing_tag_alone_ends_the_thinking():
    # Qwen3 thinking models: the template opens <think> in the prompt, the
    # answer starts with the thinking and has only </think>.
    assert A.split_reasoning({"content": "add them\n</think>\n\nIt is 5."}) == \
        ("add them", "It is 5.")


def test_sad_no_reasoning_leaves_the_content_untouched():
    assert A.split_reasoning({"content": "\n\nOne file: a.txt"}) == ("", "\n\nOne file: a.txt")


def test_sad_odd_values_are_no_reasoning_and_no_answer():
    assert A.split_reasoning({"content": None, "reasoning_content": 7}) == ("", "")
    assert A.split_reasoning({"content": ["x"], "reasoning": None}) == ("", "")
    assert A.split_reasoning({}) == ("", "")


def test_edge_an_unclosed_think_block_is_all_thinking():
    # Cut at the output limit while still thinking.
    assert A.split_reasoning({"content": "<think>first I list the folder, then"}) == \
        ("first I list the folder, then", "")


def test_edge_both_kinds_of_reasoning_are_kept_in_order():
    assert A.split_reasoning({"content": "<think>inline</think>Answer",
                              "reasoning_content": "field"}) == ("field\n\ninline", "Answer")


def test_edge_think_tags_in_the_middle_of_an_answer_stay_text():
    text = "Use <think>...</think> tags to mark thinking."
    assert A.split_reasoning({"content": text}) == ("", text)


# -- the agent's events -------------------------------------------------------------------------


def test_happy_the_thinking_comes_before_the_answer_as_its_own_event(fake, tmp_path):
    server = fake({"content": "\n\n17 times 3 equals 51.", "reasoning_content": "17*3 = 51."})
    agent, events = _agent(server, tmp_path)
    result = agent.run("17*3?")
    assert _kinds(events) == ["reasoning", "assistant"]
    assert events[[e["type"] for e in events].index("reasoning")]["text"] == "17*3 = 51."
    assert result.answer == "\n\n17 times 3 equals 51."


def test_happy_the_thinking_of_a_tool_call_step_is_shown_too(fake, tmp_path):
    (tmp_path / "a.txt").write_text("a")
    server = fake({"content": "\n\n", "reasoning_content": "I list the folder.",
                   "tool_calls": [_call("list_dir", {"path": str(tmp_path)})]},
                  {"content": "One file.", "reasoning_content": "It holds a.txt."})
    agent, events = _agent(server, tmp_path)
    agent.run("what is here?")
    shown = [(e["type"], e.get("text")) for e in events
             if e["type"] in ("reasoning", "assistant", "tool_call")]
    assert shown == [("reasoning", "I list the folder."), ("tool_call", None),
                     ("reasoning", "It holds a.txt."), ("assistant", "One file.")]


def test_happy_inline_think_tags_never_reach_the_answer(fake, tmp_path):
    server = fake({"content": "<think>add them</think>\n\nIt is 5."})
    agent, events = _agent(server, tmp_path)
    result = agent.run("2+3?")
    assert result.answer == "It is 5."
    assert [e.get("text") for e in events if e["type"] == "assistant"] == ["It is 5."]
    assert [e.get("text") for e in events if e["type"] == "reasoning"] == ["add them"]


def test_sad_an_answer_only_in_the_thinking_is_still_shown_as_the_answer(fake, tmp_path):
    # The earlier fix (test_agent_stop_and_reasoning) stays: no Thinking
    # block then, the notice and the text as the answer.
    server = fake({"content": "<think>The folder holds a.txt.</think>"})
    agent, events = _agent(server, tmp_path)
    result = agent.run("what is here?")
    assert result.answer == "The folder holds a.txt."
    assert _kinds(events) == ["notice", "assistant"]


def test_edge_the_history_keeps_what_the_model_sent(fake, tmp_path):
    server = fake({"content": "<think>x</think>A", "reasoning_content": "r"}, {"content": "B"})
    agent, _events = _agent(server, tmp_path)
    agent.run("one")
    agent.run("two")
    assistant = [m for m in server.requests[1]["messages"] if m["role"] == "assistant"]
    assert assistant == [{"role": "assistant", "content": "<think>x</think>A"}]


def test_edge_a_sandbox_worker_may_report_its_thinking():
    from core.agent_sandbox import _MAX_EVENT_TEXT, _clean_event

    assert _clean_event({"type": "reasoning", "text": "plan"}) == \
        {"type": "reasoning", "text": "plan"}
    cut = _clean_event({"type": "reasoning", "text": "x" * (_MAX_EVENT_TEXT + 5), "extra": 1})
    assert cut == {"type": "reasoning", "text": "x" * _MAX_EVENT_TEXT}
    assert _clean_event({"type": "reasoning", "text": None}) == {"type": "reasoning", "text": ""}


def test_happy_a_sandboxed_agent_shows_its_thinking_too(fake, tmp_path):
    from core import agent_sandbox as SB

    server = fake({"content": "\n\nIt is 5.", "reasoning_content": "two plus three"})
    events: list[dict] = []
    profile = LLMProfile(name="local", provider="lmstudio", endpoint=server.url, model="tiny")
    agent = SB.SandboxedAgent(A.AgentConfig(profile=profile, root=str(tmp_path)), None,
                              on_event=events.append, command=SB.worker_argv())
    try:
        result = agent.run("2+3?")
    finally:
        agent.close()
    assert result.answer == "\n\nIt is 5."
    assert [(e["type"], e["text"]) for e in events if e["type"] in ("reasoning", "assistant")] \
        == [("reasoning", "two plus three"), ("assistant", "\n\nIt is 5.")]


# -- the session file ---------------------------------------------------------------------------


def test_happy_a_thinking_entry_survives_the_session_file(tmp_path):
    store = SessionStore(tmp_path)
    session = AgentSession(transcript=[
        {"who": "Thinking:", "text": "plan", "muted": True, "kind": "reasoning"},
        {"who": "Agent:", "text": "done", "muted": False},
    ])
    store.save(session)
    back = store.all()[0]
    assert back.transcript == [
        {"who": "Thinking:", "text": "plan", "muted": True, "kind": "reasoning"},
        {"who": "Agent:", "text": "done", "muted": False},
    ]


def test_sad_an_unknown_kind_is_a_normal_line(tmp_path):
    data = AgentSession(transcript=[]).to_dict()
    data["transcript"] = [{"who": "Agent:", "text": "x", "muted": False, "kind": "<b>evil"},
                          {"who": "Agent:", "text": "y", "kind": 3}]
    back = AgentSession.from_dict(data)
    assert back.transcript == [{"who": "Agent:", "text": "x", "muted": False},
                               {"who": "Agent:", "text": "y", "muted": False}]


def test_edge_a_session_of_an_older_axross_loads_unchanged(tmp_path):
    old = {"version": 1, "id": "a" * 32, "title": "t",
           "transcript": [{"who": "You:", "text": "hi", "muted": False},
                          {"who": "Agent:", "text": "hello", "muted": False}],
           "messages": []}
    (tmp_path / f"{'a' * 32}.json").write_text(json.dumps(old))
    back = SessionStore(tmp_path).all()[0]
    assert back.transcript == old["transcript"]


# -- the dock ---------------------------------------------------------------------------------


def _find(tab, text: str) -> QTextCursor:
    cursor = tab.transcript.document().find(text, 0, QTextDocument.FindFlag.FindCaseSensitively)
    assert not cursor.isNull(), (text, tab.transcript.toPlainText())
    return cursor


def _click(tab, text: str) -> None:
    """Click the middle of *text* in the transcript, as a person would."""
    cursor = _find(tab, text)
    middle = QTextCursor(cursor)
    middle.setPosition((cursor.selectionStart() + cursor.selectionEnd()) // 2)
    point = tab.transcript.cursorRect(middle).center()
    QTest.mouseClick(tab.transcript.viewport(), Qt.MouseButton.LeftButton, pos=point)
    APP.processEvents()


def _format_at(tab, text: str):
    cursor = _find(tab, text)
    probe = QTextCursor(cursor.document())
    probe.setPosition(cursor.selectionStart() + 1)
    return probe.charFormat()


def _shown_tab(env):
    dock = env.dock()
    dock.resize(700, 600)
    dock.show()
    APP.processEvents()
    return dock, dock.current_tab()


def test_happy_e2e_thinking_is_a_collapsed_grey_block_apart_from_the_answer(env):
    env.fake({"content": "\n\nThe folder is empty.", "reasoning_content": LONG_THINKING})
    _dock, tab = _shown_tab(env)
    say(tab, "what is here?")
    text = tab.transcript.toPlainText()
    assert "Thinking" in text and "The user asks what the folder holds." in text
    assert "Then count the files" not in text, "collapsed: one line only"
    assert "The folder is empty." in text
    thinking = _format_at(tab, "The user asks")
    assert thinking.fontItalic()
    assert thinking.foreground().color().name() == "#888888"
    answer = _format_at(tab, "The folder is empty.")
    assert not answer.fontItalic()
    assert answer.foreground().style() == Qt.BrushStyle.NoBrush
    # What is kept: the thinking marked as such, the answer as before.
    kinds = [(e["who"], e.get("kind")) for e in tab.session.transcript]
    assert ("Thinking:", "reasoning") in kinds and ("Agent:", None) in kinds


def test_happy_e2e_a_click_opens_and_closes_the_thinking(env):
    env.fake({"content": "Done.", "reasoning_content": LONG_THINKING})
    _dock, tab = _shown_tab(env)
    say(tab, "go")
    _click(tab, "Thinking")
    assert "Then count the files and answer briefly." in tab.transcript.toPlainText()
    assert "▾" in tab.transcript.toPlainText()
    _click(tab, "Thinking")
    assert "Then count the files" not in tab.transcript.toPlainText()
    assert "▸" in tab.transcript.toPlainText()
    assert "Done." in tab.transcript.toPlainText()


def test_happy_e2e_inline_think_tags_become_a_thinking_block(env):
    env.fake({"content": "<think>\nadd two and three\n</think>\n\nIt is 5."})
    _dock, tab = _shown_tab(env)
    say(tab, "2+3?")
    text = tab.transcript.toPlainText()
    assert "<think>" not in text and "</think>" not in text
    assert "add two and three" in text and "It is 5." in text
    assert [e["text"] for e in tab.session.transcript if e["who"] == "Agent:"] == ["It is 5."]


def test_sad_e2e_markup_in_the_thinking_stays_text_and_is_no_link(env):
    env.fake({"content": "ok", "reasoning_content": '<a href="axross-thinking:0">x</a><b>y'})
    _dock, tab = _shown_tab(env)
    say(tab, "go")
    _click(tab, "Thinking")
    assert '<a href="axross-thinking:0">x</a><b>y' in tab.transcript.toPlainText()
    # A link that names no block, or another scheme, changes nothing.
    before = tab.transcript.toPlainText()
    tab.transcript.anchorClicked.emit(QUrl("axross-thinking:99"))
    tab.transcript.anchorClicked.emit(QUrl("axross-thinking:x"))
    tab.transcript.anchorClicked.emit(QUrl("https://example.com"))
    APP.processEvents()
    assert tab.transcript.toPlainText() == before


def test_edge_e2e_a_kept_tab_comes_back_with_its_thinking_collapsed(env):
    env.fake({"content": "Done.", "reasoning_content": LONG_THINKING})
    dock, tab = _shown_tab(env)
    say(tab, "go")
    _click(tab, "Thinking")  # opened before the restart
    dock.shutdown()
    again = env.dock()
    restored = again.current_tab()
    text = restored.transcript.toPlainText()
    assert "Thinking" in text and "The user asks what the folder holds." in text
    assert "Then count the files" not in text
    assert "Done." in text


def test_edge_e2e_the_thinking_is_not_spoken_and_counts_no_answer(env):
    env.fake({"content": "Short answer.", "reasoning_content": LONG_THINKING})
    _dock, tab = _shown_tab(env)
    spoken: list[str] = []
    tab.voice.speak_answer = lambda text: spoken.append(text) or False
    say(tab, "go")
    assert spoken == ["Short answer."]
    assert "1 answers" in tab.status_label.text()


def test_edge_a_thinking_block_keeps_the_scroll_position_when_toggled(env):
    env.fake(*[{"content": f"answer {i}", "reasoning_content": LONG_THINKING}
               for i in range(25)])
    _dock, tab = _shown_tab(env)
    for i in range(25):
        say(tab, f"q{i}")
    bar = tab.transcript.verticalScrollBar()
    assert bar.maximum() > 0
    bar.setValue(bar.maximum())
    APP.processEvents()
    tab.toggle_reasoning(len(tab._entries) - 2)
    APP.processEvents()
    assert bar.value() == bar.maximum(), "the end of the transcript stays in view"
    bar.setValue(0)
    tab.toggle_reasoning(len(tab._entries) - 2)
    APP.processEvents()
    assert bar.value() == 0


def test_edge_the_summary_line():
    from ui.agent_dock import reasoning_summary

    assert reasoning_summary("\n\n  first line  \nsecond") == "first line …"
    assert reasoning_summary("only line") == "only line"
    assert reasoning_summary("x" * 300).endswith("…") and len(reasoning_summary("x" * 300)) <= 101
    assert reasoning_summary("   \n ") == ""


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))


# -- the answer starts on the Agent line ---------------------------------------------
#
# Measured live (LM Studio, qwen3.6-35b-a3b-mlx@4bit): after its thinking the
# model sends the answer as "\n\n17 times 3 equals 51." - every newline became
# a <br>, so two empty lines stood between "Agent:" and the answer. The
# history keeps what the model sent (test_edge_the_history_keeps_...); the
# transcript shows the answer without its leading and trailing blank lines.


def test_happy_e2e_the_answer_starts_on_the_agent_line(env):
    env.fake({"content": "\n\n17 times 3 equals 51.\n", "reasoning_content": "multiply"})
    _dock, tab = _shown_tab(env)
    say(tab, "17*3?")
    assert "Agent: 17 times 3 equals 51." in tab.transcript.toPlainText()
    entry = next(e for e in tab.session.transcript if e["who"] == "Agent:")
    assert entry["text"] == "17 times 3 equals 51."


def test_sad_blank_lines_inside_an_answer_stay(env):
    env.fake({"content": "\n\nFirst part.\n\nSecond part.", "reasoning_content": "two parts"})
    _dock, tab = _shown_tab(env)
    say(tab, "two parts please")
    text = tab.transcript.toPlainText()
    assert "Agent: First part.\n\nSecond part." in text


def test_edge_the_model_history_still_has_the_raw_answer(fake, tmp_path):
    server = fake({"content": "\n\nAnswer.", "reasoning_content": "think"}, {"content": "B"})
    agent, events = _agent(server, tmp_path)
    agent.run("one")
    agent.run("two")
    assistant = [m for m in server.requests[1]["messages"] if m["role"] == "assistant"]
    assert assistant == [{"role": "assistant", "content": "\n\nAnswer."}]
