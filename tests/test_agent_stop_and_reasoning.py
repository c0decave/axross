"""Two defects the live run against LM Studio found (tests/test_agent_dock_live.py).

1. Stop during a long answer did nothing until the server had answered:
   the agent checked its cancel flag only between two model requests, and
   the request itself (urllib, not streamed) blocks until the whole answer is
   generated. LM Studio: Stop at 2 s, the tab stayed busy 14 s, and the essay
   was then shown as a normal answer ("stopped": "answered").
2. Qwen3.6 on LM Studio wrote its final answer into ``reasoning_content``
   with ``content: ""`` (finish "stop") in about one run of four; the agent
   read only ``content``, so the tab showed no answer at all.
"""

from __future__ import annotations

import os
import sys
import threading
import time
import unittest
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import agent as A  # noqa: E402
from core.llm_profiles import LLMProfile  # noqa: E402
from tests.test_agent_dock import _Base  # noqa: E402
from tests.test_agent_loop import _call, _no_proxy, fake  # noqa: E402,F401


def _agent(server, root, **kw):
    profile = LLMProfile(name="local", provider="lmstudio", endpoint=server.url, model="tiny")
    events: list[dict] = []
    agent = A.Agent(A.AgentConfig(profile=profile, root=str(root)), on_event=events.append, **kw)
    return agent, events


def _run_in_thread(agent, task):
    box: dict = {}

    def work():
        try:
            box["result"] = agent.run(task)
        except Exception as exc:  # noqa: BLE001 - the test reads it
            box["error"] = exc

    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    return thread, box


def _wait(cond, seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.02)
    return bool(cond())


# -- Stop ---------------------------------------------------------------------------------------


def test_happy_stop_ends_a_long_model_request_at_once(fake, tmp_path):
    server = fake({"content": "a very long essay", "_delay": 8})
    agent, events = _agent(server, tmp_path)
    began = time.monotonic()
    thread, box = _run_in_thread(agent, "write an essay")
    assert _wait(lambda: server.requests, 3)
    agent.cancel.set()
    thread.join(3)
    assert not thread.is_alive(), "the run still waits for the server after Stop"
    assert time.monotonic() - began < 4
    assert box["result"].stopped == "cancelled" and box["result"].answer == ""
    assert not [e for e in events if e.get("type") == "assistant"]


def test_happy_stop_closes_the_connection_so_the_server_stops_generating(fake, tmp_path):
    server = fake({"content": "a very long essay", "_delay": 8})
    agent, _events = _agent(server, tmp_path)
    thread, _box = _run_in_thread(agent, "write an essay")
    assert _wait(lambda: server.requests, 3)
    agent.cancel.set()
    thread.join(3)
    assert _wait(lambda: server.aborted == 1, 3), "the server never saw the client leave"


def test_sad_an_answer_that_arrives_after_stop_is_not_taken(tmp_path):
    cancel = threading.Event()

    def transport(body):
        cancel.set()  # Stop while the server answered
        return {"choices": [{"message": {"role": "assistant", "content": "late answer"},
                             "finish_reason": "stop"}]}

    profile = LLMProfile(name="local", provider="lmstudio", endpoint="http://127.0.0.1:9/v1")
    events: list[dict] = []
    agent = A.Agent(A.AgentConfig(profile=profile, root=str(tmp_path)), on_event=events.append,
                    cancel=cancel, transport=transport)
    result = agent.run("hi")
    assert result.stopped == "cancelled" and result.answer == ""
    assert not [e for e in events if e.get("type") == "assistant"]


def test_sad_tool_calls_that_arrive_after_stop_do_not_run(tmp_path):
    cancel = threading.Event()
    (tmp_path / "a.txt").write_text("a")

    def transport(body):
        cancel.set()
        return {"choices": [{"message": {"role": "assistant", "content": "",
                                         "tool_calls": [_call("list_dir",
                                                              {"path": str(tmp_path)})]},
                             "finish_reason": "tool_calls"}]}

    profile = LLMProfile(name="local", provider="lmstudio", endpoint="http://127.0.0.1:9/v1")
    agent = A.Agent(A.AgentConfig(profile=profile, root=str(tmp_path)), cancel=cancel,
                    transport=transport)
    result = agent.run("list")
    assert result.stopped == "cancelled" and result.calls == []


def test_edge_a_transport_failing_after_stop_is_a_stop_not_an_error(tmp_path):
    """The sandbox worker's transport: the host drops the request on Stop
    and answers an error - the run ends as stopped, not as failed."""
    cancel = threading.Event()

    def transport(body):
        cancel.set()
        raise A.AgentError("the request was stopped")

    profile = LLMProfile(name="local", provider="lmstudio", endpoint="http://127.0.0.1:9/v1")
    agent = A.Agent(A.AgentConfig(profile=profile, root=str(tmp_path)), cancel=cancel,
                    transport=transport)
    assert agent.run("hi").stopped == "cancelled"


def test_edge_a_failing_transport_without_stop_is_still_an_error(tmp_path):
    def transport(body):
        raise A.AgentError("cannot reach the LLM server")

    profile = LLMProfile(name="local", provider="lmstudio", endpoint="http://127.0.0.1:9/v1")
    agent = A.Agent(A.AgentConfig(profile=profile, root=str(tmp_path)), transport=transport)
    with pytest.raises(A.AgentError, match="cannot reach"):
        agent.run("hi")


def test_edge_post_chat_with_a_cancel_that_never_fires_answers_as_before(fake):
    server = fake({"content": "Hello."})
    profile = LLMProfile(name="local", provider="lmstudio", endpoint=server.url, model="tiny")
    payload = A.post_chat(profile, "", {"model": "tiny", "messages": []},
                          cancel=threading.Event())
    assert payload["choices"][0]["message"]["content"] == "Hello."


def test_sad_post_chat_cancelled_raises_the_stop(fake):
    server = fake({"content": "late", "_delay": 8})
    profile = LLMProfile(name="local", provider="lmstudio", endpoint=server.url, model="tiny")
    cancel = threading.Event()
    threading.Timer(0.3, cancel.set).start()
    began = time.monotonic()
    with pytest.raises(A.AgentCancelled):
        A.post_chat(profile, "", {"model": "tiny", "messages": []}, cancel=cancel)
    assert time.monotonic() - began < 3


def test_edge_https_requests_go_through_the_cuttable_handler_too(monkeypatch):
    import urllib.request

    from core.agent_net import AbortableConnections, opener_without_redirects

    # urllib keeps a ProxyHandler only when a proxy is set.
    monkeypatch.setenv("https_proxy", "http://proxy.example:3128")
    opener = opener_without_redirects(*AbortableConnections().handlers())
    https = [h for h in opener.handlers if isinstance(h, urllib.request.HTTPSHandler)]
    http = [h for h in opener.handlers if isinstance(h, urllib.request.HTTPHandler)]
    assert [type(h).__name__ for h in https] == ["_TrackingHTTPSHandler"]
    assert [type(h).__name__ for h in http] == ["_TrackingHTTPHandler"]
    # Proxies and the refused redirects stay.
    names = {type(h).__name__ for h in opener.handlers}
    assert {"ProxyHandler", "_RefuseRedirects"} <= names


def test_edge_a_connection_opened_after_abort_is_cut_as_it_opens(fake):
    import urllib.request

    from core.agent_net import AbortableConnections, opener_without_redirects

    server = fake({"content": "never", "_delay": 5})
    connections = AbortableConnections()
    connections.abort()
    opener = opener_without_redirects(*connections.handlers())
    request = urllib.request.Request(server.url + "/chat/completions", data=b"{}",
                                     headers={"Content-Type": "application/json"})
    began = time.monotonic()
    with pytest.raises(OSError):
        opener.open(request, timeout=10).read()
    assert time.monotonic() - began < 3


def test_happy_stop_in_a_sandboxed_tab_ends_the_model_request_at_once(fake, tmp_path):
    """A sandboxed agent's model requests are sent by axross (the host): the
    host's request is cut too, and the worker ends the task as stopped."""
    from core import agent_sandbox as SB

    server = fake({"content": "a very long essay", "_delay": 8})
    profile = LLMProfile(name="local", provider="lmstudio", endpoint=server.url, model="tiny")
    cancel = threading.Event()
    agent = SB.SandboxedAgent(A.AgentConfig(profile=profile, root=str(tmp_path)), None,
                              cancel=cancel, command=SB.worker_argv())
    try:
        thread, box = _run_in_thread(agent, "write an essay")
        assert _wait(lambda: server.requests, 30)
        began = time.monotonic()
        cancel.set()
        thread.join(5)
        assert not thread.is_alive(), "the sandboxed run still waits for the server"
        assert time.monotonic() - began < 4
        assert box.get("result") is not None, box
        assert box["result"].stopped == "cancelled"
        assert _wait(lambda: server.aborted == 1, 3)
    finally:
        agent.close()


# -- an answer only in the reasoning -----------------------------------------------------------


def test_happy_an_answer_only_in_reasoning_content_is_shown(fake, tmp_path):
    server = fake({"content": "", "reasoning_content": "The folder holds a.txt."})
    agent, events = _agent(server, tmp_path)
    result = agent.run("what is here?")
    assert result.stopped == "answered" and result.answer == "The folder holds a.txt."
    kinds = [e["type"] for e in events]
    assert "notice" in kinds and "assistant" in kinds
    assert next(e for e in events if e["type"] == "assistant")["text"] == \
        "The folder holds a.txt."


def test_happy_the_reasoning_field_of_ollama_and_vllm_counts_too(fake, tmp_path):
    server = fake({"content": None, "reasoning": "Two files."})
    agent, _events = _agent(server, tmp_path)
    assert agent.run("count").answer == "Two files."


def test_sad_no_answer_at_all_is_said_not_silent(fake, tmp_path):
    server = fake({"content": ""})
    agent, events = _agent(server, tmp_path)
    result = agent.run("hi")
    assert result.answer == "" and result.stopped == "answered"
    notices = [e["text"] for e in events if e["type"] == "notice"]
    assert notices == ["The model ended without an answer."]


def test_edge_whitespace_beside_tool_calls_is_no_empty_answer_line(fake, tmp_path):
    (tmp_path / "a.txt").write_text("a")
    server = fake({"content": "\n\n", "tool_calls": [_call("list_dir", {"path": str(tmp_path)})]},
                  {"content": "\n\nOne file: a.txt"})
    agent, events = _agent(server, tmp_path)
    result = agent.run("list")
    assert [e["text"] for e in events if e["type"] == "assistant"] == ["\n\nOne file: a.txt"]
    assert result.answer == "\n\nOne file: a.txt"


def test_edge_content_wins_over_reasoning(fake, tmp_path):
    server = fake({"content": "The answer.", "reasoning_content": "thinking about it"})
    agent, events = _agent(server, tmp_path)
    assert agent.run("q").answer == "The answer."
    assert not [e for e in events if e["type"] == "notice"]


def test_edge_whitespace_content_with_reasoning_takes_the_reasoning(fake, tmp_path):
    server = fake({"content": "\n\n", "reasoning_content": "  It is 42.  "})
    agent, _events = _agent(server, tmp_path)
    assert agent.run("q").answer == "It is 42."


def test_edge_the_history_keeps_what_the_model_sent(fake, tmp_path):
    """The reasoning is shown, but the conversation the server sees next
    keeps the model's own (empty) content - no invented assistant text."""
    server = fake({"content": "", "reasoning_content": "Answer A."}, {"content": "B"})
    agent, _events = _agent(server, tmp_path)
    agent.run("one")
    agent.run("two")
    assistant = [m for m in server.requests[1]["messages"] if m["role"] == "assistant"]
    assert assistant == [{"role": "assistant", "content": ""}]


# -- the dock, offscreen ----------------------------------------------------------------------


class DockTest(_Base):
    def test_happy_e2e_stop_in_the_tab_ends_a_long_answer_at_once(self) -> None:
        from PyQt6.QtCore import Qt
        from PyQt6.QtTest import QTest

        server = self.make({"content": "the whole essay", "_delay": 8})
        tab = self.dock.current_tab()
        tab.input.setPlainText("write an essay")
        QTest.keyClick(tab.input, Qt.Key.Key_Return, Qt.KeyboardModifier.ControlModifier)
        end = time.monotonic() + 3
        while not server.requests and time.monotonic() < end:
            self.app.processEvents()
            time.sleep(0.01)
        began = time.monotonic()
        QTest.mouseClick(tab.stop_button, Qt.MouseButton.LeftButton)
        self.wait_idle(3)
        self.assertLess(time.monotonic() - began, 3)
        text = tab.transcript.toPlainText()
        self.assertIn("Stopped.", text)
        self.assertNotIn("the whole essay", text)

    def test_happy_e2e_a_reasoning_only_answer_reaches_the_transcript(self) -> None:
        self.make({"content": "", "reasoning_content": "Only in the reasoning: 7."})
        self.say("what is it?")
        text = self.dock.transcript.toPlainText()
        self.assertIn("Only in the reasoning: 7.", text)
        self.assertIn("The model gave its answer only as reasoning", text)


if __name__ == "__main__":
    unittest.main()
