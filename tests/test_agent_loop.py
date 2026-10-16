"""The agent loop: a local LLM drives axross through the MCP tools, in process.

core.agent sends the task to an OpenAI-compatible chat endpoint (LM
Studio, Ollama, vLLM, llama.cpp) with the MCP tools as functions, runs
each tool call the model asks for through the MCP dispatcher - same
schemas, root confinement, timeouts and audit as the MCP server - and
hands the results back until the model answers. A mutating or exec call
runs only after the confirm callback said yes.

The server here is a scripted fake on loopback that records every
request.
"""

from __future__ import annotations

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from core import agent as A
from core.llm_profiles import LLMProfile


class _Fake:
    """An OpenAI-compatible /chat/completions that answers from a script."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.requests: list[dict] = []
        self.headers: list[dict] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 - http.server API
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                fake.requests.append({"path": self.path, **body})
                fake.headers.append(dict(self.headers))
                reply = fake.replies.pop(0) if fake.replies else {"content": "done"}
                if isinstance(reply, int):
                    self.send_response(reply)
                    self.end_headers()
                    self.wfile.write(b'{"error": "boom"}')
                    return
                reply = dict(reply)
                finish = reply.pop("finish_reason", "tool_calls" if reply.get("tool_calls") else "stop")
                data = json.dumps({"choices": [{"index": 0, "message": {"role": "assistant", **reply},
                                                "finish_reason": finish}]})
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(data.encode())

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/v1"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture(autouse=True)
def _no_proxy(monkeypatch):
    # An environment proxy makes even loopback "remote" (the content would
    # pass the proxy) and the agent would ask for consent first.
    for name in ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def fake():
    servers = []

    def make(*replies):
        server = _Fake(replies)
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.close()


def _call(name, args, call_id="c1"):
    return {"id": call_id, "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}


def _agent(server, root, *, confirm=None, api_key="", **cfg):
    profile = LLMProfile(name="local", provider="lmstudio", endpoint=server.url, model="tiny")
    config = A.AgentConfig(profile=profile, api_key=api_key, root=str(root), **cfg)
    return A.Agent(config, confirm=confirm)


def _tool_messages(request):
    return [m for m in request["messages"] if m["role"] == "tool"]


# --- happy ------------------------------------------------------------------


def test_happy_a_plain_answer(fake, tmp_path):
    server = fake({"content": "Hello."})
    result = _agent(server, tmp_path).run("Say hello")
    assert result.answer == "Hello." and result.stopped == "answered"
    sent = server.requests[0]
    assert sent["path"] == "/v1/chat/completions" and sent["model"] == "tiny"
    assert sent["messages"][-1] == {"role": "user", "content": "Say hello"}
    names = {t["function"]["name"] for t in sent["tools"]}
    assert {"list_dir", "read_file", "stat"} <= names


def test_happy_a_read_only_tool_call_runs_without_asking(fake, tmp_path):
    (tmp_path / "notes.txt").write_text("x")
    server = fake({"tool_calls": [_call("list_dir", {"path": str(tmp_path)})]}, {"content": "One file."})
    asked = []
    result = _agent(server, tmp_path, confirm=lambda n, a: asked.append(n) or True).run("What is here?")
    assert result.answer == "One file." and asked == []
    (tool_msg,) = _tool_messages(server.requests[1])
    assert tool_msg["tool_call_id"] == "c1" and "notes.txt" in tool_msg["content"]
    assert [c["name"] for c in result.calls] == ["list_dir"] and result.calls[0]["outcome"] == "ok"


def test_happy_a_confirmed_write_lands(fake, tmp_path):
    import base64

    args = {"path": str(tmp_path / "out.txt"), "content_b64": base64.b64encode(b"hi\n").decode()}
    server = fake({"tool_calls": [_call("write_file", args)]}, {"content": "Written."})
    asked = []
    result = _agent(server, tmp_path, allow_write=True,
                    confirm=lambda n, a: asked.append((n, a)) or True).run("Write hi")
    assert (tmp_path / "out.txt").read_bytes() == b"hi\n"
    assert asked == [("write_file", args)] and result.calls[0]["outcome"] == "ok"


def test_happy_the_conversation_carries_on(fake, tmp_path):
    server = fake({"content": "First."}, {"content": "Second."})
    agent = _agent(server, tmp_path)
    agent.run("one")
    agent.run("two")
    roles = [m["role"] for m in server.requests[1]["messages"]]
    assert roles == ["system", "user", "assistant", "user"]


# --- sad --------------------------------------------------------------------


def test_sad_a_declined_write_does_not_run(fake, tmp_path, caplog):
    import base64

    args = {"path": str(tmp_path / "out.txt"), "content_b64": base64.b64encode(b"hi").decode()}
    server = fake({"tool_calls": [_call("write_file", args)]}, {"content": "Ok, not written."})
    caplog.set_level(logging.INFO, logger="core.agent.audit")
    result = _agent(server, tmp_path, allow_write=True, confirm=lambda n, a: False).run("Write hi")
    assert not (tmp_path / "out.txt").exists()
    (tool_msg,) = _tool_messages(server.requests[1])
    assert "declined" in tool_msg["content"]
    assert result.calls[0]["outcome"] == "declined"
    assert any("tool=write_file" in r.getMessage() and "declined" in r.getMessage() for r in caplog.records)


def test_sad_without_a_confirm_callback_nothing_mutating_runs(fake, tmp_path):
    import base64

    args = {"path": str(tmp_path / "out.txt"), "content_b64": base64.b64encode(b"hi").decode()}
    server = fake({"tool_calls": [_call("write_file", args)]}, {"content": "no"})
    _agent(server, tmp_path, allow_write=True).run("Write hi")
    assert not (tmp_path / "out.txt").exists()


def test_sad_a_tool_error_goes_back_to_the_model(fake, tmp_path):
    server = fake({"tool_calls": [_call("read_file", {"path": "/etc/shadow"})]}, {"content": "Cannot."})
    result = _agent(server, tmp_path).run("Read it")
    (tool_msg,) = _tool_messages(server.requests[1])
    assert tool_msg["content"].startswith("error:") and result.calls[0]["outcome"] == "error"


def test_sad_an_unknown_tool_is_not_run(fake, tmp_path):
    server = fake({"tool_calls": [_call("write_file", {"path": "/x", "content_b64": ""})]}, {"content": "?"})
    result = _agent(server, tmp_path).run("Write")  # write not allowed: not offered
    (tool_msg,) = _tool_messages(server.requests[1])
    assert "not available" in tool_msg["content"] and result.calls[0]["outcome"] == "unavailable"


def test_sad_malformed_arguments_are_reported(fake, tmp_path):
    bad = {"id": "c1", "type": "function", "function": {"name": "list_dir", "arguments": "{not json"}}
    server = fake({"tool_calls": [bad]}, {"content": "?"})
    result = _agent(server, tmp_path).run("List")
    assert "arguments" in _tool_messages(server.requests[1])[0]["content"]
    assert result.calls[0]["outcome"] == "error"


def test_sad_cut_arguments_do_not_poison_the_history(fake, tmp_path):
    # A model that runs into its output limit leaves the arguments cut
    # off; llama.cpp then refused the whole next request (HTTP 500, "Failed
    # to parse tool call arguments as JSON") because the history carried
    # them back. The history keeps valid JSON; the model learns why.
    cut = {"id": "c1", "type": "function",
           "function": {"name": "write_file", "arguments": '{"path": "/x", "content": "line\\nline'}}
    server = fake({"tool_calls": [cut], "finish_reason": "length"}, {"content": "sorry"})
    result = _agent(server, tmp_path, allow_write=True, confirm=lambda n, a: True).run("write")
    history = server.requests[1]["messages"]
    for message in history:
        for call in message.get("tool_calls") or []:
            assert isinstance(json.loads(call["function"]["arguments"]), dict)
    tool_msg = _tool_messages(server.requests[1])[0]["content"]
    assert "output limit" in tool_msg and result.calls[0]["outcome"] == "error"


def test_sad_a_server_error_is_an_agent_error(fake, tmp_path):
    server = fake(500)
    with pytest.raises(A.AgentError, match="500"):
        _agent(server, tmp_path, api_key="sk-secret-key").run("Hi")


def test_sad_a_remote_endpoint_without_consent_sends_nothing(tmp_path):
    profile = LLMProfile(name="cloud", provider="openai", endpoint="https://llm.example.com/v1", model="m")
    agent = A.Agent(A.AgentConfig(profile=profile, root=str(tmp_path)))
    with pytest.raises(A.AgentError, match="consent"):
        agent.run("Hi")


# --- edge -------------------------------------------------------------------


def test_edge_the_step_limit_stops_a_looping_model(fake, tmp_path):
    loop = {"tool_calls": [_call("stat", {"path": str(tmp_path)})]}
    server = fake(*[loop] * 5)
    result = _agent(server, tmp_path, max_steps=3).run("Loop")
    assert result.stopped == "max_steps" and len(result.calls) == 3


def test_edge_a_large_result_is_cut_for_the_model(fake, tmp_path):
    for i in range(300):
        (tmp_path / f"file-{i:03d}-with-a-long-name.txt").write_text("")
    server = fake({"tool_calls": [_call("list_dir", {"path": str(tmp_path)})]}, {"content": "Many."})
    _agent(server, tmp_path, max_tool_chars=2000).run("List")
    content = _tool_messages(server.requests[1])[0]["content"]
    assert len(content) <= 2100 and "truncated" in content


def test_edge_write_and_exec_are_offered_only_when_allowed(fake, tmp_path):
    server = fake({"content": "a"}, {"content": "b"})
    _agent(server, tmp_path, groups=frozenset({"exec"})).run("x")
    names = {t["function"]["name"] for t in server.requests[0]["tools"]}
    assert "write_file" not in names and "remote_exec" not in names
    _agent(server, tmp_path, groups=frozenset({"exec"}), allow_write=True, allow_exec=True).run("y")
    names = {t["function"]["name"] for t in server.requests[1]["tools"]}
    assert {"write_file", "remote_exec"} <= names


def test_edge_exec_tools_always_ask(fake, tmp_path):
    server = fake({"tool_calls": [_call("exec_backends", {})]}, {"content": "none"})
    asked = []
    _agent(server, tmp_path, groups=frozenset({"exec"}), allow_exec=True,
           confirm=lambda n, a: asked.append(n) or True).run("x")
    assert asked == []  # exec_backends only lists; remote_exec and remote_script ask
    assert A.needs_confirmation("remote_exec", write=True, group="exec")
    assert not A.needs_confirmation("exec_backends", write=False, group="exec")


def test_edge_cancel_stops_between_steps(fake, tmp_path):
    loop = {"tool_calls": [_call("stat", {"path": str(tmp_path)})]}
    server = fake(loop, loop, loop)
    cancel = threading.Event()
    profile = LLMProfile(name="local", provider="lmstudio", endpoint=server.url, model="tiny")
    agent = A.Agent(A.AgentConfig(profile=profile, root=str(tmp_path)), cancel=cancel,
                    on_event=lambda e: cancel.set() if e["type"] == "tool_result" else None)
    result = agent.run("x")
    assert result.stopped == "cancelled" and len(server.requests) == 1


def test_edge_the_api_key_is_a_header_and_nowhere_else(fake, tmp_path, caplog):
    server = fake({"tool_calls": [_call("stat", {"path": str(tmp_path)})]}, {"content": "ok"})
    caplog.set_level(logging.DEBUG)
    events = []
    profile = LLMProfile(name="local", provider="lmstudio", endpoint=server.url, model="tiny")
    A.Agent(A.AgentConfig(profile=profile, api_key="sk-secret-key", root=str(tmp_path)),
            on_event=events.append).run("x")
    assert server.headers[0]["Authorization"] == "Bearer sk-secret-key"
    assert "sk-secret-key" not in json.dumps(server.requests) + json.dumps(events) + caplog.text


@pytest.mark.parametrize(
    "provider, endpoint, url",
    [
        ("ollama", "", "http://localhost:11434/v1/chat/completions"),
        ("ollama", "http://gpu.lan:11434", "http://gpu.lan:11434/v1/chat/completions"),
        ("lmstudio", "", "http://localhost:1234/v1/chat/completions"),
        ("openai", "http://10.0.0.5:8000/v1/", "http://10.0.0.5:8000/v1/chat/completions"),
    ],
)
def test_edge_the_chat_url_of_each_provider(provider, endpoint, url):
    assert A.chat_url(LLMProfile(name="p", provider=provider, endpoint=endpoint, model="m")) == url
