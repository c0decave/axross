"""An Ollama server cuts a request that does not fit its context - silently.

Found by the live run (tests/test_agent_dock_live.py): Ollama runs a model
with a context of 4096 tokens unless told otherwise (its log: "vram-based
default context ... default_num_ctx=4096" on a CPU host). The agent's first
request with Allow changes on is 5259 tokens (measured on LM Studio, same
tokenizer family); Ollama answered it with ``prompt_tokens: 3870`` - it
dropped what did not fit (the instructions, the tools or the start of the
conversation) and said nothing. Its OpenAI-compatible endpoint ignores a
context size in the request (``options.num_ctx`` and ``num_ctx``: still
3870), so axross cannot ask for more there; it can see the cut and say so.
Ollama's ``/api/ps`` names the context of a loaded model (``context_length``).
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from core import agent as A
from core.llm_profiles import LLMProfile
from tests.test_agent_loop import _call, _no_proxy  # noqa: F401


class _Ollama:
    """/v1/chat/completions with a usage, and /api/ps with a context."""

    def __init__(self, replies, *, ps=None, ps_status=200):
        self.replies = list(replies)
        self.requests: list[dict] = []
        self.ps_asked = 0
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - http.server API
                if self.path != "/api/ps":
                    self.send_response(404)
                    self.end_headers()
                    return
                fake.ps_asked += 1
                self.send_response(ps_status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                body = ps if isinstance(ps, (bytes, bytearray)) else json.dumps(ps or {}).encode()
                self.wfile.write(body)

            def do_POST(self):  # noqa: N802 - http.server API
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                fake.requests.append({"path": self.path, **body})
                reply = dict(fake.replies.pop(0) if fake.replies else {"content": "done"})
                usage = reply.pop("usage", None)
                finish = "tool_calls" if reply.get("tool_calls") else "stop"
                data = {"choices": [{"index": 0, "message": {"role": "assistant", **reply},
                                     "finish_reason": finish}]}
                if usage is not None:
                    data["usage"] = usage
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(data).encode())

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05},
                         daemon=True).start()
        self.root = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def ollama():
    servers = []

    def make(*replies, **kw):
        server = _Ollama(replies, **kw)
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.close()


def _ps(model="qwen2.5:1.5b", context=4096):
    return {"models": [{"name": model, "model": model, "context_length": context}]}


def _usage(prompt, completion=1):
    return {"prompt_tokens": prompt, "completion_tokens": completion}


def _agent(server, root, *, provider="ollama", model="qwen2.5:1.5b", endpoint=None):
    # allow_model_load: the check of loaded models (test_agent_model_load)
    # would ask /api/ps too; this is about the context only.
    profile = LLMProfile(name="o", provider=provider, endpoint=endpoint or server.root,
                         model=model, allow_model_load=True)
    events: list[dict] = []
    agent = A.Agent(A.AgentConfig(profile=profile, root=str(root)), on_event=events.append)
    return agent, events


def _notices(events):
    return [e["text"] for e in events if e.get("type") == "notice"]


# -- happy ---------------------------------------------------------------------------------


def test_happy_a_request_that_filled_the_context_is_said(ollama, tmp_path):
    server = ollama({"content": "hi", "usage": _usage(3870)}, ps=_ps(context=4096))
    agent, events = _agent(server, tmp_path)
    agent.run("hi")
    (notice,) = _notices(events)
    assert "4096" in notice and "3870" in notice
    assert "OLLAMA_CONTEXT_LENGTH" in notice and "num_ctx" in notice
    assert server.ps_asked == 1


def test_happy_said_once_per_conversation(ollama, tmp_path):
    (tmp_path / "a.txt").write_text("a")
    server = ollama({"tool_calls": [_call("list_dir", {"path": str(tmp_path)})],
                     "usage": _usage(3900)},
                    {"content": "one file", "usage": _usage(4000)},
                    {"content": "again", "usage": _usage(4010)}, ps=_ps())
    agent, events = _agent(server, tmp_path)
    agent.run("list")
    agent.run("again")
    assert len(_notices(events)) == 1


def test_happy_the_model_name_without_a_tag_is_its_latest(ollama, tmp_path):
    server = ollama({"content": "hi", "usage": _usage(3870)},
                    ps=_ps(model="mine:latest", context=4096))
    agent, events = _agent(server, tmp_path, model="mine")
    agent.run("hi")
    assert len(_notices(events)) == 1


def test_happy_an_endpoint_typed_with_v1_asks_the_server_root(ollama, tmp_path):
    server = ollama({"content": "hi", "usage": _usage(3870)}, ps=_ps())
    agent, events = _agent(server, tmp_path, endpoint=server.root + "/v1")
    agent.run("hi")
    assert server.requests[0]["path"] == "/v1/chat/completions"
    assert server.ps_asked == 1 and len(_notices(events)) == 1


# -- sad -----------------------------------------------------------------------------------


def test_sad_api_ps_failing_is_no_notice_and_no_error(ollama, tmp_path):
    server = ollama({"content": "hi", "usage": _usage(3870)}, ps=_ps(), ps_status=500)
    agent, events = _agent(server, tmp_path)
    assert agent.run("hi").answer == "hi"
    assert _notices(events) == []


def test_sad_api_ps_answering_garbage_is_no_notice(ollama, tmp_path):
    server = ollama({"content": "hi", "usage": _usage(3870)}, ps=b"<html>no</html>")
    agent, events = _agent(server, tmp_path)
    assert agent.run("hi").answer == "hi"
    assert _notices(events) == []


def test_sad_a_model_api_ps_does_not_list_is_no_notice(ollama, tmp_path):
    server = ollama({"content": "hi", "usage": _usage(3870)}, ps=_ps(model="other:7b"))
    agent, events = _agent(server, tmp_path)
    agent.run("hi")
    assert _notices(events) == []


# -- edge ----------------------------------------------------------------------------------


def test_edge_a_request_well_inside_the_context_is_quiet(ollama, tmp_path):
    server = ollama({"content": "hi", "usage": _usage(3350)},
                    {"content": "again", "usage": _usage(3400)}, ps=_ps(context=16384))
    agent, events = _agent(server, tmp_path)
    agent.run("hi")
    agent.run("again")
    assert _notices(events) == []
    assert server.ps_asked == 1, "the context is asked once and kept"


def test_edge_other_providers_never_ask_api_ps(ollama, tmp_path):
    server = ollama({"content": "hi", "usage": _usage(3870)}, ps=_ps())
    agent, events = _agent(server, tmp_path, provider="lmstudio", endpoint=server.root + "/v1")
    agent.run("hi")
    assert server.ps_asked == 0 and _notices(events) == []


def test_edge_no_usage_in_the_answer_asks_nothing(ollama, tmp_path):
    server = ollama({"content": "hi"}, ps=_ps())
    agent, events = _agent(server, tmp_path)
    agent.run("hi")
    assert server.ps_asked == 0 and _notices(events) == []


def test_edge_the_border_is_ninety_percent_of_the_context(ollama, tmp_path):
    below = ollama({"content": "hi", "usage": _usage(3685, 0)}, ps=_ps(context=4096))
    agent, events = _agent(below, tmp_path)
    agent.run("hi")
    assert _notices(events) == []
    at = ollama({"content": "hi", "usage": _usage(3687, 0)}, ps=_ps(context=4096))
    agent, events = _agent(at, tmp_path)
    agent.run("hi")
    assert len(_notices(events)) == 1


def test_happy_a_sandboxed_tab_is_told_too(ollama, tmp_path):
    """A sandboxed agent's requests are sent by axross: the host asks the
    context and says it, once."""
    from core import agent_sandbox as SB

    server = ollama({"content": "hi", "usage": _usage(3870)},
                    {"content": "again", "usage": _usage(3900)}, ps=_ps())
    profile = LLMProfile(name="o", provider="ollama", endpoint=server.root, model="qwen2.5:1.5b",
                         allow_model_load=True)
    events: list[dict] = []
    agent = SB.SandboxedAgent(A.AgentConfig(profile=profile, root=str(tmp_path)), None,
                              on_event=events.append, command=SB.worker_argv())
    try:
        agent.run("hi")
        agent.run("again")
    finally:
        agent.close()
    notices = [n for n in _notices(events) if "context of 4096" in n]
    assert len(notices) == 1
