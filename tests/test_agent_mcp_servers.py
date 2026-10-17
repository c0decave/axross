"""Further MCP servers for the agent (Agent Settings > MCP Servers).

Their tools reach the model as ``<server>__<tool>``. They run with
axross, never in the sandbox: a sandboxed agent gets them as host tools,
under the sandbox's level (paranoid: none; an http server only when its
host is allowed). A server's tool that may change something asks first;
a server set to "always" asks for every call.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import agent as A  # noqa: E402
from core import agent_sandbox as SB  # noqa: E402
from core import agent_settings as AGS  # noqa: E402
from core import mcp_client as C  # noqa: E402
from core.llm_profiles import LLMProfile  # noqa: E402
from tests.test_agent_loop import _call, _Fake, _tool_messages  # noqa: E402
from tests.test_mcp_client import FAKE  # noqa: E402


@pytest.fixture(autouse=True)
def _no_proxy(monkeypatch):
    for name in (
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
    ):
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


@pytest.fixture
def pool(tmp_path):
    script = tmp_path / "fake_mcp.py"
    script.write_text(FAKE)
    pool = C.McpClientPool(token_lookup=lambda name: "")
    pool.config = lambda **kw: C.McpServerConfig(
        name="fake", command=(sys.executable, str(script), "normal"), **kw
    )
    yield pool
    pool.close_all()


def _config(server, root, pool=None, servers=(), **cfg):
    profile = LLMProfile(name="local", provider="lmstudio", endpoint=server.url, model="tiny")
    external = (lambda: pool.tools(list(servers))) if pool is not None else None
    return A.AgentConfig(profile=profile, root=str(root), external_tools=external, **cfg)


# -- settings ------------------------------------------------------------------


def test_happy_servers_round_trip_through_the_settings_file(tmp_path):
    settings = AGS.AgentSettings(
        mcp_servers=[
            C.McpServerConfig(
                name="git", command=("mcp-git", "--repo", "/srv/x"), confirm="writes"
            ),
            C.McpServerConfig(
                name="web", transport="http", url="http://127.0.0.1:9000/mcp", bearer=True
            ),
        ]
    )
    settings.save(tmp_path / "s.json")
    back = AGS.AgentSettings.load(tmp_path / "s.json")
    assert back.mcp_servers == settings.mcp_servers
    assert "token" not in (tmp_path / "s.json").read_text()


def test_sad_broken_and_duplicate_servers_are_dropped():
    data = {
        "mcp_servers": [
            {"name": "a", "command": ["x"]},
            {"name": "a", "command": ["y"]},
            {"name": "bad name", "command": ["z"]},
            "junk",
            {"name": "h", "transport": "http"},
        ]
    }
    assert [s.name for s in AGS.AgentSettings.from_dict(data).mcp_servers] == ["a"]


# -- in process ----------------------------------------------------------------


def test_happy_a_read_only_server_tool_runs_without_asking(fake, tmp_path, pool):
    server = fake({"tool_calls": [_call("fake__look", {"q": "status"})]}, {"content": "done"})
    asked = []
    agent = A.Agent(_config(server, tmp_path, pool, [pool.config(confirm="writes")]),
                    confirm=lambda n, a: asked.append(n) or True)
    result = agent.run("look")
    assert result.calls == [{"name": "fake__look", "outcome": "ok"}] and asked == []
    assert '{"q": "status"}' in _tool_messages(server.requests[1])[0]["content"]
    offered = {t["function"]["name"] for t in server.requests[0]["tools"]}
    assert {"fake__look", "fake__change", "read_file"} <= offered


def test_happy_always_asks_for_every_call_of_the_server(fake, tmp_path, pool):
    server = fake({"tool_calls": [_call("fake__look", {})]}, {"content": "done"})
    asked = []
    agent = A.Agent(
        _config(server, tmp_path, pool, [pool.config()]),
        confirm=lambda n, a: asked.append(n) or True,
    )
    agent.run("look")
    assert asked == ["fake__look"]


def test_sad_a_declined_server_call_does_not_run(fake, tmp_path, pool):
    server = fake({"tool_calls": [_call("fake__look", {"q": 1})]}, {"content": "done"})
    result = A.Agent(
        _config(server, tmp_path, pool, [pool.config()]), confirm=lambda n, a: False
    ).run("look")
    assert result.calls[0]["outcome"] == "declined"
    assert "q" not in _tool_messages(server.requests[1])[0]["content"]


def test_sad_a_server_that_cannot_start_is_reported_and_the_agent_goes_on(fake, tmp_path, pool):
    server = fake({"content": "fine"})
    events = []
    broken = C.McpServerConfig(name="gone", command=("/nonexistent/server",))
    agent = A.Agent(_config(server, tmp_path, pool, [broken]), on_event=events.append)
    assert agent.run("hi").answer == "fine"
    notes = [e["text"] for e in events if e.get("type") == "notice"]
    assert notes and "gone" in notes[0]


def test_edge_a_server_tool_error_reaches_the_model(fake, tmp_path, pool):
    server = fake({"tool_calls": [_call("fake__change", {})]}, {"content": "done"})
    result = A.Agent(
        _config(server, tmp_path, pool, [pool.config()]), confirm=lambda n, a: True
    ).run("change")
    assert result.calls[0]["outcome"] == "error"
    assert "disk full" in _tool_messages(server.requests[1])[0]["content"]


# -- in a sandbox --------------------------------------------------------------


def _sandboxed(server, tmp_path, profile, pool, servers, **kw):
    return SB.SandboxedAgent(
        _config(server, tmp_path, pool, servers), profile, command=SB.worker_argv(), **kw
    )


def test_happy_sandboxed_server_tools_run_in_axross(fake, tmp_path, pool):
    server = fake({"tool_calls": [_call("fake__look", {"q": 2})]}, {"content": "done"})
    agent = _sandboxed(server, tmp_path, SB.SandboxProfile(name="N", level="normal"), pool,
                       [pool.config(confirm="writes")])
    try:
        result = agent.run("look")
    finally:
        agent.close()
    assert result.calls == [{"name": "fake__look", "outcome": "ok"}]
    assert '{"q": 2}' in _tool_messages(server.requests[1])[0]["content"]


def test_sad_paranoid_offers_no_server(fake, tmp_path, pool):
    server = fake({"tool_calls": [_call("fake__look", {})]}, {"content": "done"})
    agent = _sandboxed(server, tmp_path, SB.SandboxProfile(name="P", level="paranoid"), pool,
                       [pool.config(confirm="writes")])
    try:
        result = agent.run("look")
    finally:
        agent.close()
    assert result.calls[0]["outcome"] == "unavailable"
    assert "fake__look" not in {t["function"]["name"] for t in server.requests[0]["tools"]}


def test_sad_an_http_server_outside_the_allowed_hosts_is_refused(tmp_path):
    sent = []
    profile = LLMProfile(name="x", provider="lmstudio", endpoint="http://127.0.0.1:9/v1")
    client = type("Client", (), {"config": C.McpServerConfig(name="web", transport="http",
                                                             url="http://mcp.example:9000/mcp")})()
    tool = C.ExternalTool(name="web__q", description="", schema={"type": "object"}, write=False,
                          client=client, remote_name="q", always_ask=False)
    config = A.AgentConfig(profile=profile, root=str(tmp_path), external_tools=lambda: ([tool], []))
    agent = SB.SandboxedAgent(
        config,
        SB.SandboxProfile(name="N", level="normal", hosts=("other:1",)),
        command=SB.worker_argv(),
    )
    agent._load_external()
    agent._send = sent.append
    agent._answer_host_tool({"type": "host_tool", "id": 1, "name": "web__q", "args": {}}, wait=True)
    agent.close()
    reply = sent[0]["value"]
    assert reply["outcome"] == "error" and "mcp.example:9000" in reply["text"]


def test_edge_an_external_tool_with_a_backend_argument_is_not_mistaken_for_a_file_tool(tmp_path):
    sent = []
    profile = LLMProfile(name="x", provider="lmstudio", endpoint="http://127.0.0.1:9/v1")
    calls = []
    client = type(
        "Client",
        (),
        {
            "config": C.McpServerConfig(name="db", command=("x",)),
            "call_tool": lambda self, n, a: calls.append(a) or {"content": []},
        },
    )()
    tool = C.ExternalTool(
        name="db__query",
        description="",
        write=False,
        client=client,
        remote_name="query",
        schema={"type": "object", "properties": {"backend": {"type": "string"}}},
        always_ask=False,
    )
    config = A.AgentConfig(profile=profile, root=str(tmp_path), external_tools=lambda: ([tool], []))
    agent = SB.SandboxedAgent(
        config, SB.SandboxProfile(name="L", level="lax"), command=SB.worker_argv()
    )
    agent._load_external()
    agent._send = sent.append
    agent._answer_host_tool(
        {"type": "host_tool", "id": 1, "name": "db__query", "args": {"backend": "pg"}}, wait=True
    )
    agent.close()
    assert sent[0]["value"]["outcome"] == "ok" and calls == [{"backend": "pg"}]
    assert json.dumps(sent)
