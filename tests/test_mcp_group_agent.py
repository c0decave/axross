"""MCP capability group ``agent``: hand a task to the local LLM.

``agent_run(task)`` lets an MCP client - another LLM - delegate work to
the user's own model (the active LLM profile of the axross GUI, or one
named), which then works with axross' read-only tools inside the MCP
root and answers. Nothing it does can change a file or run a command:
there is nobody to confirm a change on a headless server, so the inner
agent is offered no write, exec, script or agent tool. A remote LLM
endpoint needs the consent the GUI asked for.
"""

from __future__ import annotations

import json

import pytest

from core import llm_profiles as LP
from tests import mcp_group_testkit as T
from tests.test_agent_loop import _call, _Fake


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
def llm(tmp_path, monkeypatch):
    """A fake model and an llm.json whose active profile points at it."""
    servers = []

    def make(*replies, endpoint=None, consent=False):
        server = _Fake(replies)
        servers.append(server)
        profile = LP.LLMProfile(
            name="local", provider="lmstudio", endpoint=endpoint or server.url, model="tiny"
        )
        if consent:
            profile.consent()
        path = tmp_path / "llm.json"
        LP.LLMSettings([profile], "local").save(path)
        monkeypatch.setattr(LP, "SETTINGS_FILE", path)
        monkeypatch.setattr(LP, "get_api_key", lambda name: "")
        return server

    yield make
    for server in servers:
        server.close()


def _tools(root, write=False):
    return T.build(root, {"agent"}, allow_write=write)


# --- happy ------------------------------------------------------------------


def test_happy_the_local_model_answers_with_the_tools(tmp_path, llm):
    (tmp_path / "notes.txt").write_text("Meeting Friday 10:00\n")
    server = llm(
        {
            "tool_calls": [
                _call("read_file", {"path": str(tmp_path / "notes.txt"), "encoding": "text"})
            ]
        },
        {"content": "Friday at 10."},
    )
    r = T.call(_tools(tmp_path), "agent_run", {"task": "When is the meeting?"})
    assert r["answer"] == "Friday at 10." and r["stopped"] == "answered"
    assert r["profile"] == "local" and r["calls"] == [{"name": "read_file", "outcome": "ok"}]
    assert "Meeting Friday" in server.requests[1]["messages"][-1]["content"]


def test_happy_extra_read_only_groups_can_be_offered(tmp_path, llm):
    server = llm({"content": "ok"})
    T.call(_tools(tmp_path), "agent_run", {"task": "x", "groups": ["filetype", "metadata"]})
    names = {t["function"]["name"] for t in server.requests[0]["tools"]}
    assert {"file_type", "metadata_read"} <= names


# --- sad --------------------------------------------------------------------


def test_sad_without_a_profile_it_says_how_to_get_one(tmp_path, monkeypatch):
    monkeypatch.setattr(LP, "SETTINGS_FILE", tmp_path / "none.json")
    with pytest.raises(T.RpcError) as info:
        T.call(_tools(tmp_path), "agent_run", {"task": "x"})
    assert "LLM profile" in str(info.value)


def test_sad_a_remote_endpoint_needs_the_guis_consent(tmp_path, llm):
    server = llm({"content": "never"}, endpoint="https://llm.example.com/v1")
    with pytest.raises(T.RpcError) as info:
        T.call(_tools(tmp_path), "agent_run", {"task": "x"})
    assert "consent" in str(info.value) and server.requests == []


def test_sad_an_unknown_profile_is_refused(tmp_path, llm):
    llm({"content": "never"})
    with pytest.raises(T.RpcError) as info:
        T.call(_tools(tmp_path), "agent_run", {"task": "x", "profile": "nope"})
    assert "nope" in str(info.value)


def test_sad_groups_outside_the_read_only_list_are_refused(tmp_path, llm):
    llm({"content": "never"})
    for group in ("exec", "scripts", "agent", "crypto"):
        with pytest.raises(T.RpcError):
            T.call(_tools(tmp_path), "agent_run", {"task": "x", "groups": [group]})


# --- edge -------------------------------------------------------------------


def test_edge_the_inner_agent_can_change_nothing(tmp_path, llm):
    server = llm(
        {"tool_calls": [_call("write_file", {"path": str(tmp_path / "x"), "content": "y"})]},
        {"content": "could not"},
    )
    r = T.call(_tools(tmp_path, write=True), "agent_run", {"task": "write x", "groups": ["packer"]})
    names = {t["function"]["name"] for t in server.requests[0]["tools"]}
    assert not names & {"write_file", "remove", "pack", "remote_exec", "script_run", "agent_run"}
    assert (
        r["calls"] == [{"name": "write_file", "outcome": "unavailable"}]
        and not (tmp_path / "x").exists()
    )


def test_edge_the_tool_is_read_only_in_the_manifest(tmp_path):
    from core import mcp_groups

    tools = list(_tools(tmp_path).values())
    manifest = mcp_groups.tool_manifest(
        tools, groups={"agent"}, allow_write=False, allow_scripts=False
    )
    entry = next(t for t in manifest["tools"] if t["name"] == "agent_run")
    assert entry["mutating"] is False and entry["required_flags"] == ["--mcp-tools agent"]
    assert entry["timeout_class"] == "long"
    assert json.dumps(entry["input_schema"]).count('"backend"') == 0


def test_sad_groups_beyond_the_root_need_the_server_to_offer_them(tmp_path, llm):
    """remote opens saved connections with their stored credentials and
    extensions lists code: agent_run may only pass them on when the server
    itself was started with them (--mcp-tools)."""
    server = llm({"content": "ok"}, {"content": "ok"})
    for group in ("remote", "extensions"):
        with pytest.raises(T.RpcError) as info:
            T.call(_tools(tmp_path), "agent_run", {"task": "x", "groups": [group]})
        assert "--mcp-tools" in str(info.value)
    assert server.requests == []
    both = T.build(tmp_path, {"agent", "remote"})
    T.call(both, "agent_run", {"task": "x", "groups": ["remote"]})
    names = {t["function"]["name"] for t in server.requests[0]["tools"]}
    assert "remote_profiles" in names
