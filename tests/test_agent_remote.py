"""The agent and remote files: the connections open in the panes and the
saved profiles.

In process the agent reaches a pane's connection directly (backend
``pane:<name>``). In a sandbox the connection - and its credentials -
stay with axross: the worker hands such a call to axross as a *host
tool*, and axross runs it after its own checks: the call must name a
remote backend (the local files are the sandbox's), the sandbox's level
and allowed hosts must let the connection's host in (paranoid: none),
and a change still needs the user's yes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import agent as A  # noqa: E402
from core import agent_sandbox as SB  # noqa: E402
from core.llm_profiles import LLMProfile  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402
from tests.test_agent_loop import _call, _Fake, _tool_messages  # noqa: E402


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


def _ram(name="pane-ram"):
    ram = RamFsSession(name)
    ram.mkdir("/data")
    with ram.open_write("/data/f.txt") as handle:
        handle.write(b"remote text")
    return ram


def _pane(ram=None, *, host="files.example", port=22, production=False):
    profile = ConnectionProfile(
        name="box", protocol="sftp", host=host, port=port, production=production
    )
    return ("pane:box", ram or _ram(), profile)


def _config(server, root, **cfg):
    profile = LLMProfile(name="local", provider="lmstudio", endpoint=server.url, model="tiny")
    return A.AgentConfig(profile=profile, root=str(root), **cfg)


def _read_remote(path="/data/f.txt", backend="pane:box"):
    return _call("read_file", {"path": path, "encoding": "text", "backend": backend})


def _spec(name, **kw):
    return {"name": name, "description": f"{name} on axross",
            "schema": {"type": "object", "properties": {"path": {"type": "string"},
                                                        "backend": {"type": "string"}}},
            "write": False, "group": "core", **kw}


# -- happy: in process ---------------------------------------------------------


def test_happy_in_process_the_agent_reads_a_pane_connection(fake, tmp_path):
    server = fake({"tool_calls": [_read_remote()]}, {"content": "It says remote text."})
    agent = A.Agent(_config(server, tmp_path, remote_backends=(_pane(),)))
    result = agent.run("What is in f.txt on box?")
    assert result.calls == [{"name": "read_file", "outcome": "ok"}]
    (tool_msg,) = _tool_messages(server.requests[1])
    assert "remote text" in tool_msg["content"]
    names = {t["function"]["name"] for t in server.requests[0]["tools"]}
    assert "list_backends" in names
    agent.close()


def test_happy_in_process_closing_the_agent_leaves_the_pane_connected(fake, tmp_path):
    ram = _ram()
    server = fake({"content": "ok"})
    agent = A.Agent(_config(server, tmp_path, remote_backends=(_pane(ram),)))
    agent.run("hi")
    agent.close()
    with ram.open_read("/data/f.txt") as handle:
        assert handle.read() == b"remote text"


# -- happy: routing in the worker's agent --------------------------------------


def test_happy_a_call_naming_a_remote_backend_goes_to_axross(fake, tmp_path):
    (tmp_path / "local.txt").write_text("local text")
    server = fake(
        {
            "tool_calls": [
                _read_remote(),
                _call(
                    "read_file",
                    {"path": str(tmp_path / "local.txt"), "encoding": "text", "backend": "local"},
                    call_id="c2",
                ),
            ]
        },
        {"content": "done"},
    )
    routed = []

    def host_call(name, args):
        routed.append((name, args))
        return "ok", '{"text": "from axross"}'

    asked = []
    agent = A.Agent(_config(server, tmp_path), confirm=lambda n, a: asked.append(n) or True,
                    host_tools=[_spec("read_file"), _spec("remote_profiles")], host_call=host_call)
    agent.run("read both")
    assert routed == [
        ("read_file", {"path": "/data/f.txt", "encoding": "text", "backend": "pane:box"})
    ]
    first, second = _tool_messages(server.requests[1])
    assert "from axross" in first["content"] and "local text" in second["content"]
    offered = {t["function"]["name"]: t["function"] for t in server.requests[0]["tools"]}
    assert "backend" in offered["read_file"]["parameters"]["properties"]
    assert "remote_profiles" in offered  # a tool only axross has


def test_happy_a_host_only_tool_goes_to_axross_without_a_backend(fake, tmp_path):
    server = fake({"tool_calls": [_call("remote_profiles", {})]}, {"content": "done"})
    routed = []
    agent = A.Agent(_config(server, tmp_path), host_tools=[_spec("remote_profiles")],
                    host_call=lambda n, a: routed.append(n) or ("ok", "[]"))
    result = agent.run("which profiles?")
    assert routed == ["remote_profiles"] and result.calls[0]["outcome"] == "ok"


# -- sad -----------------------------------------------------------------------


def test_sad_without_host_tools_a_remote_backend_is_an_error_not_a_local_read(fake, tmp_path):
    (tmp_path / "f.txt").write_text("LOCAL")
    server = fake({"tool_calls": [_read_remote(path=str(tmp_path / "f.txt"))]}, {"content": "done"})
    result = A.Agent(_config(server, tmp_path)).run("read")
    (tool_msg,) = _tool_messages(server.requests[1])
    assert result.calls[0]["outcome"] == "error" and "LOCAL" not in tool_msg["content"]
    assert "pane:box" in tool_msg["content"]


def test_sad_a_host_tool_error_reaches_the_model(fake, tmp_path):
    server = fake({"tool_calls": [_read_remote()]}, {"content": "done"})
    agent = A.Agent(
        _config(server, tmp_path),
        host_tools=[_spec("read_file")],
        host_call=lambda n, a: ("error", "error: files.example:22 is not an allowed host"),
    )
    result = agent.run("read")
    assert result.calls[0]["outcome"] == "error"
    assert "not an allowed host" in _tool_messages(server.requests[1])[0]["content"]


# -- the host side: SandboxedAgent ---------------------------------------------


def _sandboxed(server, tmp_path, profile, *, confirm=None, events=None, **cfg):
    return SB.SandboxedAgent(_config(server, tmp_path, **cfg), profile, confirm=confirm,
                             on_event=(events.append if events is not None else None),
                             command=SB.worker_argv())


def test_happy_sandboxed_the_agent_reads_a_pane_connection_through_axross(fake, tmp_path):
    server = fake({"tool_calls": [_read_remote()]}, {"content": "It says remote text."})
    profile = SB.SandboxProfile(name="Ops", level="normal", hosts=("files.example:22",))
    agent = _sandboxed(server, tmp_path, profile, remote_backends=(_pane(),))
    try:
        result = agent.run("read f.txt on box")
    finally:
        agent.close()
    assert result.calls == [{"name": "read_file", "outcome": "ok"}]
    assert "remote text" in _tool_messages(server.requests[1])[0]["content"]


def test_happy_sandboxed_a_remote_write_asks_axross_once(fake, tmp_path):
    ram = _ram()
    server = fake({"tool_calls": [_call("write_file", {"path": "/data/n.txt", "content": "x",
                                                       "backend": "pane:box"})]},
                  {"content": "written"})
    asked = []
    profile = SB.SandboxProfile(name="Ops", level="lax")
    agent = _sandboxed(server, tmp_path, profile, confirm=lambda n, a: asked.append((n, a)) or True,
                       remote_backends=(_pane(ram),), allow_write=True)
    try:
        agent.run("write n.txt on box")
    finally:
        agent.close()
    assert [n for n, _ in asked] == ["write_file"]
    with ram.open_read("/data/n.txt") as handle:
        assert handle.read() == b"x"


def test_sad_paranoid_offers_no_remote_connection(fake, tmp_path):
    server = fake({"tool_calls": [_read_remote()]}, {"content": "done"})
    profile = SB.SandboxProfile(name="P", level="paranoid")
    agent = _sandboxed(server, tmp_path, profile, remote_backends=(_pane(),))
    try:
        result = agent.run("read")
    finally:
        agent.close()
    assert result.calls[0]["outcome"] == "error"
    assert "remote text" not in _tool_messages(server.requests[1])[0]["content"]
    names = {t["function"]["name"] for t in server.requests[0]["tools"]}
    assert "list_backends" not in names


def test_sad_a_host_outside_the_allowed_hosts_is_refused(fake, tmp_path):
    server = fake({"tool_calls": [_read_remote()]}, {"content": "done"})
    profile = SB.SandboxProfile(name="Ops", level="normal", hosts=("llm.example:8080",))
    agent = _sandboxed(server, tmp_path, profile, remote_backends=(_pane(),))
    try:
        result = agent.run("read")
    finally:
        agent.close()
    content = _tool_messages(server.requests[1])[0]["content"]
    assert result.calls[0]["outcome"] == "error" and "files.example" in content
    assert "remote text" not in content


def test_sad_a_declined_remote_write_does_not_land(fake, tmp_path):
    ram = _ram()
    server = fake({"tool_calls": [_call("write_file", {"path": "/data/n.txt", "content": "x",
                                                       "backend": "pane:box"})]},
                  {"content": "ok"})
    agent = _sandboxed(server, tmp_path, SB.SandboxProfile(name="L", level="lax"),
                       confirm=lambda n, a: False, remote_backends=(_pane(ram),), allow_write=True)
    try:
        result = agent.run("write")
    finally:
        agent.close()
    assert result.calls[0]["outcome"] == "declined"
    assert not ram.exists("/data/n.txt")


def test_sad_axross_refuses_a_host_tool_call_on_local_files(tmp_path):
    """A worker that asks axross for a local path (a broken or subverted
    worker) gets a refusal: the local files are the sandbox's."""
    (tmp_path / "secret.txt").write_text("host secret")
    sent = []
    profile = SB.SandboxProfile(name="L", level="lax")
    config = A.AgentConfig(profile=LLMProfile(name="x", provider="lmstudio", endpoint="http://127.0.0.1:9/v1"),
                           root=str(tmp_path), remote_backends=(_pane(),))
    agent = SB.SandboxedAgent(config, profile, command=SB.worker_argv())
    agent._send = sent.append
    for args in ({"path": str(tmp_path / "secret.txt"), "encoding": "text"},
                 {"path": str(tmp_path / "secret.txt"), "encoding": "text", "backend": "local"}):
        agent._answer_host_tool(
            {"type": "host_tool", "id": 7, "name": "read_file", "args": args}, wait=True
        )
    assert len(sent) == 2
    for reply in sent:
        assert reply["id"] == 7 and reply["value"]["outcome"] == "error"
        assert "only runs calls on a remote backend" in reply["value"]["text"]
        assert "host secret" not in json.dumps(reply)
    agent.close()


def test_sad_a_host_copy_into_the_local_files_is_refused_by_the_backend_too(tmp_path):
    """The second layer: a call that names a remote backend may still name
    the local files on its other side - axross has none to give."""
    sent = []
    config = A.AgentConfig(
        profile=LLMProfile(name="x", provider="lmstudio", endpoint="http://127.0.0.1:9/v1"),
        root=str(tmp_path),
        remote_backends=(_pane(),),
        groups=frozenset({"transfer"}),
        allow_write=True,
    )
    agent = SB.SandboxedAgent(
        config,
        SB.SandboxProfile(name="L", level="lax"),
        confirm=lambda n, a: True,
        command=SB.worker_argv(),
    )
    agent._send = sent.append
    agent._answer_host_tool(
        {
            "type": "host_tool",
            "id": 3,
            "name": "transfer_copy",
            "args": {
                "src": "/data/f.txt",
                "src_backend": "pane:box",
                "dst": str(tmp_path / "f.txt"),
                "dst_backend": "local",
            },
        },
        wait=True,
    )
    agent.close()
    assert sent[0]["value"]["outcome"] == "error"
    assert not (tmp_path / "f.txt").exists()


def test_edge_the_host_tools_have_no_local_files():
    local = SB._SandboxLocal()
    assert not hasattr(local, "open_read")
    with pytest.raises(AttributeError, match="inside the sandbox"):
        local.list_dir("/")


# -- edge ----------------------------------------------------------------------


def test_edge_the_allowed_hosts_are_read_on_every_call(fake, tmp_path):
    hosts = ["files.example:22"]
    server = fake({"tool_calls": [_read_remote()]}, {"content": "done"})
    agent = _sandboxed(server, tmp_path,
                       lambda: SB.SandboxProfile(name="Ops", level="normal", hosts=tuple(hosts)),
                       remote_backends=(_pane(),))
    try:
        first = agent.run("read")
        hosts[:] = ["other.example:22"]  # changed in Agent Settings while the tab is open
        server.replies[:] = [{"tool_calls": [_read_remote()]}, {"content": "done"}]
        second = agent.run("read again")
    finally:
        agent.close()
    assert first.calls[0]["outcome"] == "ok"
    assert second.calls[0]["outcome"] == "error"


def test_edge_a_production_pane_stays_read_only_through_the_sandbox(fake, tmp_path):
    ram = _ram()
    server = fake({"tool_calls": [_call("write_file", {"path": "/data/n.txt", "content": "x",
                                                       "backend": "pane:box"})]},
                  {"content": "ok"})
    agent = _sandboxed(server, tmp_path, SB.SandboxProfile(name="L", level="lax"),
                       confirm=lambda n, a: True, remote_backends=(_pane(ram, production=True),),
                       allow_write=True)
    try:
        result = agent.run("write")
    finally:
        agent.close()
    assert result.calls[0]["outcome"] == "error" and not ram.exists("/data/n.txt")


def test_sad_a_vanished_sandbox_profile_refuses_everything(tmp_path):
    """Renamed or deleted in Agent Settings while a tab uses it: never a
    run without the sandbox - the host tools refuse and no worker starts."""
    current = {"p": SB.SandboxProfile(name="Lax", level="lax")}
    sent = []
    config = A.AgentConfig(profile=LLMProfile(name="x", provider="lmstudio", endpoint="http://127.0.0.1:9/v1"),
                           root=str(tmp_path), remote_backends=(_pane(),))
    agent = SB.SandboxedAgent(config, lambda: current["p"], command=SB.worker_argv())
    agent._send = sent.append
    msg = {"type": "host_tool", "id": 1, "name": "read_file",
           "args": {"path": "/data/f.txt", "encoding": "text", "backend": "pane:box"}}
    agent._answer_host_tool(msg, wait=True)
    current["p"] = None
    agent._answer_host_tool(msg, wait=True)
    assert sent[0]["value"]["outcome"] == "ok"
    assert sent[1]["value"]["outcome"] == "error" and "remote text" not in sent[1]["value"]["text"]
    with pytest.raises(A.AgentError, match="no longer exists"):
        agent.run("anything")
    assert agent._proc is None
    agent.close()
