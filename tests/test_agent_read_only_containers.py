"""Files read-only, made precise: a tool of an MCP server stays offered
under "Files read-only" - also when the server asks before every call - only
when the server cannot change the user's files: a container server on
axross's own podman line (core.mcp_install.run_command) with no network
and only read-only folders. Everything else is left out as before, and
the server's confirm mode still asks at every call."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import agent as A  # noqa: E402
from core import agent_profiles as AP  # noqa: E402
from core import mcp_client as C  # noqa: E402
from core import mcp_install as I  # noqa: E402
from tests.mcp_podman_testkit import fake_podman  # noqa: E402

IMAGE = "ghcr.io/c0decave/sleuthkit@sha256:" + "a" * 64
FW = "Security: Firmware & Forensics"


def _container(name="tsk", *, network="none", mounts=(("/srv/evidence", "/evidence", False),),
               confirm="always", **kw):
    command = I.run_command(name, IMAGE, network=network, mounts=mounts)
    return C.McpServerConfig(name=name, command=tuple(command), container=True,
                             confirm=confirm, category=FW,
                             egress=("api.example:443",) if network == "allowlist" else (),
                             **kw)


# -- happy -----------------------------------------------------------------------


def test_happy_a_read_only_container_without_network_cannot_change_files():
    server = _container()
    assert server.problems() == []
    assert server.files_risk() == "" and server.files_safe()
    assert _container(mounts=()).files_safe()  # no folder at all
    assert _container(mounts=(("/a", "/a", False), ("/b", "/b", False))).files_safe()


def test_happy_read_only_keeps_its_tools_and_the_call_still_asks():
    tool = C.ExternalTool(name="tsk__ls", description="", schema={}, write=True, client=None,
                          remote_name="ls", always_ask=True, files_safe=True)
    other = C.ExternalTool(name="x__ls", description="", schema={}, write=True, client=None,
                           remote_name="ls", always_ask=True)
    config = A.read_only(A.AgentConfig(profile=None, root="/", files_read_only=True,
                                       external_tools=lambda: ([tool, other], [])))
    assert [t.name for t in config.external_tools()[0]] == ["tsk__ls"]
    assert not A.may_change_files(tool) and A.may_change_files(other)
    assert A.needs_confirmation(tool.name, write=tool.write, group=tool.group)  # still asks
    spec = A.tool_spec(tool)
    assert spec["files_safe"] is True and not A.may_change_files(spec)


def test_happy_e2e_forensics_read_only_offers_a_contained_server_and_asks(tmp_path,
                                                                          monkeypatch):
    from tests.test_agent_loop import _call
    from tests.test_agent_profiles_dock import _mcp_tools
    from tests.test_agent_tabs import Env, say

    fake_podman(tmp_path, monkeypatch)
    env = Env(tmp_path)
    env.mcp_pool = C.McpClientPool(token_lookup=lambda name: "")
    env.settings.access.mcp_servers = True
    env.settings.mcp_servers = [_container()]
    server = env.fake({"tool_calls": [_call("tsk__env", {})]}, {"content": "done"})
    try:
        tab = env.dock().new_tab_from_profile("Forensics read-only")
        assert tab.files_read_only()
        say(tab, "list the evidence")
        assert _mcp_tools(server.requests[0]) == {"tsk__env"}
        assert [n for n, _a in env.asked] == ["tsk__env"]  # "Every call asks" still asks
        assert "envfile" in tab.transcript.toPlainText() or len(server.requests) == 2
    finally:
        env.close()
        env.mcp_pool.close_all()


# -- sad -------------------------------------------------------------------------


@pytest.mark.parametrize("server, why", [
    (lambda: _container(mounts=(("/srv/evidence", "/evidence", True),)), "writable"),
    (lambda: _container(mounts=(("/a", "/a", False), ("/b", "/b", True))), "writable"),
    (lambda: _container(network="allowlist"), "network"),
    (lambda: _container(network="full"), "network"),
    (lambda: C.McpServerConfig(name="git", command=("mcp-server-git",)), "outside a container"),
    (lambda: C.McpServerConfig(name="web", transport="http", url="http://127.0.0.1:7/mcp"),
     "HTTP"),
])
def test_sad_anything_else_is_dropped_under_read_only(server, why):
    config = server()
    assert config.problems() == []
    assert not config.files_safe()
    assert why in config.files_risk()


def test_sad_e2e_a_writable_mount_keeps_the_server_out(tmp_path, monkeypatch):
    from tests.test_agent_profiles_dock import _mcp_tools, _plain
    from tests.test_agent_tabs import Env, say

    fake_podman(tmp_path, monkeypatch)
    env = Env(tmp_path)
    env.mcp_pool = C.McpClientPool(token_lookup=lambda name: "")
    env.settings.access.mcp_servers = True
    env.settings.mcp_servers = [_container(mounts=(("/srv/evidence", "/evidence", True),))]
    server = env.fake({"content": "ok"})
    try:
        tab = env.dock().new_tab_from_profile("Forensics read-only")
        say(tab, "look")
        assert _mcp_tools(server.requests[0]) == set()
        note = _plain(tab.profile_notes)
        assert "none of tsk's tools is offered" in note and "writable" in note
    finally:
        env.close()
        env.mcp_pool.close_all()


# -- edge ------------------------------------------------------------------------


@pytest.mark.parametrize("command", [
    ["bash", "-c", "rm -rf ~"],                                  # no podman at all
    ["podman", "run", "--network=none", IMAGE],                  # not axross's hardening
    ["podman", "create", *I.RUN_FLAGS, "--network=none", IMAGE],  # not "run"
    [*I.run_command("x", IMAGE)[:-1], "--env=LD_PRELOAD=/x", IMAGE],  # an option of its own
    [*I.run_command("x", IMAGE)[:-1], "--network=none", IMAGE],  # the network twice
    I.run_command("x", IMAGE)[:-1],                              # no image
    ["/opt/docker", *I.run_command("x", IMAGE)[1:]],             # another program
])
def test_edge_a_hand_edited_container_line_does_not_qualify(command):
    """McpServerConfig.from_dict keeps container=true when the line has no
    widening flag (core.mcp_client.containment_problems ->
    core.mcp_runner.container_flag_problems is a list of forbidden options,
    it does not say the line is axross's): files_safe recognises the line."""
    raw = {"name": "x", "transport": "stdio", "command": command, "container": True}
    config = C.McpServerConfig.from_dict(raw)
    if config is None:  # refused outright: never offered at all
        return
    assert config.container
    assert not config.files_safe() and config.files_risk()


def test_edge_bash_passes_today_s_validation_and_still_does_not_qualify():
    config = C.McpServerConfig.from_dict({"name": "x", "command": ["bash", "-c", "id"],
                                          "container": True})
    assert config is not None and config.container  # what validation guarantees: no more
    assert "podman line" in config.files_risk()


def test_edge_research_keeps_files_writable_off_instead_of_read_only():
    research = AP.preset("Research")
    assert not research.files_read_only and not research.allow_write and not research.allow_exec
    assert "network" in research.description and "read-only" in research.description


def test_edge_the_preview_says_why_a_server_is_dropped_under_read_only():
    s = AP.resolve(AP.preset("Forensics read-only"), _settings(
        _container("tsk"), _container("wide", network="full"),
        C.McpServerConfig(name="host", command=("mcp-host",), category=FW)))
    text = "\n".join(s.notes)
    assert "tsk" not in text
    assert "none of wide's tools is offered" in text and "network" in text
    assert "none of host's tools is offered" in text and "outside a container" in text


def _settings(*servers):
    from core import agent_settings as S

    s = S.AgentSettings()
    s.access.axross_functions = s.access.mcp_servers = True
    s.mcp_servers = list(servers)
    return s


DOC_FILES = {"USAGE.md": "**Files read-only**", "USAGE_de.md": "**Files read-only**",
             "USAGE_es.md": "**Files read-only**"}


@pytest.mark.parametrize("name", DOC_FILES)
def test_happy_each_handbook_explains_the_precise_rule(name):
    root = Path(__file__).resolve().parent.parent
    text = (root / "docs" / name).read_text(encoding="utf-8")
    start = text.index(DOC_FILES[name])
    paragraph = " ".join(text[start:text.index("\n\n", start)].split())
    for needle in ("`--network=none`", "`:ro`", "Every call asks"):
        assert needle in paragraph, (name, needle)
    table = next(line for line in text.splitlines() if line.startswith("| Research |"))
    assert "read-only" not in table or "not" in table.lower() or "nicht" in table \
        or "no " in table


def test_happy_the_settings_and_the_tab_say_the_rule():
    import os

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])  # noqa: F841 - kept alive
    from ui.agent_settings_dialog import AgentSettingsDialog

    dlg = AgentSettingsDialog(settings_path=Path("/nonexistent/agent.json"))
    try:
        tip = dlg.files_read_only_check.toolTip()
        assert "container" in tip and "network" in tip and "read-only folders" in tip
        assert "container" in dlg.access_note.text()
    finally:
        dlg.deleteLater()


class _Ext:
    """An MCP server's tool as core.agent runs it (no server behind it)."""

    def __init__(self, name, files_safe, calls):
        self.name, self.files_safe, self._calls = name, files_safe, calls
        self.description, self.schema, self.write, self.group = "", {"type": "object"}, True, "mcp"
        self.always_ask, self.external, self.client, self.accepts_backend = True, True, None, False

    def call(self, args):
        self._calls.append(self.name)
        return "ok", "listed"


def test_happy_the_agent_runs_a_files_safe_tool_under_read_only_after_asking(tmp_path):
    from tests.test_agent_loop import _call

    calls, asked = [], []
    tools = [_Ext("tsk__ls", True, calls), _Ext("git__commit", False, calls)]
    agent = A.Agent(A.AgentConfig(profile=None, root=str(tmp_path), files_read_only=True,
                                  external_tools=lambda: (tools, [])),
                    confirm=lambda name, args: asked.append(name) or True)
    agent._load_external()
    assert set(agent._external) == {"tsk__ls"}
    assert agent._run_tool(_call("tsk__ls", {}))[1] == "ok"
    assert asked == ["tsk__ls"] and calls == ["tsk__ls"]
    agent._external["git__commit"] = tools[1]  # slipped in: still refused at the call
    assert agent._run_tool(_call("git__commit", {}))[1] == "declined"
    assert calls == ["tsk__ls"]


def test_sad_a_worker_cannot_call_an_axross_write_tool_files_safe(tmp_path):
    """Only a tool of an MCP server can be files_safe: a sandboxed worker
    that marks axross's own write tool so is refused in axross."""
    from tests.test_agent_loop import _call

    ran = []
    specs = [{"name": "write_file", "description": "w", "schema": {"type": "object"},
              "write": True, "group": "files", "files_safe": True},
             {"name": "tsk__ls", "description": "l", "schema": {"type": "object"},
              "write": True, "group": "mcp", "files_safe": True}]
    agent = A.Agent(A.AgentConfig(profile=None, root=str(tmp_path), files_read_only=True),
                    host_tools=specs, host_call=lambda n, a: ran.append(n) or ("ok", "done"),
                    confirm=lambda *_: True)
    assert agent._run_tool(_call("write_file", {"path": "/x", "backend": "pane:b"}))[1] \
        == "declined"
    assert ran == []
    assert A.may_change_files(specs[0]) and not A.may_change_files(specs[1])
