"""Files read-only: the agent may read files but never change them.

Operator punch list item 11: "es sollte bei agent permission im dock und
settings auch was geben das sagt files only read-only, sodass ein agent
dateien zwar lesen kann aber nicht schreiben".

What existed: a per-tab "Allow changes to files" checkbox hidden under the
dock's Tools ▸ (off by default) and the paranoid sandbox level, which mounts
the folder read-only. Neither is a switch in Agent Settings, and with
changes off a tab still offered remote commands and the write tools of MCP
servers and extensions. "Files read-only" - per tab in the dock's head, and
for every tab in Agent Settings > Access - is enforced in core.agent: no
write tool is built or run, no remote command (it can change files), extra
folders are read-only, a sandbox mounts nothing writable.
"""

from __future__ import annotations

import base64
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import agent as A  # noqa: E402
from core import agent_settings as AGS  # noqa: E402
from core.agent_session import AgentSession  # noqa: E402
from core.llm_profiles import LLMProfile  # noqa: E402
from tests.test_agent_loop import _call  # noqa: E402
from tests.test_agent_tabs import Env, say  # noqa: E402

PROFILE = LLMProfile(name="local", provider="lmstudio", endpoint="http://127.0.0.1:9/v1",
                     model="tiny")
ORIGINAL_B64 = base64.b64encode(b"original").decode()
#: Every group a tab can offer, plus remote commands and saved connections.
ALL_GROUPS = frozenset(AGS.OFFERED_GROUPS) | {"exec", "remote"}


def _config(root, **kw) -> A.AgentConfig:
    base = dict(profile=PROFILE, root=str(root), groups=ALL_GROUPS, allow_write=True,
                allow_exec=True)
    base.update(kw)
    return A.AgentConfig(**base)


def _write_tools(root) -> list[str]:
    """The mutating tools an agent with changes allowed is offered."""
    agent = A.Agent(_config(root))
    return sorted(t.name for t in agent._tool_list if t.write or t.group == "exec")


class _Script:
    """A model that calls *calls* once, then answers."""

    def __init__(self, calls):
        self.calls = list(calls)
        self.bodies = []

    def __call__(self, body):
        self.bodies.append(body)
        if self.calls:
            calls, self.calls = self.calls, []
            return {"choices": [{"message": {"role": "assistant", "content": "",
                                             "tool_calls": calls}}]}
        return {"choices": [{"message": {"role": "assistant", "content": "done"}}]}


@pytest.fixture
def root(tmp_path):
    r = tmp_path / "work"
    r.mkdir()
    (r / "keep.txt").write_text("original")
    (r / "sub").mkdir()
    return r


# --- core: happy ----------------------------------------------------------------


def test_happy_read_only_builds_no_write_and_no_exec_tool(root) -> None:
    assert _write_tools(root), "the comparison needs write tools to exist"
    agent = A.Agent(_config(root, files_read_only=True))
    assert [t.name for t in agent._tool_list if t.write or t.group == "exec"] == []
    assert {"read_file", "list_dir", "stat"} <= {t.name for t in agent._tool_list}
    assert agent.config.allow_write is False and agent.config.allow_exec is False


def test_happy_every_write_tool_is_refused_and_the_files_stay(root) -> None:
    names = _write_tools(root)
    agent = A.Agent(_config(root, files_read_only=True), confirm=lambda *_: True)
    for name in names:
        tool, outcome, text = agent._run_tool(
            _call(name, {"path": str(root / "keep.txt"), "content": "changed",
                         "src": str(root / "keep.txt"), "dst": str(root / "moved.txt")})
        )
        assert outcome == "unavailable", (name, outcome, text)
    assert (root / "keep.txt").read_text() == "original"
    assert sorted(p.name for p in root.iterdir()) == ["keep.txt", "sub"]


def test_happy_reads_still_work_in_a_whole_run(root) -> None:
    model = _Script([
        _call("read_file", {"path": str(root / "keep.txt")}, "r1"),
        _call("write_file", {"path": str(root / "keep.txt"), "content": "x"}, "w1"),
        _call("remove", {"path": str(root / "keep.txt")}, "d1"),
    ])
    result = A.Agent(_config(root, files_read_only=True), transport=model,
                     confirm=lambda *_: True).run("read and change")
    outcomes = {c["name"]: c["outcome"] for c in result.calls}
    assert outcomes == {"read_file": "ok", "write_file": "unavailable", "remove": "unavailable"}
    tool_answers = [m for m in model.bodies[1]["messages"] if m["role"] == "tool"]
    assert ORIGINAL_B64 in tool_answers[0]["content"]  # read_file answers in base64
    offered = {t["function"]["name"] for t in model.bodies[0]["tools"]}
    assert not offered & set(_write_tools(root))
    assert (root / "keep.txt").read_text() == "original"


# --- core: sad ------------------------------------------------------------------------


def test_sad_a_write_tool_slipped_in_is_still_refused_at_the_call(root) -> None:
    """Defense in depth: the call is checked, not only the offer."""
    writer = next(t for t in A.Agent(_config(root))._tool_list if t.name == "write_file")
    agent = A.Agent(_config(root, files_read_only=True), confirm=lambda *_: True)
    agent._tools["write_file"] = writer
    _name, outcome, text = agent._run_tool(
        _call("write_file", {"path": str(root / "keep.txt"), "content": "x"})
    )
    assert outcome == "declined" and "read-only" in text
    assert (root / "keep.txt").read_text() == "original"


def test_sad_external_write_tools_are_dropped_and_refused(root) -> None:
    calls = []
    reader = A.FunctionTool(name="ext_read", description="r", schema={"type": "object"},
                            handler=lambda a: calls.append("read") or "ok", write=False)
    writer = A.FunctionTool(name="ext_write", description="w", schema={"type": "object"},
                            handler=lambda a: calls.append("write") or "ok", write=True)
    agent = A.Agent(_config(root, files_read_only=True, external_tools=lambda: ([reader, writer],
                                                                                    [])),
                    confirm=lambda *_: True)
    agent._load_external()
    assert set(agent._external) == {"ext_read"}
    assert agent._run_tool(_call("ext_write", {}))[1] == "unavailable"
    assert agent._run_tool(_call("ext_read", {}))[1] == "ok"
    # and if one gets in anyway, the call refuses it
    agent._external["ext_write"] = writer
    assert agent._run_tool(_call("ext_write", {}))[1] == "declined"
    assert calls == ["read"]


def test_sad_a_host_write_tool_is_refused_for_a_sandboxed_agent(root) -> None:
    """A worker that offers a write tool anyway is refused in axross."""
    spec = {"name": "write_file", "description": "w", "schema": {"type": "object"},
            "write": True, "group": "files"}
    ran = []
    agent = A.Agent(_config(root, files_read_only=True), host_tools=[spec],
                    host_call=lambda n, a: ran.append(n) or ("ok", "written"),
                    confirm=lambda *_: True)
    _name, outcome, text = agent._run_tool(_call("write_file", {"path": "/x", "backend": "pane:b"}))
    assert outcome == "declined" and ran == []


# --- core: edge -----------------------------------------------------------------------


def test_edge_extra_folders_turn_read_only(root, tmp_path) -> None:
    extra = tmp_path / "extra"
    extra.mkdir()
    config = A.restrict(_config(root, files_read_only=True, extra_roots=((str(extra), True),)))
    assert config.extra_roots == ((str(extra), False),)


def test_edge_restrict_applies_without_a_function_limit(root) -> None:
    """functions=None (the MCP group's agent, tests) is no way around it."""
    config = A.restrict(_config(root, files_read_only=True, functions=None))
    assert (config.allow_write, config.allow_exec, "exec" in config.groups) == (False, False, False)


def test_edge_the_sandbox_gets_no_writable_folder_and_the_flag(root, monkeypatch) -> None:
    from core import agent_sandbox as SB

    sent = []
    agent = SB.SandboxedAgent(_config(root, files_read_only=True), None, command=["true"])
    monkeypatch.setattr(agent, "_send", sent.append)
    agent._start_message(None)
    start = sent[0]["config"]
    assert start["allow_write"] is False and start["files_read_only"] is True
    assert agent.config.allow_write is False  # sandbox_command(writable=...) reads this


def test_edge_the_worker_keeps_it_read_only(root) -> None:
    from core import agent_worker as W

    config = W._config_from({"root": str(root), "allow_write": True, "files_read_only": True,
                             "groups": ["archive"]})
    agent = A.Agent(config, transport=_Script([]))
    assert [t.name for t in agent._tool_list if t.write] == []


# --- settings and session ------------------------------------------------------------


def test_happy_settings_and_sessions_store_the_switch(tmp_path) -> None:
    s = AGS.AgentSettings()
    s.access.files_read_only = True
    s.save(tmp_path / "s.json")
    assert AGS.AgentSettings.load(tmp_path / "s.json").access.files_read_only is True
    session = AgentSession(files_read_only=True)
    assert AgentSession.from_dict(session.to_dict()).files_read_only is True


def test_sad_a_non_bool_switch_in_the_files_is_ignored() -> None:
    assert AGS.AgentSettings.from_dict({"access": {"files_read_only": "yes"}}).access \
        .files_read_only is False
    data = AgentSession().to_dict()
    data["files_read_only"] = 1
    assert AgentSession.from_dict(data).files_read_only is False


# --- the dock and the settings dialog (e2e) ----------------------------------------


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    yield e
    e.close()


def test_happy_e2e_the_dock_switch_refuses_a_write_and_still_reads(env) -> None:
    (env.root / "keep.txt").write_text("original")
    server = env.fake(
        {"tool_calls": [
            _call("read_file", {"path": str(env.root / "keep.txt")}, "r1"),
            _call("write_file", {"path": str(env.root / "keep.txt"), "content": "x"}, "w1"),
        ]},
        {"content": "ok"},
    )
    tab = env.dock().current_tab()
    tab.allow_write.setChecked(True)
    tab.mode_combo.setCurrentIndex(tab.mode_combo.findData("auto"))
    assert tab.read_only_check.isVisibleTo(tab)  # in the head, not under Tools ▸
    tab.read_only_check.setChecked(True)
    assert not tab.allow_write.isEnabled() and not tab.allow_exec.isEnabled()
    say(tab, "read, then change")
    offered = {t["function"]["name"] for t in server.requests[0]["tools"]}
    assert "read_file" in offered and "write_file" not in offered
    assert (env.root / "keep.txt").read_text() == "original"
    tool_msgs = [m for m in server.requests[1]["messages"] if m["role"] == "tool"]
    assert ORIGINAL_B64 in tool_msgs[0]["content"]
    assert tab.session.files_read_only is True


def test_edge_e2e_agent_settings_make_every_tab_read_only(env) -> None:
    env.settings.access.files_read_only = True
    env.fake({"content": "ok"})
    tab = env.dock().current_tab()
    assert tab.read_only_check.isChecked() and not tab.read_only_check.isEnabled()
    assert "Agent Settings" in tab.read_only_check.toolTip()
    tab.allow_write.setChecked(True)
    config = tab._config(tab.profile(), mode="auto")
    assert config.files_read_only is True
    assert A.restrict(config).allow_write is False


def test_happy_e2e_the_settings_dialog_has_the_switch(tmp_path, monkeypatch) -> None:
    from PyQt6.QtWidgets import QApplication

    from ui.agent_settings_dialog import AgentSettingsDialog

    _ = QApplication.instance() or QApplication([])
    monkeypatch.setattr(AGS, "settings_file", lambda: tmp_path / "agent" / "settings.json")
    dialog = AgentSettingsDialog()
    try:
        box = dialog.files_read_only_check
        assert not box.isChecked()
        box.setChecked(True)
        assert dialog.save()
        assert AGS.AgentSettings.load().access.files_read_only is True
    finally:
        dialog.deleteLater()


def test_edge_the_write_tools_compared_cover_files_groups_and_commands(root) -> None:
    """The refusal test above walks a real, wide list - not an empty one."""
    names = set(_write_tools(root))
    assert {"write_file", "remove", "rename", "mkdir", "copy", "chmod"} <= names
    assert {"transfer_move", "archive_extract", "metadata_remove", "encrypt"} <= names
    assert {"remote_exec", "remote_script"} <= names


def test_edge_negative_control_without_the_switch_the_same_call_writes(root) -> None:
    """The refusals above come from the switch, not from a broken call."""
    agent = A.Agent(_config(root), confirm=lambda *_: True)
    _name, outcome, _text = agent._run_tool(
        _call("write_file", {"path": str(root / "keep.txt"), "content": "changed"})
    )
    assert outcome == "ok"
    assert (root / "keep.txt").read_text() == "changed"


# --- round-2 verification: a sandbox profile's own folders --------------------------


def _sandbox_mounts(argv: list[str]) -> dict[str, str]:
    """``path -> "rw"|"ro"`` of the folders a bwrap command line binds."""
    out: dict[str, str] = {}
    for i, arg in enumerate(argv):
        if arg in ("--bind", "--ro-bind") and i + 2 < len(argv):
            out[argv[i + 2]] = "rw" if arg == "--bind" else "ro"
    return out


@pytest.mark.parametrize("level", ["lax", "normal"])
def test_sad_a_sandbox_profiles_writable_folder_is_mounted_read_only(
    root, tmp_path, monkeypatch, level
) -> None:
    """Files read-only covers the folders a sandbox profile mounts too: on
    the lax and normal levels those keep their read-write flag, and a
    subverted worker could otherwise write there - the kernel mount is the
    layer that does not trust the worker."""
    from core import agent_sandbox as SB

    shared = tmp_path / "shared"
    shared.mkdir()
    monkeypatch.setattr(SB, "available", lambda engine: True)
    profile = SB.SandboxProfile(name="P", engine="bubblewrap", level=level,
                                mounts=((str(shared), True),))
    agent = SB.SandboxedAgent(_config(root, files_read_only=True), profile)
    mounts = _sandbox_mounts(agent._argv(profile))
    assert mounts[str(shared)] == "ro", mounts
    assert mounts[str(root)] == "ro", mounts
    sent = []
    monkeypatch.setattr(agent, "_send", sent.append)
    agent._start_message(profile)
    assert [p for p, rw in sent[0]["config"]["extra_roots"] if rw] == []


def test_edge_negative_control_without_the_switch_the_profile_folder_stays_writable(
    root, tmp_path, monkeypatch
) -> None:
    """The level's rule is unchanged for a tab that may change files."""
    from core import agent_sandbox as SB

    shared = tmp_path / "shared"
    shared.mkdir()
    monkeypatch.setattr(SB, "available", lambda engine: True)
    profile = SB.SandboxProfile(name="P", engine="bubblewrap", level="normal",
                                mounts=((str(shared), True),))
    agent = SB.SandboxedAgent(_config(root), profile)
    assert _sandbox_mounts(agent._argv(profile))[str(shared)] == "rw"
