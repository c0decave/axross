"""What one agent tab may reach (core.agent_access): its axross functions,
its network and its folders. Agent Settings > Access is the ceiling, the
tab's session chooses within it; the agent itself checks again."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import agent as A  # noqa: E402
from core import agent_access as X  # noqa: E402
from core import agent_sandbox as SB  # noqa: E402
from core import agent_settings as S  # noqa: E402
from core.agent_session import AgentSession  # noqa: E402
from core.llm_profiles import LLMProfile  # noqa: E402
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


def _ceiling(**on) -> S.Access:
    access = S.Access(
        axross_functions=True,
        remote_files=True,
        saved_profiles=True,
        remote_commands=True,
        mcp_servers=True,
        extensions=True,
    )
    for name, value in on.items():
        setattr(access, name, value)
    return access


def _bwrap(level, **kw):
    return SB.SandboxProfile(name=level.title(), engine="bubblewrap", level=level, **kw)


# -- the session's access: saved and read back ------------------------------------


def test_happy_the_access_of_a_session_is_saved_and_read_back():
    session = AgentSession()
    session.access = X.SessionAccess(axross=True, functions=("mcp_servers",), network="hosts",
                                     hosts=("db.example:5432", "[::1]:8080"))
    back = AgentSession.from_dict(session.to_dict())
    assert back.access == session.access


def test_sad_a_broken_access_entry_is_cleaned():
    data = AgentSession().to_dict()
    data["access"] = {
        "axross": "yes",
        "functions": ["mcp_servers", "rm -rf", 5],
        "network": "everything",
        "hosts": ["db.example", "ok.example:22", 7, "*:1"],
    }
    access = AgentSession.from_dict(data).access
    assert access.axross is False
    assert access.functions == ("mcp_servers",)
    assert access.network == "profile"
    assert access.hosts == ("ok.example:22",)


def test_edge_a_session_from_before_has_no_access_of_its_own():
    data = AgentSession().to_dict()
    data.pop("access", None)
    assert AgentSession.from_dict(data).access is None


def test_happy_new_tabs_take_the_settings_as_their_access():
    settings = S.AgentSettings()
    settings.access = _ceiling(extensions=False)
    access = X.SessionAccess.from_settings(settings.access)
    assert access.axross is True
    assert access.functions == X.FUNCTIONS  # the tab's own choice: everything the ceiling allows
    allowed = X.allowed_functions(settings.access, access)
    assert "extensions" not in allowed and "mcp_servers" in allowed


# -- axross functions: the ceiling and the tab's choice ------------------------------


def test_happy_a_function_needs_the_settings_and_the_tab():
    tab = X.SessionAccess(axross=True, functions=X.FUNCTIONS)
    assert X.allowed_functions(_ceiling(), tab) == frozenset(X.FUNCTIONS)
    assert X.allowed_functions(_ceiling(mcp_servers=False), tab) == frozenset(X.FUNCTIONS) - {
        "mcp_servers"
    }


def test_sad_the_master_switch_turns_every_function_off():
    tab = X.SessionAccess(axross=True, functions=X.FUNCTIONS)
    assert X.allowed_functions(_ceiling(axross_functions=False), tab) == frozenset()
    off = X.SessionAccess(axross=False, functions=X.FUNCTIONS)
    assert X.allowed_functions(_ceiling(), off) == frozenset()


def test_edge_the_settings_default_is_closed():
    settings = S.AgentSettings.from_dict({"version": 1})
    assert settings.access.axross_functions is False
    assert (
        X.allowed_functions(settings.access, X.SessionAccess.from_settings(settings.access))
        == frozenset()
    )
    back = S.AgentSettings.from_dict(
        S.AgentSettings(access=_ceiling(extensions=False)).to_dict()
    ).access
    assert back.axross_functions is True and back.extensions is False and back.mcp_servers is True


def test_happy_restrict_keeps_only_what_the_functions_allow(tmp_path):
    config = A.AgentConfig(
        profile=LLMProfile(name="x", provider="lmstudio", endpoint="http://127.0.0.1:9/v1"),
        root=str(tmp_path),
        groups=frozenset({"metadata", "remote", "exec"}),
        allow_exec=True,
        remote_backends=(("pane:nas", object(), None),),
        functions=frozenset(),
    )
    out = A.restrict(config)
    assert out.groups == frozenset({"metadata"})
    assert out.allow_exec is False and out.remote_backends == ()
    assert A.restrict(
        A.AgentConfig(
            profile=config.profile, root=str(tmp_path), groups=frozenset({"remote"}), functions=None
        )
    ).groups == frozenset({"remote"})


def test_happy_a_tool_belongs_to_its_function():
    ext = A.FunctionTool(name="ext_a__b", description="", schema={}, handler=lambda a: "")
    talk = A.FunctionTool(
        name="ask_user", description="", schema={}, handler=lambda a: "", outside=False
    )

    class _Mcp:
        name, outside, client = "srv__t", True, object()

    assert A.tool_allowed(ext, frozenset({"extensions"}))
    assert not A.tool_allowed(ext, frozenset({"mcp_servers"}))
    assert A.tool_allowed(_Mcp(), frozenset({"mcp_servers"}))
    assert not A.tool_allowed(_Mcp(), frozenset({"extensions"}))
    assert A.tool_allowed(talk, frozenset())  # reaches nothing outside: always
    assert A.tool_allowed(ext, None)


def test_sad_the_agent_never_offers_a_function_that_is_off(tmp_path):
    server = _Fake([{"tool_calls": [_call("ext_db__drop", {})]}, {"content": "ok"}])
    ran = []
    try:
        tool = A.FunctionTool(name="ext_db__drop", description="", schema={"type": "object"},
                              handler=lambda args: ran.append(1) or "dropped")
        config = A.AgentConfig(
            profile=LLMProfile(name="l", provider="lmstudio", endpoint=server.url, model="m"),
            root=str(tmp_path),
            external_tools=lambda: ([tool], []),
            functions=frozenset({"mcp_servers"}),
        )
        A.Agent(config, confirm=lambda n, a: True).run("drop it")
    finally:
        server.close()
    offered = [t["function"]["name"] for t in server.requests[0].get("tools", [])]
    assert "ext_db__drop" not in offered and ran == []
    assert "not available" in _tool_messages(server.requests[1])[0]["content"]


def test_sad_a_sandboxed_agent_offers_and_runs_no_function_that_is_off(tmp_path):
    tool = A.FunctionTool(name="ext_db__drop", description="", schema={"type": "object"},
                          handler=lambda args: "dropped")
    talk = A.FunctionTool(name="ask_user", description="", schema={"type": "object"},
                          handler=lambda args: "yes", outside=False)
    config = A.AgentConfig(
        profile=LLMProfile(name="x", provider="lmstudio", endpoint="http://127.0.0.1:9/v1"),
        root=str(tmp_path),
        external_tools=lambda: ([tool, talk], []),
        functions=frozenset(),
    )
    agent = SB.SandboxedAgent(config, _bwrap("lax"), command=SB.worker_argv())
    sent = []
    agent._send = sent.append
    agent._load_external()
    assert [s["name"] for s in agent._host_specs(_bwrap("lax"))] == ["ask_user"]
    agent._answer_host_tool(
        {"type": "host_tool", "id": 1, "name": "ext_db__drop", "args": {}}, wait=True
    )
    agent.close()
    assert (
        sent[0]["value"]["outcome"] in ("error", "unavailable")
        and "dropped" not in sent[0]["value"]["text"]
    )


# -- the network of a tab -------------------------------------------------------------


def test_happy_only_these_hosts_replaces_the_profiles_list():
    profile = _bwrap("normal", hosts=("db.example:5432",))
    out = X.session_profile(profile, X.SessionAccess(network="hosts", hosts=("api.example:443",)))
    assert out.allows("api.example", 443) and not out.allows("db.example", 5432)
    assert out.name == profile.name and out.level == "normal"
    assert profile.hosts == ("db.example:5432",)  # the profile itself is untouched


def test_happy_none_cuts_even_a_lax_sandbox_off():
    out = X.session_profile(_bwrap("lax"), X.SessionAccess(network="none"))
    assert out.network == "none" and not out.allows("anything.example", 80)
    argv = SB.sandbox_command(out, "/tmp", writable=False)
    assert "--share-net" not in argv


def test_happy_hosts_on_a_lax_sandbox_goes_through_the_relay():
    out = X.session_profile(_bwrap("lax"), X.SessionAccess(network="hosts", hosts=("a.example:1",)))
    assert out.network == "allowlist"
    assert "--share-net" not in SB.sandbox_command(out, "/tmp", writable=False)
    assert out.allows("a.example", 1) and not out.allows("b.example", 1)


def test_sad_a_tab_never_opens_more_than_its_level():
    assert (
        X.session_profile(
            _bwrap("paranoid"), X.SessionAccess(network="hosts", hosts=("a.example:1",))
        ).network
        == "none"
    )
    normal = X.session_profile(
        _bwrap("normal", hosts=("db.example:5432",)), X.SessionAccess(network="all")
    )
    assert normal.network == "allowlist" and not normal.allows("other.example", 80)
    assert normal.allows("db.example", 5432)


def test_edge_the_choices_follow_the_level():
    assert X.network_choices(None) == ("profile", "none", "hosts", "all")
    assert X.network_choices(_bwrap("lax")) == ("profile", "none", "hosts", "all")
    assert X.network_choices(_bwrap("normal")) == ("profile", "none", "hosts")
    assert X.network_choices(_bwrap("paranoid")) == ("profile", "none")
    assert X.session_profile(None, X.SessionAccess(network="none")) is None


def test_happy_the_firewall_without_a_sandbox():
    assert X.firewall(X.SessionAccess(network="profile")) is None
    assert X.firewall(X.SessionAccess(network="all")) is None
    none = X.firewall(X.SessionAccess(network="none"))
    assert none("a.example", 1) is False
    hosts = X.firewall(X.SessionAccess(network="hosts", hosts=("a.example:1",)))
    assert hosts("A.example", 1) and not hosts("a.example", 2)


def test_sad_the_firewall_closes_remote_work_in_axross(tmp_path):
    from core.profiles import ConnectionProfile

    access = X.SessionAccess(network="hosts", hosts=("ok.example:22",))
    config = A.AgentConfig(
        profile=LLMProfile(name="x", provider="lmstudio", endpoint="http://127.0.0.1:9/v1"),
        root=str(tmp_path),
        groups=frozenset({"remote"}),
        firewall=X.firewall(access),
    )
    agent = A.Agent(config)
    with pytest.raises(PermissionError):
        agent._registry._gate(
            ConnectionProfile(name="n", protocol="sftp", host="other.example", port=22)
        )
    agent._registry._gate(ConnectionProfile(name="n", protocol="sftp", host="ok.example", port=22))
    agent.close()


def test_sad_a_sandboxed_agent_follows_the_tabs_network_live(tmp_path):
    access = X.SessionAccess(network="hosts", hosts=("a.example:1",))
    profile = _bwrap("normal", hosts=("db.example:5432",))
    config = A.AgentConfig(profile=LLMProfile(name="x", provider="lmstudio", endpoint="http://127.0.0.1:9/v1"),
                           root=str(tmp_path))
    agent = SB.SandboxedAgent(
        config, lambda: X.session_profile(profile, access), command=SB.worker_argv()
    )
    assert agent._host_allowed("a.example", 1) and not agent._host_allowed("db.example", 5432)
    access.network = "none"
    assert not agent._host_allowed("a.example", 1)
    agent.close()


# -- the folders of a tab ---------------------------------------------------------------


def _binds(argv):
    return {argv[i + 1]: a for i, a in enumerate(argv) if a in ("--bind", "--ro-bind")}


def test_happy_a_read_write_folder_of_the_tab_is_writable_where_the_level_allows(tmp_path):
    extra = tmp_path / "share"
    extra.mkdir()
    argv = SB.sandbox_command(_bwrap("normal"), str(tmp_path / "w"), writable=True,
                              extra=((str(extra), True),))
    assert _binds(argv)[str(extra)] == "--bind"


def test_sad_high_and_a_read_only_tab_keep_the_folder_read_only(tmp_path):
    extra = tmp_path / "share"
    extra.mkdir()
    high = SB.sandbox_command(
        _bwrap("high"), str(tmp_path / "w"), writable=True, extra=((str(extra), True),)
    )
    assert _binds(high)[str(extra)] == "--ro-bind"
    readonly = SB.sandbox_command(_bwrap("normal"), str(tmp_path / "w"), writable=False,
                                  extra=((str(extra), True),))
    assert _binds(readonly)[str(extra)] == "--ro-bind"


def test_edge_an_attachment_stays_read_only(tmp_path):
    extra = tmp_path / "share"
    extra.mkdir()
    argv = SB.sandbox_command(
        _bwrap("lax"), str(tmp_path / "w"), writable=True, extra=((str(extra), False),)
    )
    assert _binds(argv)[str(extra)] == "--ro-bind"


def test_happy_the_worker_is_told_a_writable_folder_of_the_tab(tmp_path):
    extra = tmp_path / "share"
    extra.mkdir()
    config = A.AgentConfig(profile=LLMProfile(name="x", provider="lmstudio", endpoint="http://127.0.0.1:9/v1"),
                           root=str(tmp_path), allow_write=True, extra_roots=((str(extra), True),))
    agent = SB.SandboxedAgent(config, _bwrap("normal"), command=SB.worker_argv())
    sent = []
    agent._send = sent.append
    agent._out = None
    agent._start_message(_bwrap("normal"))
    agent.close()
    assert [str(extra), True] in sent[0]["config"]["extra_roots"]
