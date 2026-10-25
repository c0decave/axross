"""Agent profiles (core.agent_profiles): a named bundle of a tab's settings -
LLM profile, prompt profile, mode, sandbox, tool groups, axross functions,
files read-only and MCP servers by category or name - kept in the agent's
settings file, read as untrusted data, applied within Agent Settings >
Access (never wider), with built-in presets that are read-only."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import agent_profiles as AP  # noqa: E402
from core import agent_settings as S  # noqa: E402
from core import mcp_client as C  # noqa: E402
from core.agent_access import SessionAccess  # noqa: E402
from core.agent_session import AgentSession  # noqa: E402

RE = "Security: Reverse Engineering"
FW = "Security: Firmware & Forensics"


def _server(name, category="", enabled=True, **kw):
    return C.McpServerConfig(name=name, command=("mcp-" + name,), enabled=enabled,
                             category=category, **kw)


def _settings(*servers, axross=True, functions=("mcp_servers", "remote_files", "saved_profiles",
                                                 "remote_commands", "extensions")):
    s = S.AgentSettings()
    s.access.axross_functions = axross
    for name in ("remote_files", "saved_profiles", "remote_commands", "mcp_servers",
                 "extensions"):
        setattr(s.access, name, name in functions)
    s.mcp_servers = list(servers)
    return s


# -- happy ---------------------------------------------------------------------


def test_happy_a_profile_round_trips_through_the_settings_file(tmp_path):
    path = tmp_path / "settings.json"
    s = S.AgentSettings()
    s.agent_profiles = [AP.AgentProfile(
        name="Triage", llm_profile="big", prompt_profile="Default", mode="plan",
        sandbox="High", groups=("metadata", "index"), axross=True,
        functions=("mcp_servers",), network="hosts", hosts=("db.example:5432",),
        files_read_only=True, allow_write=False, allow_exec=False,
        mcp_categories=(RE,), mcp_servers=("git",), description="look only")]
    s.agent_profile = "Triage"
    s.save(path)
    back = S.AgentSettings.load(path)
    assert [p.to_dict() for p in back.agent_profiles] == [p.to_dict() for p in s.agent_profiles]
    assert back.agent_profile == "Triage"
    raw = json.loads(path.read_text())
    assert raw["agent_profiles"][0]["mcp_categories"] == [RE]


def test_happy_the_presets_are_there_read_only_and_match_the_real_catalogs():
    presets = AP.presets()
    names = [p.name for p in presets]
    assert names == ["Files Assistant", "Reverse Engineering", "Forensics read-only",
                     "Network & Web Recon", "Code & Secrets", "Remote Ops", "Research"]
    assert all(p.preset and not p.problems() for p in presets)
    by = {p.name: p for p in presets}
    # Categories as the c0decave hub and the shipped catalog name them.
    for p in presets:
        for category in p.mcp_categories:
            assert category in AP.known_categories(), category
    assert by["Reverse Engineering"].mcp_categories == (RE, FW)
    assert by["Reverse Engineering"].sandbox == "High"
    assert by["Forensics read-only"].files_read_only and by["Forensics read-only"].mcp_categories
    assert set(by["Network & Web Recon"].mcp_categories) == {
        "Security: Network Recon", "Security: Web", "Security: OSINT"}
    assert by["Network & Web Recon"].mode == "ask"
    assert set(by["Code & Secrets"].mcp_servers) == {"git", "filesystem"}
    assert by["Code & Secrets"].mcp_categories == ("Security: Code & Secrets",)
    assert {"remote_commands", "saved_profiles"} <= set(by["Remote Ops"].functions)
    assert by["Remote Ops"].mode == "ask" and by["Remote Ops"].allow_exec
    assert set(by["Research"].mcp_servers) == {"fetch", "memory", "sequentialthinking"}
    # Not read-only (fetch has network: read-only would drop it); no file changes.
    assert not by["Research"].files_read_only and not by["Research"].allow_write
    assert not by["Files Assistant"].mcp_categories and not by["Files Assistant"].mcp_servers
    assert "remote_files" in by["Files Assistant"].functions
    # Each call hands out fresh objects: editing one changes no preset.
    presets[0].groups = ()
    assert AP.presets()[0].groups


def test_happy_resolving_picks_servers_by_category_and_by_name():
    s = _settings(_server("r2", RE), _server("bw", FW), _server("nmap", "Security: Network Recon"),
                  _server("git", "Files & Dev"))
    res = AP.resolve(AP.preset("Reverse Engineering"), s)
    assert res.servers == ["bw", "r2"]
    assert {"mcp:r2", "mcp:bw"} <= set(res.groups) and "mcp:nmap" not in res.groups
    assert res.missing == [] and res.sandbox == "High"
    assert res.access.axross and "mcp_servers" in res.access.functions
    res = AP.resolve(AP.preset("Code & Secrets"), s)
    assert res.servers == ["git"]
    assert [(m.kind, m.name) for m in res.missing] == [
        ("server", "filesystem"), ("category", "Security: Code & Secrets")]


def test_happy_applying_sets_the_session_and_names_the_profile():
    s = _settings(_server("fetch", "Web & Data"))
    session = AgentSession(mode="auto", groups=["index"], allow_write=True)
    res = AP.resolve(AP.preset("Research"), s)
    res.apply_to(session, "Research")
    assert session.agent_profile == "Research"
    assert not session.files_read_only and not session.allow_write
    assert session.mode == "ask" and "mcp:fetch" in session.groups and "index" not in session.groups
    assert isinstance(session.access, SessionAccess) and session.access.axross
    back = AgentSession.from_dict(json.loads(json.dumps(session.to_dict())))
    assert back.agent_profile == "Research" and back.prompt_profile == ""


def test_happy_a_category_comes_from_the_install_record_or_the_builtin_catalog():
    installed = _server("x", "")
    installed.package = {"source": "builtin", "entry": "fetch"}
    assert AP.server_category(installed) == "Web & Data"
    assert AP.server_category(_server("y", RE)) == RE
    hand = _server("z")
    assert AP.server_category(hand) == ""


def test_happy_a_server_matches_by_its_catalog_entry_after_a_rename():
    renamed = _server("fetch-2", "Web & Data")
    renamed.package = {"source": "builtin", "entry": "fetch"}
    res = AP.resolve(AP.preset("Research"), _settings(renamed))
    assert res.servers == ["fetch-2"]
    assert {m.name for m in res.missing} == {"memory", "sequentialthinking"}


def test_happy_install_records_the_catalog_category():
    from core import mcp_catalog as M
    from core import mcp_install as I

    entry = M.CatalogEntry(id="remote1", name="remote1", category="Security: OSINT",
                           kind="remote", url="https://mcp.example/mcp")
    config = I.install(entry, I.InstallChoice(name="remote1"))
    assert config.category == "Security: OSINT"
    back = C.McpServerConfig.from_dict(config.to_dict())
    assert back.category == "Security: OSINT"


def test_happy_the_tab_prompt_profile_is_chosen_by_name():
    from core.agent_prompts import PromptProfile

    s = S.AgentSettings()
    s.prompt_profiles = [PromptProfile("Terse", "be terse", "{task}!")]
    assert s.prompts_for("Terse").system_prompt == "be terse"
    assert s.prompts_for("Default").builtin
    assert s.prompts_for("").builtin  # Agent Settings' choice: the built-in Default
    s.prompt_profile = "Terse"
    assert s.prompts_for("").name == "Terse"


# -- sad -----------------------------------------------------------------------


def test_sad_hand_edited_json_unknown_keys_and_wrong_types_take_defaults(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"agent_profiles": [
        {"name": "Odd", "mode": "yolo", "groups": "metadata", "functions": ["root", "mcp_servers"],
         "axross": "yes", "network": "everything", "hosts": ["nope", "ok.example:443", 7],
         "files_read_only": 1, "allow_exec": None, "mcp_categories": [RE, 5, None, ""],
         "mcp_servers": ["git", "bad name!", "../x", 3], "llm_profile": ["x"],
         "sandbox": {"a": 1}, "evil": "rm -rf /", "preset": True},
        "not a dict", 42, None,
    ], "agent_profile": 7}))
    s = S.AgentSettings.load(path)
    assert len(s.agent_profiles) == 1
    p = s.agent_profiles[0]
    assert (p.mode, p.groups, p.functions, p.axross, p.network) == (
        "ask", AP.AgentProfile("x").groups, ("mcp_servers",), False, "profile")
    assert p.hosts == ("ok.example:443",)
    assert (p.files_read_only, p.allow_exec) == (False, False)
    assert p.mcp_categories == (RE,) and p.mcp_servers == ("git",)
    assert (p.llm_profile, p.sandbox) == ("", "")
    assert p.preset is False  # a file never makes a preset
    assert "evil" not in p.to_dict() and "preset" not in p.to_dict()
    assert s.agent_profile == ""


def test_sad_duplicate_names_and_preset_names_are_dropped(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"agent_profiles": [
        {"name": "Mine", "mode": "plan"}, {"name": "Mine", "mode": "auto"},
        {"name": "mine", "mode": "auto"},
        {"name": "Research"}, {"name": "  "}, {"name": "x" * 200}, {},
    ], "agent_profile": "Gone"}))
    s = S.AgentSettings.load(path)
    assert [(p.name, p.mode) for p in s.agent_profiles] == [("Mine", "plan")]
    assert s.agent_profile == ""  # a default that names no profile is none


def test_sad_problems_name_what_cannot_be_stored():
    assert AP.AgentProfile("").problems()
    assert AP.AgentProfile("Research").problems()  # a preset's name
    assert AP.AgentProfile("files assistant").problems()
    assert AP.AgentProfile("ok\u202ename").problems()  # a bidi character
    assert AP.AgentProfile("x" * (AP.MAX_NAME + 1)).problems()
    assert AP.AgentProfile("Fine").problems() == []


def test_sad_unknown_categories_are_kept_but_reported_missing():
    p = AP.AgentProfile("Custom", axross=True, functions=("mcp_servers",),
                        mcp_categories=("My Own Tools",))
    back = AP.AgentProfile.from_dict(p.to_dict())
    assert back.mcp_categories == ("My Own Tools",)  # a catalog of the user's may have it
    res = AP.resolve(back, _settings())
    assert [(m.kind, m.name, m.why) for m in res.missing] == [
        ("category", "My Own Tools", "not installed")]
    bad = AP.AgentProfile.from_dict({"name": "B", "mcp_categories": ["a\u0000b", "y" * 61]})
    assert bad.mcp_categories == ()


def test_sad_the_ceiling_cuts_and_says_so():
    s = _settings(_server("r2", RE), axross=False)
    res = AP.resolve(AP.preset("Reverse Engineering"), s)
    assert not res.access.axross and res.servers == ["r2"]
    assert any("Agent Settings > Access" in n and "axross functions" in n for n in res.notes)
    s = _settings(_server("r2", RE), functions=("remote_files",))
    res = AP.resolve(AP.preset("Reverse Engineering"), s)
    assert "mcp_servers" not in res.access.functions
    assert any("MCP servers" in n and "r2" in n for n in res.notes)
    s = _settings(functions=("remote_files",))
    res = AP.resolve(AP.preset("Remote Ops"), s)
    assert set(res.access.functions) == {"remote_files"}
    assert any("remote commands" in n for n in res.notes)


def test_sad_a_disabled_server_is_listed_as_switched_off():
    res = AP.resolve(AP.preset("Reverse Engineering"), _settings(_server("r2", RE, enabled=False)))
    assert res.servers == []
    assert ("category", RE, "switched off") in [(m.kind, m.name, m.why) for m in res.missing]
    res = AP.resolve(AP.preset("Code & Secrets"), _settings(_server("git", enabled=False)))
    assert ("server", "git", "switched off") in [(m.kind, m.name, m.why) for m in res.missing]


def test_sad_bypass_is_never_widened_and_gone_names_fall_back():
    p = AP.AgentProfile("Wild", mode="bypass", llm_profile="gone", prompt_profile="gone",
                        sandbox="Nope")
    s = S.AgentSettings()
    res = AP.resolve(p, s, llm_names=["local"])
    assert res.mode == "ask" and any("Bypass" in n for n in res.notes)
    assert res.profile == "" and any("gone" in n and "LLM profile" in n for n in res.notes)
    assert res.prompt_profile == "" and any("prompt profile" in n for n in res.notes)
    # A missing sandbox is kept: the tab refuses to run, never "no sandbox" quietly.
    assert res.sandbox == "Nope" and any("Nope" in n for n in res.notes)
    s.allow_bypass = True
    assert AP.resolve(p, s).mode == "bypass"


def test_sad_files_read_only_of_the_ceiling_wins():
    s = _settings()
    s.access.files_read_only = True
    res = AP.resolve(AP.preset("Files Assistant"), s)
    assert any("read-only" in n for n in res.notes)


def test_sad_read_only_says_that_an_always_asking_server_offers_nothing():
    s = _settings(_server("tsk", FW), _server("yara", FW, confirm="writes"))
    res = AP.resolve(AP.preset("Forensics read-only"), s)
    assert res.servers == ["tsk", "yara"]
    note = next(n for n in res.notes if "asks before every call" in n)
    assert "none of tsk's tools" in note and "outside a container" in note
    assert "yara" not in note  # its read-only tools stay; nothing to say
    assert not any("asks before every call" in n
                   for n in AP.resolve(AP.preset("Code & Secrets"),
                                       _settings(_server("git"))).notes)


# -- edge ----------------------------------------------------------------------


def test_edge_category_matching_ignores_case_and_surrounding_space():
    s = _settings(_server("r2", "security: reverse engineering"))
    res = AP.resolve(AP.AgentProfile("p", axross=True, functions=("mcp_servers",),
                                     mcp_categories=(" Security: Reverse Engineering",)), s)
    assert res.servers == ["r2"]


def test_edge_a_network_the_sandbox_level_cannot_have_falls_back():
    p = AP.AgentProfile("Net", sandbox="Paranoid", network="all")
    res = AP.resolve(p, S.AgentSettings())
    assert res.access.network == "profile" and any("network" in n for n in res.notes)
    p = AP.AgentProfile("Net2", sandbox="Normal", network="hosts", hosts=("a.example:1",))
    res = AP.resolve(p, S.AgentSettings())
    assert res.access.network == "hosts" and res.access.hosts == ("a.example:1",)


def test_edge_a_copy_is_editable_and_gets_a_free_name():
    copy = AP.preset("Research").copy("Research 2")
    assert copy.preset is False and copy.name == "Research 2"
    assert copy.mcp_servers == AP.preset("Research").mcp_servers
    assert AP.free_profile_name("Research", ["Research copy"]) == "Research copy 2"


def test_edge_profile_lookup_finds_presets_and_own_profiles():
    s = S.AgentSettings()
    s.agent_profiles = [AP.AgentProfile("Mine")]
    assert AP.find_profile(s, "Mine").name == "Mine"
    assert AP.find_profile(s, "Research").preset
    assert AP.find_profile(s, "nope") is None and AP.find_profile(s, "") is None
    assert [p.name for p in AP.all_profiles(s)][-1] == "Mine"


def test_edge_known_categories_include_hub_shipped_and_installed():
    cats = AP.known_categories([_server("x", "Lab Tools")])
    for c in ("Files & Dev", "Web & Data", "Knowledge & Reasoning", "Security",
              "Security: Passwords & Crypto", "Lab Tools"):
        assert c in cats
    assert cats == sorted(set(cats), key=str.casefold)


def test_edge_an_empty_profile_resolves_to_a_closed_tab():
    res = AP.resolve(AP.AgentProfile("Bare", groups=()), _settings())
    assert res.groups == [] and res.servers == [] and res.missing == []
    assert not res.access.axross and res.notes == []


@pytest.mark.parametrize("bad", [None, [], "x", 5, {"name": 5}])
def test_edge_from_dict_refuses_what_is_no_profile(bad):
    assert AP.AgentProfile.from_dict(bad) is None
