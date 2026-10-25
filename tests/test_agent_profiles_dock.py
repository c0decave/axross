"""Agent profiles in the Agent dock: "+" ▸ New Tab from Profile, Apply
Profile… for the current tab, the tab's profile line and notes, Install
from Catalog… for what a profile misses. End to end: a tab made from a
preset offers the fake LLM exactly the tools and MCP servers the profile
gives within Agent Settings > Access."""

from __future__ import annotations

import sys
import time

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QDialogButtonBox, QMessageBox

from core import agent_profiles as AP
from core import mcp_client as C
from tests.test_agent_tabs import Env, say
from tests.test_mcp_client import FAKE

APP = QApplication.instance() or QApplication([])
RE = "Security: Reverse Engineering"


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    script = tmp_path / "fake_mcp.py"
    script.write_text(FAKE)

    def server(name, category="", **kw):
        return C.McpServerConfig(name=name, command=(sys.executable, str(script), "normal"),
                                 category=category, **kw)

    e.server = server
    e.mcp_pool = C.McpClientPool(token_lookup=lambda name: "")
    for name in ("remote_files", "saved_profiles", "remote_commands", "mcp_servers"):
        setattr(e.settings.access, name, True)
    yield e
    e.close()
    e.mcp_pool.close_all()


def _plain(label) -> str:
    """A rich-text label's text as shown."""
    from PyQt6.QtGui import QTextDocumentFragment

    return QTextDocumentFragment.fromHtml(label.text()).toPlainText()


def _mcp_tools(request) -> set[str]:
    return {t["function"]["name"] for t in request["tools"] if "__" in t["function"]["name"]}


def _all_tools(request) -> set[str]:
    return {t["function"]["name"] for t in request["tools"]}


def _menu_action(menu, text):
    menu.aboutToShow.emit()
    for action in menu.actions():
        if action.text().replace("&", "") == text:
            return action
    raise AssertionError(f"{text!r} not in {[a.text() for a in menu.actions()]}")


def _wait(predicate, seconds=10.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        if predicate():
            return True
        time.sleep(0.01)
    return False


# -- happy (e2e) ------------------------------------------------------------------


def test_happy_e2e_a_tab_from_the_research_preset_offers_exactly_its_servers(env):
    env.settings.mcp_servers = [env.server("fetch", "Web & Data", confirm="writes"),
                                env.server("memory", confirm="writes"),
                                env.server("nmap", "Security: Network Recon")]
    server = env.fake({"content": "ok"}, {"content": "ok"})
    dock = env.dock()
    # The real menu: "+" ▸ New Tab from Profile ▸ Research (preset).
    menu = dock.new_tab_button.menu()
    sub = _menu_action(menu, "New Tab from Profile").menu()
    _menu_action(sub, "Research (preset)").trigger()
    tab = dock.current_tab()
    assert tab.session.agent_profile == "Research"
    assert "Profile: Research" in tab.profile_label.text()
    say(tab, "look")
    # Not Files read-only (fetch needs network): both servers' tools, writing ones ask.
    assert _mcp_tools(server.requests[0]) == {"fetch__look", "fetch__change", "memory__look",
                                              "memory__change"}
    assert not tab.files_read_only() and not tab.allow_write.isChecked()
    # The same tab set up by hand offers the very same tools.
    manual = dock.new_tab()
    for i in range(manual.groups.count()):
        item = manual.groups.item(i)
        item.setCheckState(Qt.CheckState.Checked if item.text() in
                           ("metadata", "filetype", "mcp:fetch", "mcp:memory")
                           else Qt.CheckState.Unchecked)
    manual.read_only_check.setChecked(False)
    manual.allow_write.setChecked(False)
    say(manual, "look")
    assert _all_tools(server.requests[1]) == _all_tools(server.requests[0])


def test_happy_e2e_network_recon_offers_its_categories_and_asks(env):
    env.settings.mcp_servers = [env.server("nmap", "Security: Network Recon"),
                                env.server("nuclei", "Security: Web"),
                                env.server("r2", RE)]
    server = env.fake({"content": "ok"})
    dock = env.dock()
    tab = dock.new_tab_from_profile("Network & Web Recon")
    assert tab.mode_combo.currentData() == "ask"
    say(tab, "scan")
    assert _mcp_tools(server.requests[0]) == {"nmap__look", "nmap__change", "nuclei__look",
                                              "nuclei__change"}
    # OSINT has no server here: listed, with Install from Catalog….
    assert not tab.profile_notes.isHidden()
    assert "Security: OSINT" in tab.profile_notes.text()
    assert "Install from Catalog" in tab.profile_notes.text()


def test_happy_apply_profile_dialog_previews_and_applies_to_the_current_tab(env):
    env.settings.mcp_servers = [env.server("git", "Files & Dev")]
    env.fake({"content": "ok"})
    dock = env.dock()
    tab = dock.current_tab()
    tab.session.transcript = [{"who": "You:", "text": "hi", "muted": False}]
    dialog = dock.pick_profile(tab)
    dialog.select("Code & Secrets")
    preview = dialog.preview.toPlainText()
    assert "filesystem" in preview and "Security: Code & Secrets" in preview
    assert "conversation stay" in dialog.note.text()
    QTest.mouseClick(dialog.buttons.button(QDialogButtonBox.StandardButton.Ok),
                     Qt.MouseButton.LeftButton)
    assert tab.session.agent_profile == "Code & Secrets"
    assert "mcp:git" in tab.selected_groups()
    assert tab.session.transcript  # the conversation stays
    saved = dock.store.load(tab.session.id)
    assert saved.agent_profile == "Code & Secrets" and "mcp:git" in saved.groups


def test_happy_the_default_profile_sets_up_every_new_tab(env):
    env.settings.agent_profiles = [AP.AgentProfile("Plain plan", mode="plan",
                                                   groups=("metadata",))]
    env.settings.agent_profile = "Plain plan"
    env.fake({"content": "ok"})
    dock = env.dock()
    tab = dock.new_tab()
    assert tab.session.agent_profile == "Plain plan" and tab.session.mode == "plan"
    assert tab.selected_groups() == frozenset({"metadata"})


def test_happy_a_profile_prompt_profile_reaches_the_model(env):
    from core.agent_prompts import PromptProfile

    env.settings.prompt_profiles = [PromptProfile("Shout", "SYSTEM-SHOUT", "LOUD: {task}")]
    env.settings.agent_profiles = [AP.AgentProfile("Loud", prompt_profile="Shout")]
    server = env.fake({"content": "ok"})
    tab = env.dock().new_tab_from_profile("Loud")
    say(tab, "hello")
    messages = server.requests[0]["messages"]
    assert messages[0]["content"].startswith("SYSTEM-SHOUT")
    assert messages[-1]["content"].endswith("LOUD: hello")


def test_happy_the_tab_menu_offers_apply_profile(env):
    env.fake({"content": "ok"})
    dock = env.dock()
    labels = [a.text() for a in dock.tab_menu(0).actions()]
    assert "Apply Profile…" in labels


# -- sad --------------------------------------------------------------------------


def test_sad_e2e_the_ceiling_cuts_the_servers_and_the_tab_says_so(env):
    env.settings.mcp_servers = [env.server("fetch", "Web & Data")]
    env.settings.access.axross_functions = False
    server = env.fake({"content": "ok"})
    tab = env.dock().new_tab_from_profile("Research")
    say(tab, "look")
    assert _mcp_tools(server.requests[0]) == set()
    assert not tab.session.access.axross
    assert "Agent Settings > Access" in _plain(tab.profile_notes)


def test_sad_a_running_tab_refuses_a_profile(env, monkeypatch):
    env.fake({"content": "ok"})
    dock = env.dock()
    tab = dock.current_tab()
    told = []
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: told.append(a[2]))
    monkeypatch.setattr(type(tab), "busy", lambda self: True)
    before = tab.session.mode
    assert dock.apply_profile(tab, "Remote Ops") is False
    assert told and "running" in told[0]
    assert tab.session.agent_profile == "" and tab.session.mode == before


def test_sad_an_unknown_profile_name_changes_nothing(env):
    env.fake({"content": "ok"})
    dock = env.dock()
    tab = dock.current_tab()
    assert dock.apply_profile(tab, "No such profile") is False
    assert dock.new_tab_from_profile("No such profile") is None
    assert tab.session.agent_profile == ""


def test_sad_cancelling_the_dialog_changes_nothing(env):
    env.fake({"content": "ok"})
    dock = env.dock()
    tab = dock.current_tab()
    dialog = dock.pick_profile(tab)
    dialog.select("Remote Ops")
    dialog.reject()
    assert tab.session.agent_profile == ""


def test_sad_e2e_read_only_and_an_always_asking_server_offers_nothing_and_says_so(env):
    # A program on this machine (no container), confirm "always".
    env.settings.mcp_servers = [env.server("tsk", "Security: Firmware & Forensics")]
    server = env.fake({"content": "ok"})
    tab = env.dock().new_tab_from_profile("Forensics read-only")
    say(tab, "look")
    assert _mcp_tools(server.requests[0]) == set()
    note = _plain(tab.profile_notes)
    assert "none of tsk's tools is offered" in note and "outside a container" in note


# -- edge -------------------------------------------------------------------------


def test_edge_install_from_catalog_opens_the_catalog_on_the_missing_category(env):
    from core import mcp_catalog as M

    env.settings.mcp_sources = M.CatalogSources(builtin=True, dockerhub=False,
                                                mcpregistry=False, c0decave=False,
                                                discover=False)
    env.fake({"content": "ok"})
    dock = env.dock()
    tab = dock.new_tab_from_profile("Research")
    assert "fetch" in tab.profile_notes.text()
    links = tab.profile_link_targets()
    assert "server:fetch" in links
    dialog = tab.profile_notes_link("server:fetch")
    try:
        assert dialog.search_edit.text() == "fetch"
        dialog = tab.profile_notes_link("category:" + RE)
        assert dialog.category_combo.currentData() == RE  # even before results arrive
        assert _wait(lambda: not dialog.busy() and dialog.status_label.text())
        assert dialog.category_combo.currentData() == RE  # a hub category, not in builtin
        assert dialog.entries() == []
    finally:
        dialog.reject()


def test_edge_a_server_installed_from_the_notes_is_ticked_in_the_tab(env, monkeypatch):
    env.fake({"content": "ok"})
    dock = env.dock()
    tab = dock.new_tab_from_profile("Research")
    config = env.server("fetch", "Web & Data")
    monkeypatch.setattr(C, "set_secret", lambda *a: None)
    monkeypatch.setattr(C, "set_token", lambda *a: None)
    dock._catalog_installed(tab, config, {}, "")
    assert env.saved and env.saved[-1].mcp_servers[-1].name == "fetch"
    assert "mcp:fetch" in tab.selected_groups()
    assert "server:fetch" not in tab.profile_link_targets()


def test_edge_a_tab_shows_its_profile_after_a_restart(env):
    env.fake({"content": "ok"})
    dock = env.dock()
    tab = dock.new_tab_from_profile("Remote Ops")
    session_id = tab.session.id
    dock.shutdown()
    again = env.dock()
    back = next(t for t in again.all_tabs() if t.session.id == session_id)
    assert "Profile: Remote Ops" in back.profile_label.text()
    assert back.session.access.functions == ("remote_files", "saved_profiles",
                                             "remote_commands")


def test_edge_an_empty_profile_keeps_an_empty_tool_list(env):
    env.settings.agent_profiles = [AP.AgentProfile("Bare", groups=())]
    env.fake({"content": "ok"})
    tab = env.dock().new_tab_from_profile("Bare")
    assert tab.selected_groups() == frozenset()  # not the General page's groups


def test_edge_profiles_menu_lists_presets_then_own_profiles(env):
    env.settings.agent_profiles = [AP.AgentProfile("Mine")]
    env.fake({"content": "ok"})
    dock = env.dock()
    sub = _menu_action(dock.new_tab_button.menu(), "New Tab from Profile").menu()
    sub.aboutToShow.emit()
    texts = [a.text() for a in sub.actions() if not a.isSeparator()]
    assert texts[0] == "Files Assistant (preset)" and texts[-1] == "Mine"
    assert len(texts) == len(AP.presets()) + 1
    # "&" in a name is shown, never a mnemonic.
    assert "Network && Web Recon (preset)" in texts


def test_edge_apply_again_takes_what_agent_settings_allow_now(env):
    env.settings.mcp_servers = [env.server("fetch", "Web & Data", confirm="writes")]
    env.settings.access.axross_functions = False
    server = env.fake({"content": "ok"})
    dock = env.dock()
    tab = dock.new_tab_from_profile("Research")
    assert "apply:again" in tab.profile_notes.text()
    env.settings.access.axross_functions = True
    dock.reload_settings()
    tab.profile_notes_link("apply:again")
    assert tab.session.access.axross and "mcp_servers" in tab.functions()
    assert "apply:again" not in tab.profile_notes.text()
    say(tab, "look")
    assert _mcp_tools(server.requests[0]) == {"fetch__look", "fetch__change"}
