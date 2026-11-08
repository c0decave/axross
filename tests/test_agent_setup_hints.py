"""The Agent tab says which switch a refused tool needs, with a link to it.

Review 4 (features/extensions):
- A tool the tab does not offer showed only the model-facing "the tool 'X'
  is not available to you" and never named the switch the user must tick
  (a tool group, Allow changes to files, an extension's line under Tools).
- Every profile preset said "axross functions are off" on a fresh install,
  without a way to the setting (Agent Settings > Access).
"""

from __future__ import annotations

from unittest import mock

import pytest
from PyQt6.QtWidgets import QApplication

from core import agent as A
from core import agent_profiles as AP
from core import agent_settings as AGS
from tests.test_agent_loop import _call
from tests.test_agent_tabs import Env, say

APP = QApplication.instance() or QApplication([])


# -- core: which switch -----------------------------------------------------------------


def _switch(name, **kw):
    args = dict(groups=(), allow_write=False, allow_exec=False, files_read_only=False)
    args.update(kw)
    return A.unavailable_switch(name, **args)


def test_happy_the_switch_of_each_kind_of_tool_is_named():
    assert _switch("metadata_read") == ("group", "metadata")
    assert _switch("write_file") == ("write", "")
    assert _switch("remote_exec", functions=frozenset({"remote_commands"})) == ("exec", "")
    assert _switch("rev_code", extension_tools={"ext_revext__rev_code": "user:revext"}) \
        == ("ext", "user:revext")
    assert _switch("fetch__get", mcp_servers=["fetch"]) == ("mcp", "fetch")


def test_sad_off_functions_and_read_only_are_named_before_a_tick():
    assert _switch("write_file", files_read_only=True) == ("read_only", "")
    assert _switch("remote_exec", functions=frozenset()) == ("access", "remote_commands")
    assert _switch("rev_code", groups={"ext:user:revext"}, functions=frozenset(),
                   extension_tools={"ext_revext__rev_code": "user:revext"}) == ("access", "extensions")


def test_edge_a_ticked_extension_tool_called_by_its_short_name_and_an_unknown_tool():
    ticked = {"ext:user:revext"}
    tools = {"ext_revext__rev_code": "user:revext"}
    assert _switch("rev_code", groups=ticked, extension_tools=tools) \
        == ("offered", "ext_revext__rev_code")
    assert _switch("no_such_tool") == ("unknown", "")
    assert _switch("stat") == ("unknown", "")     # offered always: nothing to switch


# -- the tab ------------------------------------------------------------------------------


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    yield e
    e.close()


def test_happy_a_refused_group_tool_names_the_tick_and_links_to_the_tools(env):
    env.fake({"tool_calls": [_call("duplicates_scan", {"path": str(env.root)})]}, {"content": "ok"})
    tab = env.dock().current_tab()
    say(tab, "find the duplicates")
    text = tab.transcript.toPlainText()
    assert 'tick "duplicates" under Tools' in text
    assert tab.setup_hint.isVisibleTo(tab) and 'href="tools:show"' in tab.setup_hint.text()
    assert not tab.tools_button.isChecked()
    tab.profile_notes_link("tools:show")
    assert tab.tools_button.isChecked()


def test_sad_the_model_is_told_the_full_name_of_a_tool_it_shortened(monkeypatch):
    monkeypatch.setattr(A.Agent, "_tools", property(lambda self: {"ext_revext__rev_code": object()}))
    agent = A.Agent.__new__(A.Agent)
    agent._external = {}

    class _NoHost:
        @staticmethod
        def get(_name):
            return None

    agent._host = _NoHost()
    name, outcome, text = agent._run_tool({"function": {"name": "rev_code", "arguments": "{}"}})
    assert (name, outcome) == ("rev_code", "unavailable")
    assert "did you mean 'ext_revext__rev_code'" in text


def test_edge_profile_notes_link_to_agent_settings_access(env):
    env.fake({"content": "ok"})
    env.settings.access = AGS.AgentSettings().access     # a fresh install: functions off
    dock = env.dock()
    tab = dock.current_tab()
    profile = next(p for p in AP.presets() if p.axross)
    res = AP.resolve(profile, env.settings)
    assert res.access_cut and any("Switch them on there" in n for n in res.notes)
    tab.show_profile_report(res)
    assert 'href="settings:access"' in tab.profile_notes.text()
    opened = []

    class Window:
        def open_settings(self, page=None, sub=None):
            opened.append((page, sub))

    with mock.patch.object(tab, "window", lambda: Window()):
        tab.profile_notes_link("settings:access")
    assert opened == [("agent", "access")]
