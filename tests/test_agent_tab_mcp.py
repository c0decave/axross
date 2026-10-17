"""An Agent tab and further MCP servers: each enabled server is a line of
the tab's Tools list ("mcp:<name>"); ticked, its tools reach the model.
Auto mode still asks for a server set to "always"."""

from __future__ import annotations

import sys

import pytest

from core import mcp_client as C
from tests.test_agent_loop import _call, _tool_messages
from tests.test_agent_tabs import Env, say
from tests.test_mcp_client import FAKE


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    script = tmp_path / "fake_mcp.py"
    script.write_text(FAKE)
    e.server_config = lambda **kw: C.McpServerConfig(
        name="fake", command=(sys.executable, str(script), "normal"), **kw)
    e.mcp_pool = C.McpClientPool(token_lookup=lambda name: "")
    yield e
    e.close()
    e.mcp_pool.close_all()


def _items(tab):
    return [tab.groups.item(i).text() for i in range(tab.groups.count())]


def _tick(tab, text):
    from PyQt6.QtCore import Qt

    for i in range(tab.groups.count()):
        if tab.groups.item(i).text() == text:
            tab.groups.item(i).setCheckState(Qt.CheckState.Checked)


# -- happy ---------------------------------------------------------------------


def test_happy_a_ticked_server_reaches_the_model(env):
    env.settings.mcp_servers = [env.server_config(confirm="writes")]
    server = env.fake({"tool_calls": [_call("fake__look", {"q": "x"})]}, {"content": "looked"})
    tab = env.dock().current_tab()
    assert "mcp:fake" in _items(tab)
    _tick(tab, "mcp:fake")
    say(tab, "look")
    assert '{"q": "x"}' in _tool_messages(server.requests[1])[0]["content"]
    assert "mcp:fake" in tab.session.groups


def test_happy_auto_mode_still_asks_for_an_always_server(env):
    env.settings.mcp_servers = [env.server_config()]
    env.fake({"tool_calls": [_call("fake__look", {})]}, {"content": "done"})
    tab = env.dock().current_tab()
    _tick(tab, "mcp:fake")
    tab.mode_combo.setCurrentIndex(tab.mode_combo.findData("auto"))
    say(tab, "look")
    assert [n for n, _a in env.asked] == ["fake__look"]


# -- sad -----------------------------------------------------------------------


def test_sad_an_unticked_or_disabled_server_is_not_offered(env):
    env.settings.mcp_servers = [
        env.server_config(),
        C.McpServerConfig(name="off", command=("x",), enabled=False),
    ]
    server = env.fake({"content": "ok"})
    tab = env.dock().current_tab()
    assert "mcp:off" not in _items(tab)
    say(tab, "hi")
    assert not any(t["function"]["name"].startswith("fake__") for t in server.requests[0]["tools"])


def test_sad_a_server_with_a_missing_sandbox_profile_does_not_start(env):
    env.settings.mcp_servers = [env.server_config(sandbox="Nope")]
    env.fake({"content": "ok"})
    tab = env.dock().current_tab()
    _tick(tab, "mcp:fake")
    say(tab, "hi")
    text = tab.transcript.toPlainText()
    assert "fake" in text and "Nope" in text


# -- edge ----------------------------------------------------------------------


def test_edge_removing_a_server_in_the_settings_takes_it_out(env):
    env.settings.mcp_servers = [env.server_config(confirm="writes")]
    env.fake({"tool_calls": [_call("fake__look", {})]}, {"content": "done"})
    dock = env.dock()
    tab = dock.current_tab()
    _tick(tab, "mcp:fake")
    say(tab, "look")
    assert env.mcp_pool.always_ask("fake__look") is False
    env.settings.mcp_servers = []
    dock.reload_settings()
    assert "mcp:fake" not in _items(tab)
    assert env.mcp_pool.tools([])[0] == [] and not env.mcp_pool._clients


def test_edge_a_server_runs_inside_its_sandbox_profile(env, tmp_path, monkeypatch):
    from core import agent_settings as AGS
    from core.agent_sandbox import SandboxProfile
    from tests.test_agent_sandbox import needs_bwrap

    if needs_bwrap.args[0]:
        pytest.skip(needs_bwrap.kwargs["reason"])
    monkeypatch.setattr(AGS, "agent_dir", lambda: tmp_path / "agent")
    home = tmp_path / "agent" / "mcp" / "boxed"
    home.mkdir(parents=True)
    # Inside the sandbox only the server's own folder (and the system) is there.
    (home / "server.py").write_text(FAKE)
    env.settings.sandboxes = [SandboxProfile(name="Box", engine="bubblewrap", level="normal")]
    env.settings.mcp_servers = [
        C.McpServerConfig(
            name="boxed",
            command=(sys.executable, str(home / "server.py"), "normal"),
            sandbox="Box",
            confirm="writes",
        )
    ]
    server = env.fake({"tool_calls": [_call("boxed__look", {"q": 1})]}, {"content": "done"})
    tab = env.dock().current_tab()
    _tick(tab, "mcp:boxed")
    say(tab, "look")
    assert '{"q": 1}' in _tool_messages(server.requests[1])[0]["content"]
    client = next(iter(env.mcp_pool._clients.values()))[1]
    argv = client._transport._proc.args
    assert "bwrap" in argv and "--unshare-all" in argv


def test_sad_plan_mode_offers_no_changing_server_tool(env):
    env.settings.mcp_servers = [env.server_config(confirm="writes")]
    server = env.fake({"content": "a plan"})
    tab = env.dock().current_tab()
    _tick(tab, "mcp:fake")
    tab.mode_combo.setCurrentIndex(tab.mode_combo.findData("plan"))
    say(tab, "plan it")
    offered = {t["function"]["name"] for t in server.requests[0]["tools"]}
    assert "fake__look" in offered  # marked read-only by the server
    assert "fake__change" not in offered and "update_plan" in offered
