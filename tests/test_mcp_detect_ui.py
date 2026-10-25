"""Plug and play for MCP servers already on this machine (core.mcp_detect):
one tick in Agent Settings > MCP Servers > Detected on this machine, or in
an Agent tab's Tools list, and the server is in the settings, switched on,
and its tools reach the model - driven like a user does."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core import agent_settings as S  # noqa: E402
from core import mcp_client as C  # noqa: E402
from core import mcp_detect as D  # noqa: E402
from tests.test_agent_loop import _call, _tool_messages  # noqa: E402
from tests.test_agent_settings_dialog import _dialog  # noqa: E402
from tests.test_agent_tabs import Env, say  # noqa: E402
from tests.test_mcp_client import FAKE  # noqa: E402

APP = QApplication.instance() or QApplication([])
TOKEN = "ghp_" + "Q7" * 18


def _wait(predicate, seconds=20.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("timed out")


@pytest.fixture
def home(tmp_path):
    """A home whose Cursor knows the fake MCP server (with a secret)."""
    home = tmp_path / "home"
    script = tmp_path / "fake_mcp.py"
    script.write_text(FAKE)
    (home / ".cursor").mkdir(parents=True)
    (home / ".cursor" / "mcp.json").write_text(json.dumps({"mcpServers": {
        "fake": {"command": sys.executable, "args": [str(script), "normal"],
                 "env": {"FAKE_API_TOKEN": TOKEN, "MODE": "test"}},
        "events": {"type": "sse", "url": "https://x.example/sse"}}}))
    return home


def _detector(home):
    return lambda **kw: D.detect(home=home, env={}, podman=None, **kw)


@pytest.fixture
def keyring_store(monkeypatch):
    store = {}
    monkeypatch.setattr(C, "set_secret", lambda n, v, value: store.__setitem__((n, v), value))
    monkeypatch.setattr(C, "get_secret", lambda n, v: store.get((n, v), ""))
    monkeypatch.setattr(C, "set_token", lambda n, t: store.__setitem__((n, "token"), t))
    return store


class _Asked(list):
    """The questions put to the user; *answer* is what the user answers."""

    answer = QMessageBox.StandardButton.Yes


@pytest.fixture
def asked(monkeypatch):
    questions = _Asked()

    def question(_parent, _title, text, *a, **k):
        questions.append(text)
        return questions.answer

    monkeypatch.setattr(QMessageBox, "question", staticmethod(question))
    return questions


def _detected_item(dlg, name):
    for i in range(dlg.detected_list.count()):
        item = dlg.detected_list.item(i)
        if item.text().split("  ", 1)[0] == name:
            return item
    return None


def _click_check(widget, item):
    rect = widget.visualItemRect(item)
    QTest.mouseClick(widget.viewport(), Qt.MouseButton.LeftButton,
                     pos=rect.topLeft() + type(rect.topLeft())(10, rect.height() // 2))


# -- Agent Settings ------------------------------------------------------------------


def test_happy_a_tick_in_agent_settings_adds_it_to_agent_json(tmp_path, home, keyring_store,
                                                              asked):
    path = tmp_path / "agent.json"
    s = S.AgentSettings()
    s.sandbox = ""
    s.save(path)
    dlg = _dialog(path, mcp_detector=_detector(home))
    dlg.show()
    dlg.show_tab("mcp")
    _wait(lambda: _detected_item(dlg, "fake") is not None)
    item = _detected_item(dlg, "fake")
    assert "Cursor" in item.text() and item.checkState() == Qt.CheckState.Unchecked
    dlg.detected_list.setCurrentItem(item)
    details = dlg.detected_details.toPlainText()
    assert "FAKE_API_TOKEN" in details and TOKEN not in details
    _click_check(dlg.detected_list, item)
    assert asked and "keyring" in asked[0] and "FAKE_API_TOKEN" in asked[0]
    assert TOKEN not in asked[0]
    assert _detected_item(dlg, "fake").checkState() == Qt.CheckState.Checked
    (server,) = dlg.settings.mcp_servers
    assert server.name == "fake" and server.enabled and server.env == {"MODE": "test"}
    assert dlg.server_list.count() == 1
    assert dlg.save()
    raw = path.read_text()
    assert TOKEN not in raw
    (saved,) = S.AgentSettings.load(path).mcp_servers
    assert saved.secret_env == ("FAKE_API_TOKEN",) and saved.package["source"] == "detected"
    assert keyring_store[("fake", "FAKE_API_TOKEN")] == TOKEN
    # An unusable one is shown, not tickable, and says why.
    events = _detected_item(dlg, "events")
    assert events is not None and not (events.flags() & Qt.ItemFlag.ItemIsUserCheckable)
    dlg.detected_list.setCurrentItem(events)
    assert "SSE" in dlg.detected_details.toPlainText()


def test_sad_declining_the_secret_prompt_adds_nothing(tmp_path, home, keyring_store, asked):
    asked.answer = QMessageBox.StandardButton.No
    path = tmp_path / "agent.json"
    S.AgentSettings().save(path)
    dlg = _dialog(path, mcp_detector=_detector(home))
    dlg.show()
    dlg.show_tab("mcp")
    _wait(lambda: _detected_item(dlg, "fake") is not None)
    _click_check(dlg.detected_list, _detected_item(dlg, "fake"))
    assert asked and dlg.settings.mcp_servers == []
    assert _detected_item(dlg, "fake").checkState() == Qt.CheckState.Unchecked
    assert keyring_store == {}


def test_edge_untick_removes_it_and_a_configured_one_shows_ticked(tmp_path, home, keyring_store,
                                                                  asked):
    path = tmp_path / "agent.json"
    S.AgentSettings().save(path)
    dlg = _dialog(path, mcp_detector=_detector(home))
    dlg.show()
    dlg.show_tab("mcp")
    _wait(lambda: _detected_item(dlg, "fake") is not None)
    _click_check(dlg.detected_list, _detected_item(dlg, "fake"))
    assert dlg.save()
    again = _dialog(path, mcp_detector=_detector(home))
    again.show()
    again.show_tab("mcp")
    _wait(lambda: _detected_item(again, "fake") is not None)
    assert _detected_item(again, "fake").checkState() == Qt.CheckState.Checked
    _click_check(again.detected_list, _detected_item(again, "fake"))
    assert again.settings.mcp_servers == []
    assert again.save() and S.AgentSettings.load(path).mcp_servers == []


# -- the Agent tab -------------------------------------------------------------------


@pytest.fixture
def env(tmp_path, home):
    e = Env(tmp_path)
    e.mcp_pool = C.McpClientPool(token_lookup=lambda name: "")
    e.mcp_detector = _detector(home)
    yield e
    e.close()
    e.mcp_pool.close_all()


def _items(tab):
    return [tab.groups.item(i).text() for i in range(tab.groups.count())]


def _group_item(tab, text):
    return next(tab.groups.item(i) for i in range(tab.groups.count())
                if tab.groups.item(i).text() == text)


def test_happy_one_tick_in_the_tab_and_the_model_gets_its_tools(env, keyring_store, asked):
    server = env.fake({"tool_calls": [_call("fake__look", {"q": "x"})]}, {"content": "looked"})
    dock = env.dock()
    tab = dock.current_tab()
    dock.detect_servers()
    _wait(lambda: "detected:fake" in _items(tab))
    assert "detected:events" not in _items(tab)  # unusable: not offered here
    item = _group_item(tab, "detected:fake")
    assert "Cursor" in item.toolTip() and TOKEN not in item.toolTip()
    _click_check(tab.groups, item)
    _wait(lambda: "mcp:fake" in _items(tab))
    assert asked and "keyring" in asked[0]
    assert "detected:fake" not in _items(tab)
    assert _group_item(tab, "mcp:fake").checkState() == Qt.CheckState.Checked
    assert "mcp:fake" in tab.session.groups
    (config,) = env.settings.mcp_servers
    assert config.enabled and config.sandbox == "" and config.confirm == "always"
    assert env.saved and env.saved[-1] is env.settings
    assert keyring_store[("fake", "FAKE_API_TOKEN")] == TOKEN
    config.confirm = "writes"  # read-only tools run without asking, like any server
    say(tab, "look")
    assert '{"q": "x"}' in _tool_messages(server.requests[1])[0]["content"]


def test_edge_a_tick_in_a_sandboxed_tab_runs_it_in_that_profile(env, keyring_store, asked):
    from core.agent_sandbox import SandboxProfile

    env.settings.sandboxes = [SandboxProfile(name="Box", engine="bubblewrap", level="normal")]
    env.fake({"content": "ok"})
    dock = env.dock()
    tab = dock.current_tab()
    tab.sandbox_combo.setCurrentIndex(tab.sandbox_combo.findData("Box"))
    dock.detect_servers()
    _wait(lambda: "detected:fake" in _items(tab))
    _click_check(tab.groups, _group_item(tab, "detected:fake"))
    _wait(lambda: "mcp:fake" in _items(tab))
    assert env.settings.mcp_servers[0].sandbox == "Box"


def test_sad_declined_in_the_tab_leaves_it_unticked(env, keyring_store, asked):
    asked.answer = QMessageBox.StandardButton.No
    env.fake({"content": "ok"})
    dock = env.dock()
    tab = dock.current_tab()
    dock.detect_servers()
    _wait(lambda: "detected:fake" in _items(tab))
    _click_check(tab.groups, _group_item(tab, "detected:fake"))
    _wait(lambda: asked)
    APP.processEvents()
    assert env.settings.mcp_servers == [] and "mcp:fake" not in _items(tab)
    assert _group_item(tab, "detected:fake").checkState() == Qt.CheckState.Unchecked
    assert not any(g.startswith("detected:") for g in tab.selected_groups())


def test_edge_untick_keeps_a_server_set_up_by_hand(tmp_path, home, keyring_store, asked):
    path = tmp_path / "agent.json"
    s = S.AgentSettings()
    detected = next(d for d in _detector(home)().servers if d.name == "fake")
    s.mcp_servers.append(C.McpServerConfig(name="mine", command=detected.command))
    s.save(path)
    dlg = _dialog(path, mcp_detector=_detector(home))
    dlg.show()
    dlg.show_tab("mcp")
    _wait(lambda: _detected_item(dlg, "fake") is not None)
    item = _detected_item(dlg, "fake")
    assert item.checkState() == Qt.CheckState.Checked
    _click_check(dlg.detected_list, item)
    assert [x.name for x in dlg.settings.mcp_servers] == ["mine"]
    assert _detected_item(dlg, "fake").checkState() == Qt.CheckState.Checked
    assert "delete it in the list above" in dlg.server_test_label.text()


# -- downloaded servers run in containers only (operator rule) ----------------------------


@pytest.fixture
def no_host_runner(monkeypatch):
    """Every program started; npx, uvx and friends must never be among them."""
    import subprocess

    seen = []
    real_popen = subprocess.Popen

    def popen(args, *a, **k):
        seen.append([str(x) for x in args] if not isinstance(args, str) else [args])
        return real_popen(args, *a, **k)

    monkeypatch.setattr(subprocess, "Popen", popen)
    yield seen
    names = {Path(argv[0]).name for argv in seen if argv}
    assert not names & {"npx", "uvx", "pipx", "bunx", "npm", "pip", "uv", "docker"}, names


def _npm_opener():
    from tests.test_mcp_catalog import FakeOpener

    return FakeOpener({"registry.npmjs.org/": b'{"version": "1.4.0"}'})


def test_happy_a_typed_npx_command_is_installed_in_a_container_not_saved(
        tmp_path, monkeypatch, keyring_store, no_host_runner):
    from tests.mcp_podman_testkit import fake_podman

    messages = []
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(
        lambda *a, **k: messages.append(str(a[2]) if a[2:] else "")))
    podman = fake_podman(tmp_path, monkeypatch,
                         entry_line="AXROSS_ENTRY=/opt/mcp/node_modules/srv/dist/index.js")
    path = tmp_path / "agent.json"
    S.AgentSettings().save(path)
    dlg = _dialog(path, mcp_opener=_npm_opener())
    dlg.show()
    dlg.show_tab("mcp")
    assert "uvx" not in dlg.server_command_edit.placeholderText()
    QTest.mouseClick(dlg.server_add_button, Qt.MouseButton.LeftButton)
    dlg.server_command_edit.clear()
    QTest.keyClicks(dlg.server_command_edit, "npx -y @modelcontextprotocol/server-everything")
    assert dlg.server_contain_button.isVisible(), dlg.server_runner_label.text()
    assert dlg.server_contain_button.isEnabled(), dlg.server_runner_label.text()
    assert "never run on this machine" in dlg.server_runner_label.text()
    assert not dlg.save()  # not saved as a command on this machine
    assert messages and "container" in messages[-1]
    QTest.mouseClick(dlg.server_contain_button, Qt.MouseButton.LeftButton)
    _wait(lambda: dlg.settings.mcp_servers[0].container, seconds=30)
    (server,) = dlg.settings.mcp_servers
    assert server.name == "server" and server.enabled and "--network=none" in server.command
    assert server.package["kind"] == "npm" and server.package["version"] == "1.4.0"
    assert dlg.save()
    saved = json.loads(path.read_text())["mcp_servers"][0]
    assert saved["container"] is True and "npx" not in saved["command"]
    build = next(c for c in podman.calls("run") if any("install" in a for a in c))
    assert "@modelcontextprotocol/server-everything@1.4.0" in build


def test_sad_a_typed_runner_that_cannot_be_contained_is_refused_with_why(tmp_path):
    path = tmp_path / "agent.json"
    S.AgentSettings().save(path)
    dlg = _dialog(path)
    dlg.show()
    dlg.show_tab("mcp")
    dlg.add_server()
    dlg.server_command_edit.setText("npx github:someone/repo")
    assert not dlg.server_contain_button.isEnabled()
    assert "git URL" in dlg.server_runner_label.text()
    assert any("downloads" in p for p in dlg.problems())


def test_edge_a_typed_docker_line_goes_hardened_and_a_local_program_says_where_it_runs(
        tmp_path, monkeypatch, keyring_store, no_host_runner):
    from core import mcp_install as I
    from tests.mcp_podman_testkit import fake_podman

    fake_podman(tmp_path, monkeypatch)
    path = tmp_path / "agent.json"
    s = S.AgentSettings()
    s.mcp_servers.append(C.McpServerConfig(name="local", command=(sys.executable, "-V")))
    s.save(path)
    dlg = _dialog(path)
    dlg.show()
    dlg.show_tab("mcp")
    assert "runs on this machine, not in a container" in dlg.server_list.item(0).text()
    dlg.add_server()
    dlg.server_command_edit.setText("docker run -i --rm --privileged --network=host "
                                    "ghcr.io/o/srv:v1 stdio")
    assert "--privileged" in dlg.server_runner_label.text()  # what is dropped is named
    QTest.mouseClick(dlg.server_contain_button, Qt.MouseButton.LeftButton)
    _wait(lambda: dlg.settings.mcp_servers[1].container, seconds=30)
    server = dlg.settings.mcp_servers[1]
    assert "--privileged" not in server.command and "--network=host" not in server.command
    assert all(flag in server.command for flag in I.RUN_FLAGS)
    assert "not in a container" not in dlg.server_list.item(1).text()


def test_happy_a_detected_npx_server_is_installed_into_a_container_on_tick(
        tmp_path, monkeypatch, keyring_store, asked, no_host_runner):
    from tests.mcp_podman_testkit import fake_podman

    fake_podman(tmp_path, monkeypatch,
                entry_line="AXROSS_ENTRY=/opt/mcp/node_modules/gh/dist/index.js")
    home = tmp_path / "npxhome"
    (home / ".cursor").mkdir(parents=True)
    (home / ".cursor" / "mcp.json").write_text(json.dumps({"mcpServers": {"github": {
        "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
        "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": TOKEN}}}}))
    path = tmp_path / "agent.json"
    S.AgentSettings().save(path)
    dlg = _dialog(path, mcp_detector=_detector(home), mcp_opener=_npm_opener())
    dlg.show()
    dlg.show_tab("mcp")
    _wait(lambda: _detected_item(dlg, "github") is not None)
    dlg.detected_list.setCurrentItem(_detected_item(dlg, "github"))
    assert "never runs on this machine" in dlg.detected_details.toPlainText()
    _click_check(dlg.detected_list, _detected_item(dlg, "github"))
    assert asked and "container" in asked[0] and "keyring" in asked[0]
    _wait(lambda: dlg.settings.mcp_servers, seconds=30)
    (server,) = dlg.settings.mcp_servers
    assert server.container and server.secret_env == ("GITHUB_PERSONAL_ACCESS_TOKEN",)
    assert "npx" not in server.command
    assert dlg.save() and keyring_store[("github", "GITHUB_PERSONAL_ACCESS_TOKEN")] == TOKEN
    assert TOKEN not in path.read_text()


def test_happy_a_detected_npx_server_ticked_in_the_tab_is_contained(
        env, tmp_path, monkeypatch, keyring_store, asked, no_host_runner):
    from tests.mcp_podman_testkit import fake_podman

    fake_podman(tmp_path, monkeypatch,
                entry_line="AXROSS_ENTRY=/opt/mcp/node_modules/gh/dist/index.js")
    home = tmp_path / "npxhome"
    (home / ".cursor").mkdir(parents=True)
    (home / ".cursor" / "mcp.json").write_text(json.dumps({"mcpServers": {"github": {
        "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github@1.0.0"]}}}))
    env.mcp_detector = _detector(home)
    env.fake({"content": "ok"})
    dock = env.dock()
    tab = dock.current_tab()
    dock.detect_servers()
    _wait(lambda: "detected:github" in _items(tab))
    _click_check(tab.groups, _group_item(tab, "detected:github"))
    _wait(lambda: "mcp:github" in _items(tab), seconds=30)
    (config,) = env.settings.mcp_servers
    assert config.container and config.package["version"] == "1.0.0"
    assert _group_item(tab, "mcp:github").checkState() == Qt.CheckState.Checked
