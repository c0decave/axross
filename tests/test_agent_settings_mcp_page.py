"""Agent Settings > MCP Servers: add, edit, test and remove further MCP
servers. The token of an http server goes to the keyring, never into the
settings file."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core import agent_settings as S  # noqa: E402
from core import mcp_client as C  # noqa: E402
from tests.test_agent_settings_dialog import _dialog, _select  # noqa: E402
from tests.test_mcp_client import FAKE  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _wait(predicate, seconds=20.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("timed out")


# -- happy ---------------------------------------------------------------------


def test_happy_a_stdio_server_is_added_and_saved(tmp_path):
    path = tmp_path / "settings.json"
    dlg = _dialog(path)
    dlg.add_server()
    dlg.server_name_edit.setText("git")
    dlg.server_command_edit.setText("mcp-git --repo '/srv/my repo'")
    dlg.server_env_edit.setText("GIT_AUTHOR=alex LANG=C")
    _select(dlg.server_confirm_combo, "writes")
    _select(dlg.server_sandbox_combo, "High")
    assert dlg.save()
    (server,) = S.AgentSettings.load(path).mcp_servers
    assert server.command == ("mcp-git", "--repo", "/srv/my repo")
    assert server.env == {"GIT_AUTHOR": "alex", "LANG": "C"}
    assert (server.confirm, server.sandbox, server.enabled) == ("writes", "High", True)


def test_happy_an_http_token_goes_to_the_keyring(tmp_path, monkeypatch):
    stored = {}
    monkeypatch.setattr(C, "set_token", lambda name, token: stored.__setitem__(name, token))
    path = tmp_path / "settings.json"
    dlg = _dialog(path)
    dlg.add_server()
    dlg.server_name_edit.setText("web")
    _select(dlg.server_transport_combo, "http")
    dlg.server_url_edit.setText("https://mcp.example/mcp")
    dlg.server_bearer_check.setChecked(True)
    dlg.server_token_edit.setText("s3cr3t-token")
    assert dlg.save()
    assert stored == {"web": "s3cr3t-token"}
    assert "s3cr3t-token" not in path.read_text()
    assert S.AgentSettings.load(path).mcp_servers[0].bearer is True


def test_happy_test_lists_the_tools_of_a_server(tmp_path):
    script = tmp_path / "fake.py"
    script.write_text(FAKE)
    dlg = _dialog(tmp_path / "settings.json")
    dlg.add_server()
    dlg.server_name_edit.setText("fake")
    dlg.server_command_edit.setText(f"{sys.executable} {script} normal")
    dlg.test_server()
    _wait(
        lambda: "tools" in dlg.server_test_label.text() or "failed" in dlg.server_test_label.text()
    )
    assert "2 tools" in dlg.server_test_label.text()
    assert "look" in dlg.server_test_label.toolTip()


# -- sad -----------------------------------------------------------------------


def test_sad_incomplete_or_duplicate_servers_are_not_saved(tmp_path):
    path = tmp_path / "settings.json"
    dlg = _dialog(path)
    dlg.add_server()
    dlg.server_name_edit.setText("web")
    _select(dlg.server_transport_combo, "http")  # no URL
    dlg.add_server()
    dlg.server_name_edit.setText("web")
    dlg.server_command_edit.setText("x")
    problems = dlg.problems()
    assert any("web" in p and "URL" in p for p in problems)
    assert any("Two MCP servers" in p for p in problems)
    with mock.patch.object(QMessageBox, "warning") as warned:
        assert not dlg.save()
    warned.assert_called_once()
    assert not path.exists()


def test_sad_a_failing_test_says_why(tmp_path):
    dlg = _dialog(tmp_path / "settings.json")
    dlg.add_server()
    dlg.server_name_edit.setText("gone")
    dlg.server_command_edit.setText("/nonexistent/mcp-server")
    dlg.test_server()
    _wait(lambda: "failed" in dlg.server_test_label.text())
    assert "cannot start" in dlg.server_test_label.text()


# -- edge ----------------------------------------------------------------------


def test_edge_deleting_a_server_removes_its_token(tmp_path, monkeypatch):
    stored = {}
    monkeypatch.setattr(C, "set_token", lambda name, token: stored.__setitem__(name, token))
    path = tmp_path / "settings.json"
    S.AgentSettings(
        mcp_servers=[
            C.McpServerConfig(
                name="web", transport="http", url="http://127.0.0.1:1/mcp", bearer=True
            )
        ]
    ).save(path)
    dlg = _dialog(path)
    dlg.server_list.setCurrentRow(0)
    dlg.delete_server()
    assert dlg.save()
    assert stored == {"web": ""} and S.AgentSettings.load(path).mcp_servers == []


def test_edge_the_command_field_only_counts_for_stdio(tmp_path):
    dlg = _dialog(tmp_path / "settings.json")
    dlg.add_server()
    _select(dlg.server_transport_combo, "http")
    assert not dlg.server_command_edit.isEnabled() and dlg.server_url_edit.isEnabled()
    assert not dlg.server_sandbox_combo.isEnabled()
    _select(dlg.server_transport_combo, "stdio")
    assert dlg.server_command_edit.isEnabled() and not dlg.server_url_edit.isEnabled()


def test_sad_test_runs_a_sandboxed_server_in_its_sandbox(tmp_path, monkeypatch):
    seen = []

    class _Client:
        def __init__(self, config, *, token="", wrap=None):
            seen.append(wrap(["mcp-x"]) if wrap else None)

        def tools(self):
            return []

        def close(self):
            pass

    monkeypatch.setattr(C, "McpClient", _Client)
    monkeypatch.setattr(S, "agent_dir", lambda: tmp_path / "agent")
    dlg = _dialog(tmp_path / "settings.json")
    dlg.settings.sandboxes = [S.SandboxProfile(name="Box", engine="bubblewrap", level="paranoid")]
    dlg.add_server()
    dlg.server_name_edit.setText("boxed")
    dlg.server_command_edit.setText("mcp-x")
    dlg._show_server(dlg.server_list.currentRow())
    _select(dlg.server_sandbox_combo, "Box")
    dlg.test_server()
    _wait(
        lambda: "tools" in dlg.server_test_label.text() or "failed" in dlg.server_test_label.text()
    )
    assert seen and seen[0] is not None and "bwrap" in seen[0] and seen[0][-1] == "mcp-x"


def test_sad_test_refuses_a_missing_sandbox(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "agent_dir", lambda: tmp_path / "agent")
    path = tmp_path / "settings.json"
    S.AgentSettings(
        mcp_servers=[C.McpServerConfig(name="boxed", command=("mcp-x",), sandbox="Gone")]
    ).save(path)
    dlg = _dialog(path)
    dlg.server_list.setCurrentRow(0)
    assert dlg.server_sandbox_combo.currentData() == "Gone"  # kept, shown as missing
    dlg.test_server()
    _wait(lambda: "failed" in dlg.server_test_label.text())
    assert "Gone" in dlg.server_test_label.text()
    assert any("Gone" in p for p in dlg.problems())


def test_edge_renaming_a_server_takes_its_token_along(tmp_path, monkeypatch):
    stored = {"api": "T0K3N"}
    monkeypatch.setattr(C, "get_token", lambda name: stored.get(name, ""))
    monkeypatch.setattr(C, "set_token", lambda name, token: stored.__setitem__(name, token))
    path = tmp_path / "settings.json"
    S.AgentSettings(mcp_servers=[C.McpServerConfig(name="api", transport="http", url="http://127.0.0.1:1/mcp",
                                                   bearer=True)]).save(path)
    dlg = _dialog(path)
    dlg.server_list.setCurrentRow(0)
    dlg.server_name_edit.setText("api2")
    assert dlg.save()
    assert stored == {"api": "", "api2": "T0K3N"}


def test_edge_typing_through_another_servers_name_keeps_its_token(tmp_path, monkeypatch):
    stored = {"api": "T0K3N", "ap": "OTHER"}
    monkeypatch.setattr(C, "get_token", lambda name: stored.get(name, ""))
    monkeypatch.setattr(C, "set_token", lambda name, token: stored.__setitem__(name, token))
    path = tmp_path / "settings.json"
    servers = [
        C.McpServerConfig(name=n, transport="http", url="http://127.0.0.1:1/mcp", bearer=True)
        for n in ("api", "ap")
    ]
    S.AgentSettings(mcp_servers=servers).save(path)
    dlg = _dialog(path)
    dlg.server_list.setCurrentRow(0)
    for text in ("ap", "api", "api2"):  # one key at a time
        dlg.server_name_edit.setText(text)
    assert dlg.save()
    assert stored["ap"] == "OTHER" and stored["api2"] == "T0K3N" and stored["api"] == ""
