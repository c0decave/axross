"""Agent Settings > MCP Servers > Add from Catalog… and Agent Settings > MCP
Sources, driven like a user does (QTest clicks), through to the settings
file. podman is the stand-in of tests/mcp_podman_testkit.py, which also
acts as the installed server, so the dialog's own test passes."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QPoint, Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QDialogButtonBox, QMessageBox  # noqa: E402

from core import agent_settings as S  # noqa: E402
from core import mcp_catalog as M  # noqa: E402
from core import mcp_client as C  # noqa: E402
from core import mcp_install as I  # noqa: E402
from tests.mcp_podman_testkit import fake_podman  # noqa: E402
from tests.test_agent_settings_dialog import _dialog  # noqa: E402
from tests.test_mcp_catalog import FakeOpener  # noqa: E402
from tests.test_mcp_install import real_podman  # noqa: E402,F401 - a fixture

APP = QApplication.instance() or QApplication([])


def _wait(predicate, seconds=30.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("timed out")


def _settings(path: Path, **sources) -> None:
    s = S.AgentSettings()
    s.mcp_sources = M.CatalogSources(**{"dockerhub": False, "mcpregistry": False, **sources})
    s.save(path)


@pytest.fixture
def keyring_store(monkeypatch):
    store = {}
    monkeypatch.setattr(C, "set_secret", lambda n, v, value: store.__setitem__((n, v), value))
    monkeypatch.setattr(C, "get_secret", lambda n, v: store.get((n, v), ""))
    monkeypatch.setattr(C, "set_token", lambda n, t: store.__setitem__((n, "token"), t))
    return store


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    messages = []
    for name in ("information", "warning", "critical"):
        monkeypatch.setattr(QMessageBox, name, staticmethod(
            lambda *a, _n=name, **k: messages.append((_n, str(a[2]) if a[2:] else ""))))
    return messages


def _click_entry(cat, entry_id: str) -> None:
    for i in range(cat.tree.topLevelItemCount()):
        group = cat.tree.topLevelItem(i)
        for j in range(group.childCount()):
            item = group.child(j)
            if item.data(0, Qt.ItemDataRole.UserRole).id == entry_id:
                cat.tree.scrollToItem(item)
                rect = cat.tree.visualItemRect(item)
                QTest.mouseClick(cat.tree.viewport(), Qt.MouseButton.LeftButton,
                                 pos=rect.center())
                assert cat.tree.currentItem() is item
                return
    raise AssertionError(f"{entry_id} is not in the tree")


def _open_catalog(dlg):
    dlg.show()
    dlg.show_tab("mcp")
    QTest.mouseClick(dlg.catalog_button, Qt.MouseButton.LeftButton)
    cat = dlg._catalog_dialog
    assert cat is not None and cat.isVisible()
    _wait(lambda: cat.tree.topLevelItemCount() > 0)
    return cat


# -- happy (e2e) ---------------------------------------------------------------------


def test_happy_add_from_catalog_through_to_the_settings_file(tmp_path, monkeypatch):
    podman = fake_podman(tmp_path, monkeypatch)
    path = tmp_path / "agent.json"
    _settings(path)
    dlg = _dialog(path)
    cat = _open_catalog(dlg)
    groups = {cat.tree.topLevelItem(i).text(0) for i in range(cat.tree.topLevelItemCount())}
    assert {"Files & Dev", "Web & Data", "Knowledge & Reasoning", "Testing",
            "Security"} <= groups
    _click_entry(cat, "time")
    assert "Time (Reference)" in cat.details.toPlainText()
    assert cat.network_combo.currentData() == "none" and cat.name_edit.text() == "time"
    QTest.mouseClick(cat.install_button, Qt.MouseButton.LeftButton)
    _wait(lambda: cat.installs)
    log = cat.log.toPlainText()
    assert "Test passed" in log and "Copying blob" in log
    assert dlg.server_list.count() == 1 and dlg.server_list.currentRow() == 0
    cat.close()
    save = dlg.findChild(QDialogButtonBox).button(QDialogButtonBox.StandardButton.Save)
    QTest.mouseClick(save, Qt.MouseButton.LeftButton)
    (server,) = S.AgentSettings.load(path).mcp_servers
    entry = next(e for e in M.load_builtin()[0] if e.name == "time")
    assert server.container and server.enabled and server.command[-1] == entry.image_ref
    assert server.package["kind"] == "oci" and server.package["digest"] == entry.digest
    raw = json.loads(path.read_text())["mcp_servers"][0]
    assert raw["container"] is True and "--cap-drop=ALL" in raw["command"]
    assert ["pull", entry.image_ref] in podman.calls("pull")


def test_happy_the_settings_dialog_and_the_tools_menu_reach_it(tmp_path, monkeypatch):
    from tests.settings_testkit import isolate
    from ui import settings_dialog as SD

    stores = isolate(tmp_path, monkeypatch)
    fake_podman(tmp_path, monkeypatch)
    _settings(stores.agent)
    win = stores.make_window()
    try:
        tools = next(a.menu() for a in win.menuBar().actions()
                     if a.menu() is not None and a.text().replace("&", "") == "Tools")
        action = next(a for a in tools.actions() if a.text().replace("&", "") == "MCP Servers…")
        seen = {}

        def fake_exec(dialog):
            seen["page"] = dialog.current_page_id()
            seen["tab"] = dialog.page("agent").tabs.currentIndex()
            seen["item"] = dialog.tree.currentItem().text(0)
            return 0

        with mock.patch.object(SD.SettingsDialog, "exec", fake_exec):
            action.trigger()
        from ui.agent_settings_dialog import AGENT_TABS

        assert seen["page"] == "agent" and seen["item"] == "MCP Servers"
        assert AGENT_TABS[seen["tab"]][0] == "mcp"

        dialog = stores.settings_dialog(win, "agent")
        dialog.show_page("agent", "mcp")
        dialog.apply_filter("catalog")
        assert "agent" in dialog.visible_page_ids()
        dialog.apply_filter("")
        page = dialog.page("agent")
        cat = page.add_from_catalog()
        _wait(lambda: cat.tree.topLevelItemCount() > 0)
        _click_entry(cat, "sequentialthinking")
        QTest.mouseClick(cat.install_button, Qt.MouseButton.LeftButton)
        _wait(lambda: cat.installs)
        cat.close()
        assert dialog.apply()
        data = json.loads(stores.agent.read_text())
        (server,) = data["mcp_servers"]
        assert server["name"] == "sequentialthinking" and server["container"] is True
        assert server["enabled"] is True
    finally:
        stores.close_windows()


def test_happy_sources_are_switched_added_and_checked(tmp_path):
    path = tmp_path / "agent.json"
    _settings(path)
    good = tmp_path / "mine.json"
    good.write_text(json.dumps({"schema": M.SCHEMA, "version": 1, "entries": [
        {"id": "a", "name": "a", "kind": "oci", "image": "docker.io/x/a",
         "digest": "sha256:" + "a" * 64}, {"id": "b", "name": "b", "kind": "exe"}]}))
    dlg = _dialog(path)
    dlg.show()
    dlg.show_tab("mcp_sources")
    assert dlg.source_builtin_check.isChecked() and not dlg.source_dockerhub_check.isChecked()
    box = dlg.source_registry_check  # a click on its box, not the empty row beside the text
    QTest.mouseClick(box, Qt.MouseButton.LeftButton, pos=QPoint(8, box.height() // 2))
    assert dlg.add_source_file(str(good))
    QTest.mouseClick(dlg.source_check_button, Qt.MouseButton.LeftButton)
    _wait(lambda: "servers" in dlg.source_check_label.text())
    text = dlg.source_check_label.text()
    assert text.startswith("1 servers") and "skipped" in text and "kind" in text
    assert dlg.save()
    back = S.AgentSettings.load(path).mcp_sources
    assert back.mcpregistry and not back.dockerhub and back.extra == (str(good),)


# -- sad -----------------------------------------------------------------------------


def test_sad_a_hostile_or_broken_catalog_is_refused_with_a_reason(tmp_path):
    path = tmp_path / "agent.json"
    _settings(path)
    dlg = _dialog(path)
    dlg.show_tab("mcp_sources")
    for name, content, why in (
        ("other.json", json.dumps({"schema": "evil", "version": 1, "entries": []}), "schema"),
        ("big.json", " " * (M.MAX_CATALOG_BYTES + 10), "larger than"),
        ("list.json", "[1, 2]", "an object"),
        ("deep.json", "[" * 100000 + "]" * 100000, "JSON"),
    ):
        f = tmp_path / name
        f.write_text(content)
        assert dlg.add_source_file(str(f))
        dlg.check_source()
        _wait(lambda: dlg.source_check_label.text().startswith("Refused"))
        assert why in dlg.source_check_label.text(), dlg.source_check_label.text()
    assert not dlg.add_source("relative/catalog.json")
    assert "absolute" in dlg.source_check_label.text()
    assert not dlg.add_source_url("http://plain.example/c.json")
    assert "https" in dlg.source_check_label.text()
    assert not dlg.add_source(str(tmp_path / "other.json"))  # twice


def test_sad_without_podman_container_servers_cannot_be_installed(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))
    catalog = tmp_path / "remote.json"
    catalog.write_text(json.dumps({"schema": M.SCHEMA, "version": 1, "entries": [
        {"id": "web", "name": "web", "title": "Web", "kind": "remote",
         "url": "https://mcp.example/mcp", "bearer": True}]}))
    path = tmp_path / "agent.json"
    _settings(path, extra=(str(catalog),))
    dlg = _dialog(path)
    cat = _open_catalog(dlg)
    assert "podman is not installed" in cat.podman_label.text()
    _click_entry(cat, "time")
    assert not cat.install_button.isEnabled()
    _click_entry(cat, "web")
    assert cat.install_button.isEnabled() and cat.token_edit.isEnabled()
    cat.token_edit.setText("tok")
    with mock.patch.object(C, "McpClient", side_effect=C.McpClientError("offline")):
        QTest.mouseClick(cat.install_button, Qt.MouseButton.LeftButton)
        _wait(lambda: cat.installs)
    assert "Test failed" in cat.log.toPlainText()
    (server,) = dlg.settings.mcp_servers
    assert (server.transport, server.url, server.enabled) == ("http", "https://mcp.example/mcp",
                                                              False)
    assert dlg._tokens["web"] == "tok"


def test_sad_a_failed_install_adds_nothing(tmp_path, monkeypatch):
    fake_podman(tmp_path, monkeypatch, fail={"pull": "Error: manifest unknown"})
    path = tmp_path / "agent.json"
    _settings(path)
    dlg = _dialog(path)
    cat = _open_catalog(dlg)
    _click_entry(cat, "time")
    QTest.mouseClick(cat.install_button, Qt.MouseButton.LeftButton)
    _wait(lambda: "Install failed" in cat.log.toPlainText())
    assert "manifest unknown" in cat.log.toPlainText()
    assert dlg.settings.mcp_servers == [] and cat.install_button.isEnabled()


def test_sad_an_install_can_be_cancelled(tmp_path, monkeypatch):
    fake_podman(tmp_path, monkeypatch, hang={"pull": 30})
    path = tmp_path / "agent.json"
    _settings(path)
    dlg = _dialog(path)
    cat = _open_catalog(dlg)
    _click_entry(cat, "time")
    QTest.mouseClick(cat.install_button, Qt.MouseButton.LeftButton)
    _wait(lambda: cat.cancel_button.isEnabled())
    assert not cat.install_button.isEnabled()
    QTest.mouseClick(cat.cancel_button, Qt.MouseButton.LeftButton)
    _wait(lambda: "cancelled" in cat.log.toPlainText(), seconds=15)
    assert dlg.settings.mcp_servers == []


def test_sad_a_missing_folder_or_secret_is_named(tmp_path, monkeypatch):
    podman = fake_podman(tmp_path, monkeypatch)
    path = tmp_path / "agent.json"
    _settings(path)
    dlg = _dialog(path)
    cat = _open_catalog(dlg)
    _click_entry(cat, "git")
    QTest.mouseClick(cat.install_button, Qt.MouseButton.LeftButton)
    assert "needs a folder at /repo" in cat.log.toPlainText()
    _click_entry(cat, "shodan")
    QTest.mouseClick(cat.install_button, Qt.MouseButton.LeftButton)
    assert "SHODAN_API_KEY needs a value" in cat.log.toPlainText()
    assert podman.calls("pull") == []


# -- edge ----------------------------------------------------------------------------


def test_edge_a_secret_goes_to_the_keyring_not_the_file(tmp_path, monkeypatch, keyring_store):
    fake_podman(tmp_path, monkeypatch)
    path = tmp_path / "agent.json"
    _settings(path)
    dlg = _dialog(path)
    cat = _open_catalog(dlg)
    _click_entry(cat, "shodan")
    cat.env_edit("SHODAN_API_KEY").setText("s3cr3t-key")
    QTest.mouseClick(cat.install_button, Qt.MouseButton.LeftButton)
    _wait(lambda: cat.installs)
    cat.close()
    assert dlg.save()
    assert keyring_store[("shodan", "SHODAN_API_KEY")] == "s3cr3t-key"
    assert "s3cr3t-key" not in path.read_text()
    (server,) = S.AgentSettings.load(path).mcp_servers
    assert server.secret_env == ("SHODAN_API_KEY",)


def test_edge_uninstall_removes_the_image_on_save(tmp_path, monkeypatch, keyring_store):
    podman = fake_podman(tmp_path, monkeypatch)
    path = tmp_path / "agent.json"
    _settings(path)
    dlg = _dialog(path)
    cat = _open_catalog(dlg)
    _click_entry(cat, "time")
    QTest.mouseClick(cat.install_button, Qt.MouseButton.LeftButton)
    _wait(lambda: cat.installs)
    cat.close()
    assert dlg.save()
    image = S.AgentSettings.load(path).mcp_servers[0].package["image"]
    dlg.server_list.setCurrentRow(0)
    assert dlg.uninstall_button.isEnabled()
    with mock.patch.object(QMessageBox, "question",
                           return_value=QMessageBox.StandardButton.Yes):
        QTest.mouseClick(dlg.uninstall_button, Qt.MouseButton.LeftButton)
    assert dlg.server_list.count() == 0
    assert podman.calls("rmi") == []  # not before Save
    assert dlg.save()
    assert ["rmi", image] in podman.calls("rmi")
    assert S.AgentSettings.load(path).mcp_servers == []


def test_edge_an_update_is_shown_never_applied(tmp_path):
    path = tmp_path / "agent.json"
    s = S.AgentSettings()
    s.mcp_servers.append(C.McpServerConfig(
        name="tz", command=("podman", "run", "x"), container=True,
        package={"kind": "npm", "identifier": "tz-mcp", "version": "0.1.0", "image": "a" * 64}))
    s.save(path)
    dlg = _dialog(path)
    dlg.server_list.setCurrentRow(0)
    assert dlg.update_button.isEnabled() and not dlg.server_sandbox_combo.isEnabled()
    opener = FakeOpener({"registry.npmjs.org/tz-mcp/latest": b'{"version": "0.2.0"}'})
    dlg.check_update(opener=opener)
    _wait(lambda: "update exists" in dlg.server_test_label.text())
    assert "0.2.0" in dlg.server_test_label.text()
    assert dlg.save()
    assert S.AgentSettings.load(path).mcp_servers[0].package["version"] == "0.1.0"


def test_edge_pulled_images_are_marked_and_names_kept_free(tmp_path, monkeypatch):
    podman = fake_podman(tmp_path, monkeypatch)
    entry = next(e for e in M.load_builtin()[0] if e.name == "time")
    podman.add_image("f" * 64, [entry.image_ref], [entry.image_ref])
    path = tmp_path / "agent.json"
    s = S.AgentSettings()
    s.mcp_sources = M.CatalogSources(dockerhub=False, mcpregistry=False)
    s.mcp_servers.append(C.McpServerConfig(name="time", command=("x",)))
    s.save(path)
    dlg = _dialog(path)
    cat = _open_catalog(dlg)
    _wait(lambda: any(cat.tree.topLevelItem(i).child(j).text(5) == "pulled"
                      for i in range(cat.tree.topLevelItemCount())
                      for j in range(cat.tree.topLevelItem(i).childCount())))
    _click_entry(cat, "time")
    assert cat.name_edit.text() == "time2"
    assert "Image: pulled" in cat.details.toPlainText()


def test_edge_an_allowlist_server_keeps_its_hosts_editable(tmp_path):
    path = tmp_path / "agent.json"
    s = S.AgentSettings()
    command = tuple(I.run_command("f", "img@sha256:" + "a" * 64, network="allowlist"))
    s.mcp_servers.append(C.McpServerConfig(name="f", command=command, container=True,
                                           egress=("example.com:443",)))
    s.save(path)
    dlg = _dialog(path)
    dlg.server_list.setCurrentRow(0)
    assert dlg.server_egress_edit.isEnabled()
    dlg.server_egress_edit.setText("example.com:443 nohost")
    assert any("allowed host" in p for p in dlg.problems())
    dlg.server_egress_edit.setText("")
    assert any("needs an allowed host" in p for p in dlg.problems())
    dlg.server_egress_edit.setText("api.example.org:443")
    assert dlg.save()
    assert S.AgentSettings.load(path).mcp_servers[0].egress == ("api.example.org:443",)


def test_edge_a_registry_entry_is_shown_as_untrusted_text(tmp_path, monkeypatch):
    fake_podman(tmp_path, monkeypatch)
    hostile = {"servers": [{"server": {
        "name": "io.evil/x", "description": "<b>bold</b>‮<script>alert(1)</script>",
        "version": "1", "repository": {"url": "javascript:alert(1)"},
        "packages": [{"registryType": "npm", "identifier": "x-mcp", "version": "1.0.0",
                      "transport": {"type": "stdio"}}]}, "_meta": {}}],
        "metadata": {"count": 1}}
    opener = FakeOpener({"registry.modelcontextprotocol.io": json.dumps(hostile).encode()})
    cat = __import__("ui.mcp_catalog_dialog", fromlist=["x"]).McpCatalogDialog(
        sources=M.CatalogSources(builtin=False, dockerhub=False), opener=opener)
    cat.show()
    _wait(lambda: cat.tree.topLevelItemCount() > 0)
    _click_entry(cat, "mcpregistry:io.evil/x")
    text = cat.details.toPlainText()
    assert "<b>bold</b>" in text and "‮" not in text  # as text, not as markup
    assert "javascript" not in text and not cat.open_page_button.isEnabled()
    cat.close()


# -- live ----------------------------------------------------------------------------


def test_live_the_dialog_installs_and_uninstalls_a_real_image(tmp_path, real_podman,  # noqa: F811
                                                             keyring_store):
    """The whole way with the user's rootless podman: catalog -> pull -> the
    dialog's own test -> Save -> Uninstall -> Save removes the image."""
    path = tmp_path / "agent.json"
    _settings(path)
    dlg = _dialog(path)
    cat = _open_catalog(dlg)
    _click_entry(cat, "time")
    cat.name_edit.setText("live-ui-time")
    QTest.mouseClick(cat.install_button, Qt.MouseButton.LeftButton)
    _wait(lambda: cat.installs, seconds=600)
    assert "Test passed" in cat.log.toPlainText(), cat.log.toPlainText()
    cat.close()
    assert dlg.save()
    (server,) = S.AgentSettings.load(path).mcp_servers
    assert server.enabled and server.container
    image = server.package["image"]
    assert real_podman.inspect(image) is not None
    dlg.server_list.setCurrentRow(0)
    assert dlg.uninstall_server(confirm=False)
    assert dlg.save()
    if server.package.get("preexisting") != "true":
        assert real_podman.inspect(image) is None
