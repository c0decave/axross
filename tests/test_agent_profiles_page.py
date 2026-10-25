"""Agent Settings > Profiles: the presets (read-only, "(preset)") and the
user's agent profiles - New, Copy, Delete, the profile of new tabs, a
preview of what a tab gets within the Access page, Install from Catalog…
for a missing category - and the Category of an MCP server."""

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

from core import agent_profiles as AP  # noqa: E402
from core import agent_settings as S  # noqa: E402
from core import llm_profiles as LP  # noqa: E402
from core import mcp_catalog as M  # noqa: E402
from core import mcp_client as C  # noqa: E402

APP = QApplication.instance() or QApplication([])
RE = "Security: Reverse Engineering"


def _dialog(path, **kw):
    from ui.agent_settings_dialog import AgentSettingsDialog

    llm = LP.LLMSettings([LP.LLMProfile(name="local"), LP.LLMProfile(name="big")], "local")
    return AgentSettingsDialog(settings_path=path, llm_settings=llm, **kw)


def _write(path, **data):
    path.write_text(json.dumps(data))


def _row(dlg, name):
    for i in range(dlg.agent_profile_list.count()):
        if dlg.agent_profile_list.item(i).data(Qt.ItemDataRole.UserRole) == name:
            return i
    raise AssertionError(name)


def _check(list_widget, text, on=True):
    item = list_widget.findItems(text, Qt.MatchFlag.MatchExactly)[0]
    item.setCheckState(Qt.CheckState.Checked if on else Qt.CheckState.Unchecked)


def _checked(list_widget):
    return [list_widget.item(i).text() for i in range(list_widget.count())
            if list_widget.item(i).checkState() == Qt.CheckState.Checked]


# -- happy ---------------------------------------------------------------------


def test_happy_presets_are_listed_read_only_and_a_copy_is_edited_and_saved(tmp_path):
    path = tmp_path / "settings.json"
    _write(path, mcp_servers=[{"name": "r2", "command": ["mcp-r2"], "category": RE}])
    dlg = _dialog(path)
    dlg.show_tab("profiles")
    labels = [dlg.agent_profile_list.item(i).text()
              for i in range(dlg.agent_profile_list.count())]
    assert labels[:len(AP.presets())] == [f"{p.name} (preset)" for p in AP.presets()]
    dlg.agent_profile_list.setCurrentRow(_row(dlg, "Research"))
    assert not dlg.agent_profile_form.isEnabled()
    assert not dlg.agent_profile_delete_button.isEnabled()
    QTest.mouseClick(dlg.agent_profile_copy_button, Qt.MouseButton.LeftButton)
    assert dlg.agent_profile_form.isEnabled()
    assert dlg.agent_profile_name_edit.text() == "Research copy"
    dlg.agent_profile_name_edit.setText("My Research")
    dlg.agent_profile_mode_combo.setCurrentIndex(
        dlg.agent_profile_mode_combo.findData("plan"))
    _check(dlg.agent_profile_categories, RE)
    _check(dlg.agent_profile_servers, "r2")
    dlg.agent_profile_access.function_checks["remote_files"].setChecked(True)
    dlg.agent_profile_default_combo.setCurrentIndex(
        dlg.agent_profile_default_combo.findData("My Research"))
    assert dlg.save()
    back = S.AgentSettings.load(path)
    mine = back.agent_profiles[0]
    assert (mine.name, mine.mode) == ("My Research", "plan")
    assert RE in mine.mcp_categories and "r2" in mine.mcp_servers
    assert {"fetch", "memory", "sequentialthinking"} <= set(mine.mcp_servers)
    assert not mine.allow_write and "remote_files" in mine.functions
    assert back.agent_profile == "My Research"


def test_happy_new_profile_and_server_category_are_saved(tmp_path):
    path = tmp_path / "settings.json"
    _write(path, mcp_servers=[{"name": "tool", "command": ["mcp-tool"]}])
    dlg = _dialog(path)
    dlg.server_list.setCurrentRow(0)
    dlg.server_category_combo.setEditText("Lab Tools")
    dlg.add_agent_profile()
    dlg.agent_profile_name_edit.setText("Lab")
    assert "Lab Tools" in [dlg.agent_profile_categories.item(i).text()
                           for i in range(dlg.agent_profile_categories.count())]
    _check(dlg.agent_profile_categories, "Lab Tools")
    dlg.agent_profile_access.axross_check.setChecked(True)
    dlg.agent_profile_access.function_checks["mcp_servers"].setChecked(True)
    assert dlg.save()
    back = S.AgentSettings.load(path)
    assert back.mcp_servers[0].category == "Lab Tools"
    lab = back.agent_profiles[0]
    assert lab.mcp_categories == ("Lab Tools",) and lab.axross


def test_happy_the_preview_shows_what_a_tab_gets_and_follows_the_access_page(tmp_path):
    path = tmp_path / "settings.json"
    _write(path, mcp_servers=[{"name": "r2", "command": ["mcp-r2"], "category": RE}])
    dlg = _dialog(path)
    dlg.agent_profile_list.setCurrentRow(_row(dlg, "Reverse Engineering"))
    text = dlg.agent_profile_preview.toPlainText()
    assert "MCP servers: r2" in text
    assert "axross functions are off in Agent Settings > Access" in text
    assert "Security: Firmware & Forensics" in text  # missing
    dlg.axross_check.setChecked(True)
    dlg.mcp_servers_check.setChecked(True)
    text = dlg.agent_profile_preview.toPlainText()
    assert "axross functions are off" not in text and "axross functions: MCP servers" in text


# -- sad -----------------------------------------------------------------------


def test_sad_a_preset_cannot_be_deleted_or_changed(tmp_path):
    dlg = _dialog(tmp_path / "settings.json")
    dlg.agent_profile_list.setCurrentRow(_row(dlg, "Remote Ops"))
    dlg.delete_agent_profile()
    assert dlg.agent_profile_list.count() == len(AP.presets())
    dlg.agent_profile_name_edit.setText("Hacked")  # disabled, but set anyway
    assert AP.preset("Remote Ops").name == "Remote Ops"
    assert dlg.save() and S.AgentSettings.load(tmp_path / "settings.json").agent_profiles == []


def test_sad_duplicate_and_preset_names_refuse_to_save(tmp_path, monkeypatch):
    warned = []
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: warned.append(a[2]))
    dlg = _dialog(tmp_path / "settings.json")
    dlg.add_agent_profile()
    dlg.agent_profile_name_edit.setText("Twin")
    dlg.add_agent_profile()
    dlg.agent_profile_name_edit.setText("twin")
    assert not dlg.save()
    assert "Two agent profiles are named twin." in warned[-1]
    dlg.agent_profile_name_edit.setText("Research")
    assert not dlg.save() and "belongs to a preset" in warned[-1]


def test_sad_deleting_the_default_profile_resets_the_default(tmp_path):
    path = tmp_path / "settings.json"
    _write(path, agent_profiles=[{"name": "Mine"}], agent_profile="Mine")
    dlg = _dialog(path)
    assert dlg.agent_profile_default_combo.currentData() == "Mine"
    dlg.agent_profile_list.setCurrentRow(_row(dlg, "Mine"))
    dlg.delete_agent_profile()
    assert dlg.agent_profile_default_combo.currentData() == ""
    assert dlg.save()
    back = S.AgentSettings.load(path)
    assert back.agent_profiles == [] and back.agent_profile == ""


# -- edge ----------------------------------------------------------------------


def test_edge_an_unknown_category_of_the_file_stays_ticked(tmp_path):
    path = tmp_path / "settings.json"
    _write(path, agent_profiles=[{"name": "Odd", "mcp_categories": ["Somewhere Else"],
                                  "mcp_servers": ["ghost"]}])
    dlg = _dialog(path)
    dlg.agent_profile_list.setCurrentRow(_row(dlg, "Odd"))
    assert "Somewhere Else" in _checked(dlg.agent_profile_categories)
    assert "ghost" in _checked(dlg.agent_profile_servers)
    assert dlg.save()
    odd = S.AgentSettings.load(path).agent_profiles[0]
    assert odd.mcp_categories == ("Somewhere Else",) and odd.mcp_servers == ("ghost",)


def test_edge_install_from_catalog_opens_on_the_missing_category(tmp_path):
    path = tmp_path / "settings.json"
    _write(path, mcp_sources={"builtin": True, "dockerhub": False, "mcpregistry": False,
                              "c0decave": False, "discover": False})
    dlg = _dialog(path)
    dlg.agent_profile_list.setCurrentRow(_row(dlg, "Forensics read-only"))
    items = [dlg.agent_profile_missing.item(i).text()
             for i in range(dlg.agent_profile_missing.count())]
    assert any("Security: Firmware & Forensics" in t for t in items)
    dlg.agent_profile_missing.setCurrentRow(0)
    catalog = dlg.install_missing()
    try:
        assert catalog.category_combo.currentData() == "Security: Firmware & Forensics"
        end = time.monotonic() + 10
        while time.monotonic() < end and not catalog.status_label.text():
            APP.processEvents()
            time.sleep(0.01)
        assert catalog.category_combo.currentData() == "Security: Firmware & Forensics"
    finally:
        catalog.reject()


def test_edge_the_profiles_page_is_a_tab_of_its_own(tmp_path):
    from ui.agent_settings_dialog import AGENT_TABS

    assert ("profiles", "Profiles") in AGENT_TABS
    dlg = _dialog(tmp_path / "settings.json")
    dlg.show_tab("profiles")
    assert dlg.tabs.currentWidget() is dlg.agent_profiles_page


def test_edge_the_server_category_offers_the_known_ones(tmp_path, monkeypatch):
    warned = []
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: warned.append(a[2]))
    path = tmp_path / "settings.json"
    _write(path, mcp_servers=[{"name": "tool", "command": ["mcp-tool"]}])
    dlg = _dialog(path)
    dlg.server_list.setCurrentRow(0)
    known = [dlg.server_category_combo.itemText(i)
             for i in range(dlg.server_category_combo.count())]
    assert "" in known and RE in known and "Files & Dev" in known
    dlg.server_category_combo.setEditText("bad\u202ecategory")
    assert not dlg.save() and "category" in warned[-1]


@pytest.mark.parametrize("bad", [5, None, "x"])
def test_edge_a_broken_profiles_entry_does_not_break_the_page(tmp_path, bad):
    path = tmp_path / "settings.json"
    _write(path, agent_profiles=bad, agent_profile=bad)
    dlg = _dialog(path)
    assert dlg.agent_profile_list.count() == len(AP.presets())
    assert dlg.save()


def test_edge_the_profile_access_editor_has_no_folders(tmp_path):
    dlg = _dialog(tmp_path / "settings.json")
    dlg.show()
    dlg.show_tab("profiles")
    APP.processEvents()
    assert not dlg.agent_profile_access.folders_table.isVisibleTo(dlg)
    dlg.close()


def test_edge_a_long_description_shows_its_beginning(tmp_path):
    """Seen on the README screenshot: the Profiles page showed the end of a
    preset's long description - QLineEdit.setText leaves the cursor at the
    end, and the field scrolls to it."""
    dlg = _dialog(tmp_path / "agent.json")
    edit = dlg.agent_profile_description_edit
    for i in range(dlg.agent_profile_list.count()):
        dlg.agent_profile_list.setCurrentRow(i)
        if edit.text():
            assert edit.cursorPosition() == 0, dlg.agent_profile_list.item(i).text()
            assert dlg.agent_profile_name_edit.cursorPosition() == 0
    dlg.deleteLater()
