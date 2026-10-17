"""Tools > Agent Settings…: General, Access and the sandbox profiles."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core import agent_settings as S  # noqa: E402
from core import llm_profiles as LP  # noqa: E402
from core.agent_sandbox import SandboxProfile  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _dialog(path, **kw):
    from ui.agent_settings_dialog import AgentSettingsDialog

    llm = LP.LLMSettings([LP.LLMProfile(name="local"), LP.LLMProfile(name="big")], "local")
    return AgentSettingsDialog(settings_path=path, llm_settings=llm, **kw)


def _select(combo, data):
    combo.setCurrentIndex(combo.findData(data))


# -- happy ---------------------------------------------------------------------


def test_happy_general_and_access_are_saved(tmp_path):
    path = tmp_path / "settings.json"
    dlg = _dialog(path)
    _select(dlg.profile_combo, "big")
    _select(dlg.mode_combo, "plan")
    dlg.steps_spin.setValue(40)
    dlg.remote_files_check.setChecked(True)
    dlg.groups_list.findItems("index", Qt.MatchFlag.MatchExactly)[0].setCheckState(
        Qt.CheckState.Checked
    )
    saved = []
    dlg.saved.connect(lambda: saved.append(1))
    assert dlg.save()
    back = S.AgentSettings.load(path)
    assert (back.profile, back.mode, back.max_steps) == ("big", "plan", 40)
    assert back.access.remote_files and "index" in back.groups
    assert saved == [1]


def test_happy_a_sandbox_profile_with_hosts_and_folders(tmp_path):
    path = tmp_path / "settings.json"
    data = tmp_path / "data"
    data.mkdir()
    dlg = _dialog(path)
    dlg.add_sandbox()
    dlg.name_edit.setText("Ops")
    _select(dlg.level_combo, "normal")
    dlg.host_edit.setText("DB.example:5432")
    dlg.add_host()
    dlg.add_mount(str(data))
    dlg.mounts_table.cellWidget(0, 1).setCurrentIndex(1)  # read-write
    _select(dlg.default_sandbox_combo, "Ops")
    dlg._rebuild_sandbox_list()
    _select(dlg.default_sandbox_combo, "Ops")
    assert dlg.save()
    back = S.AgentSettings.load(path)
    ops = back.sandbox_profile("Ops")
    assert ops.hosts == ("db.example:5432",)
    assert ops.mounts == ((str(data), True),)
    assert back.sandbox == "Ops"


# -- sad -----------------------------------------------------------------------


def test_sad_a_host_without_port_is_refused(tmp_path):
    dlg = _dialog(tmp_path / "s.json")
    dlg.sandbox_list.setCurrentRow(1)  # Normal
    dlg.host_edit.setText("db.example")
    with mock.patch.object(QMessageBox, "warning") as warned:
        dlg.add_host()
    warned.assert_called_once()
    assert dlg.hosts_list.count() == 0


def test_sad_two_sandboxes_with_one_name_are_not_saved(tmp_path):
    path = tmp_path / "s.json"
    dlg = _dialog(path)
    dlg.sandbox_list.setCurrentRow(0)
    dlg.name_edit.setText("Normal")
    with mock.patch.object(QMessageBox, "warning") as warned:
        assert not dlg.save()
    assert "Normal" in str(warned.call_args)
    assert not path.exists()


def test_sad_bypass_is_offered_only_with_its_switch(tmp_path):
    dlg = _dialog(tmp_path / "s.json")
    modes = [dlg.mode_combo.itemData(i) for i in range(dlg.mode_combo.count())]
    assert "bypass" not in modes
    dlg.bypass_check.setChecked(True)
    modes = [dlg.mode_combo.itemData(i) for i in range(dlg.mode_combo.count())]
    assert modes == list(S.MODES)


# -- edge ----------------------------------------------------------------------


def test_edge_the_level_decides_whether_hosts_and_writable_folders_count(tmp_path):
    dlg = _dialog(tmp_path / "s.json")
    dlg.sandbox_list.setCurrentRow(0)
    for level, hosts_on, rw_note in (("lax", False, False), ("normal", True, False),
                                     ("high", True, True), ("paranoid", False, True)):
        _select(dlg.level_combo, level)
        assert dlg.hosts_list.isEnabled() is hosts_on, level
        assert bool(dlg.mounts_note.text()) is rw_note, level


def test_edge_deleting_the_default_sandbox_falls_back_to_none(tmp_path):
    path = tmp_path / "s.json"
    settings = S.AgentSettings(sandbox="Only", sandboxes=[SandboxProfile(name="Only")])
    settings.save(path)
    dlg = _dialog(path)
    dlg.sandbox_list.setCurrentRow(0)
    dlg.delete_sandbox()
    assert dlg.save()
    back = S.AgentSettings.load(path)
    assert back.sandboxes == [] and back.sandbox == ""


def test_edge_the_tools_menu_opens_it(tmp_path, monkeypatch):
    from ui import main_window as MW

    monkeypatch.setattr(S, "settings_file", lambda: tmp_path / "agent.json")
    with mock.patch("pathlib.Path.home", return_value=tmp_path):
        win = MW.MainWindow()
    try:
        actions = [a for a in win.menuBar().actions() if a.menu() is not None]
        tools = next(a.menu() for a in actions if a.text().replace("&", "") == "Tools")
        labels = [a.text().replace("&", "") for a in tools.actions()]
        assert "Agent Settings…" in labels
    finally:
        win.close()
        win.deleteLater()


def test_edge_the_llm_profile_keeps_tuning_under_advanced(tmp_path):
    from ui.llm_settings_dialog import LLMSettingsDialog

    path = tmp_path / "llm.json"
    dlg = LLMSettingsDialog(settings_path=path)
    dlg.show()
    APP.processEvents()
    dlg.add_profile()
    dlg.name_edit.setText("local")
    assert not dlg.advanced_box.isVisible()
    assert dlg.name_edit.isVisible() and dlg.endpoint_edit.isVisible()
    dlg.advanced_button.setChecked(True)
    APP.processEvents()
    assert dlg.advanced_box.isVisible() and dlg.temperature_spin.isVisible()
    dlg.temperature_spin.setValue(0.7)
    assert dlg.save()
    assert LP.LLMSettings.load(path).profile("local").temperature == 0.7
    dlg.close()
