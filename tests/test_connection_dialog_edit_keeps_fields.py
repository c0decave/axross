"""Editing a profile in the connection dialog keeps what the form does
not show.

Found in review: ``_build_profile`` constructed a brand-new
ConnectionProfile from the form widgets only. A profile carries more
than the form edits - ``production`` (the destructive-op tarpit),
``ftps_verify_tls``, ``terminal_theme``, ``suppress_shell_history``,
``ssh_keepalive_interval``, ``adb_mode`` and others, set through JSON
import or scripting. Opening such a profile and pressing Save reset all
of them to their defaults, silently switching the production guard off.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core.profiles import ConnectionProfile, ProfileManager  # noqa: E402

APP = QApplication.instance() or QApplication([])

# Fields the form has no widget for, each set away from its default.
HIDDEN = {
    "production": True,
    "terminal_theme": "Amber",
    "suppress_shell_history": False,
    "ssh_keepalive_interval": 30,
    "rsync_preserve_metadata": True,
    "smb_client_name": "WS01",
    "telnet_naws_width": 132,
    "telnet_naws_height": 50,
}


@pytest.fixture()
def manager():
    with tempfile.TemporaryDirectory() as tmp:
        with mock.patch("core.profiles.CONFIG_DIR", Path(tmp)), mock.patch(
            "core.profiles.PROFILES_FILE", Path(tmp) / "profiles.json"
        ), mock.patch.object(QMessageBox, "information"), mock.patch.object(
            QMessageBox, "warning"
        ):
            yield ProfileManager()


def _dialog(manager, profile=None):
    from ui.connection_dialog import ConnectionDialog

    return ConnectionDialog(manager, profile=profile)


def _saved_profile(**overrides) -> ConnectionProfile:
    fields = dict(name="prod-db", host="db.example.com", username="ops", **HIDDEN)
    fields.update(overrides)
    return ConnectionProfile(**fields)


def test_happy_saving_an_edited_profile_keeps_the_fields_the_form_lacks(manager):
    manager.add(_saved_profile())
    dlg = _dialog(manager, manager.get("prod-db"))
    dlg._host.setText("db2.example.com")  # the one change the user made
    dlg._save_profile()
    saved = manager.get("prod-db")
    assert saved.host == "db2.example.com"
    for name, value in HIDDEN.items():
        assert getattr(saved, name) == value, name
    dlg.close()


def test_happy_the_profile_picked_in_the_combo_keeps_its_fields_too(manager):
    manager.add(_saved_profile())
    dlg = _dialog(manager)
    dlg._profile_combo.setCurrentText("prod-db")
    dlg._username.setText("root")
    dlg._save_profile()
    saved = manager.get("prod-db")
    assert saved.username == "root"
    assert saved.production is True
    dlg.close()


def test_happy_connect_hands_on_the_full_profile(manager):
    manager.add(_saved_profile())
    dlg = _dialog(manager, manager.get("prod-db"))
    dlg._on_accept()
    assert dlg.result_profile.production is True
    assert dlg.result_profile.terminal_theme == "Amber"
    dlg.close()


def test_edge_ftps_lab_server_keeps_tls_verification_off(manager):
    manager.add(
        ConnectionProfile(
            name="lab-ftps", protocol="ftps", host="lab.local", port=990,
            username="u", ftps_verify_tls=False,
        )
    )
    dlg = _dialog(manager, manager.get("lab-ftps"))
    dlg._save_profile()
    assert manager.get("lab-ftps").ftps_verify_tls is False
    dlg.close()


def test_edge_a_new_connection_after_editing_starts_from_defaults(manager):
    """Switching to "(New Connection)" must not leak the last profile's
    hidden fields into a fresh one."""
    manager.add(_saved_profile())
    dlg = _dialog(manager)
    dlg._profile_combo.setCurrentText("prod-db")
    dlg._profile_combo.setCurrentText("(New Connection)")
    dlg._profile_name.setText("fresh")
    dlg._host.setText("fresh.example.com")
    dlg._username.setText("me")
    dlg._save_profile()
    fresh = manager.get("fresh")
    assert fresh.production is False
    assert fresh.terminal_theme == ""
    assert fresh.ssh_keepalive_interval == 0
    dlg.close()


def test_edge_renaming_keeps_the_fields_on_the_new_name(manager):
    manager.add(_saved_profile())
    dlg = _dialog(manager, manager.get("prod-db"))
    dlg._profile_name.setText("prod-db-2")
    dlg._save_profile()
    assert manager.get("prod-db") is None
    assert manager.get("prod-db-2").production is True
    dlg.close()


def test_sad_an_invalid_edit_saves_nothing_and_changes_nothing(manager):
    manager.add(_saved_profile())
    dlg = _dialog(manager, manager.get("prod-db"))
    dlg._host.setText("bad host")
    dlg._save_profile()
    saved = manager.get("prod-db")
    assert saved.host == "db.example.com"
    assert saved.production is True
    dlg.close()
