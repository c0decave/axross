"""The production countdown is switched on in the connection dialog.

docs/DAILY_DRIVER.md describes the production tarpit (a countdown before
the first destructive operation on a profile flagged ``production``), but
the product review found no way to set the flag in the GUI: the dialog
only carried it over when editing a profile set up in Python.
"""

from __future__ import annotations

import json
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


def test_happy_the_check_box_is_there_and_off_for_a_new_connection(manager):
    dlg = _dialog(manager)
    try:
        box = dlg._production
        assert box.text() == "Production (confirm destructive operations with a countdown)"
        assert not box.isChecked()
        dlg.show()
        assert box.isVisible()
        assert "countdown" in box.toolTip()
    finally:
        dlg.close()


def test_happy_checking_it_saves_a_production_profile(manager):
    dlg = _dialog(manager)
    try:
        dlg._profile_name.setText("prod-db")
        dlg._host.setText("db.example.com")
        dlg._username.setText("ops")
        dlg._production.setChecked(True)
        dlg._save_profile()
    finally:
        dlg.close()
    assert manager.get("prod-db").production is True
    # and it is what ProfileManager writes to disk
    fresh = ProfileManager()
    assert fresh.get("prod-db").production is True


def test_happy_editing_shows_the_flag_and_unchecking_clears_it(manager):
    manager.add(ConnectionProfile(name="prod-db", host="db.example.com", username="ops",
                                  production=True))
    dlg = _dialog(manager, manager.get("prod-db"))
    try:
        assert dlg._production.isChecked()
        dlg._production.setChecked(False)
        dlg._save_profile()
    finally:
        dlg.close()
    assert manager.get("prod-db").production is False


@pytest.mark.parametrize("protocol", ["sftp", "s3", "webdav", "smb", "ftp"])
def test_edge_it_is_offered_for_every_protocol(manager, protocol):
    dlg = _dialog(manager)
    try:
        dlg.show()
        if protocol not in dlg._protocol_ids:
            pytest.skip(f"{protocol} not registered here")
        dlg._protocol_combo.setCurrentIndex(dlg._protocol_ids.index(protocol))
        APP.processEvents()
        assert dlg._production.isVisible()
        dlg._production.setChecked(True)
        assert dlg._build_profile().production is True
    finally:
        dlg.close()


def test_edge_clearing_the_form_switches_it_off(manager):
    manager.add(ConnectionProfile(name="prod-db", host="db.example.com", production=True))
    dlg = _dialog(manager, manager.get("prod-db"))
    try:
        dlg._clear_fields()
        assert not dlg._production.isChecked()
    finally:
        dlg.close()


def test_sad_the_flag_is_not_written_for_an_ordinary_profile(manager, tmp_path):
    dlg = _dialog(manager)
    try:
        dlg._profile_name.setText("lab")
        dlg._host.setText("lab.example.com")
        dlg._username.setText("ops")
        dlg._save_profile()
    finally:
        dlg.close()
    assert manager.get("lab").production is False
    from core import profiles as P

    assert "production" not in json.dumps(json.loads(P.PROFILES_FILE.read_text()))


def test_happy_the_german_interface_translates_the_check_box() -> None:
    """The label and the tooltip are tr() strings; de.json had neither, so
    the German Connect to Server showed this one check box in English."""
    import ast

    root = Path(__file__).resolve().parent.parent
    source = (root / "ui" / "connection_dialog.py").read_text(encoding="utf-8")
    strings = {
        node.args[0].value
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "tr"
        and node.args and isinstance(node.args[0], ast.Constant)
    }
    wanted = {s for s in strings if "countdown" in s}
    assert len(wanted) == 2
    german = json.loads((root / "resources" / "i18n" / "de.json").read_text(encoding="utf-8"))
    assert {s: bool(german.get(s, "").strip()) for s in wanted} == {s: True for s in wanted}
