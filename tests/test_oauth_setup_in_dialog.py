"""The connection dialog says where an OAuth sign-in's credentials come from.

The operator asked in the connection dialog where Google Drive's OAuth
values come from and whether there is a live login. The login was there
(the browser opens on Connect), the guide only in OAUTH_SETUP.md. Now the
dialog shows, for each OAuth service, what to create where (with the
console's link) and that the sign-in happens in the browser; Google's
downloaded client file fills both fields (core.oauth_help).
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core import oauth_help as OH  # noqa: E402
from core.profiles import ProfileManager  # noqa: E402

APP = QApplication.instance() or QApplication([])

_GOOGLE = {"installed": {"client_id": "123-abc.apps.googleusercontent.com",
                         "client_secret": "GOCSPX-secret", "project_id": "p",
                         "redirect_uris": ["http://localhost"]}}


# -- core.oauth_help ----------------------------------------------------------------------------

@pytest.mark.parametrize("proto", ["gdrive", "onedrive", "sharepoint", "dropbox"])
def test_happy_every_oauth_service_has_a_guide_with_its_console(proto):
    guide = OH.GUIDES[proto]
    assert guide.console_url.startswith("https://")
    assert guide.steps and all(step.strip() for step in guide.steps)
    assert "browser" in guide.sign_in.lower()


def test_happy_a_google_desktop_client_file_gives_id_and_secret():
    assert OH.parse_google_client(json.dumps(_GOOGLE)) == (
        "123-abc.apps.googleusercontent.com", "GOCSPX-secret")


def test_sad_a_web_application_client_is_refused_with_the_reason():
    text = json.dumps({"web": _GOOGLE["installed"]})
    with pytest.raises(ValueError, match="Desktop app"):
        OH.parse_google_client(text)


@pytest.mark.parametrize("text", ["", "{", "[]", '{"installed": {}}',
                                  '{"installed": {"client_id": 5, "client_secret": "x"}}'])
def test_sad_a_file_that_is_no_client_file_is_refused(text):
    with pytest.raises(ValueError):
        OH.parse_google_client(text)


def test_edge_a_huge_file_is_refused_before_parsing():
    with pytest.raises(ValueError, match="too large"):
        OH.parse_google_client(" " * (OH.MAX_CLIENT_FILE_BYTES + 1))


def test_edge_values_are_trimmed():
    data = {"installed": {"client_id": "  id \n", "client_secret": "\tsecret "}}
    assert OH.parse_google_client(json.dumps(data)) == ("id", "secret")


# -- the dialog ---------------------------------------------------------------------------------

@pytest.fixture()
def dialog():
    with tempfile.TemporaryDirectory() as tmp:
        with mock.patch("core.profiles.CONFIG_DIR", Path(tmp)), mock.patch(
            "core.profiles.PROFILES_FILE", Path(tmp) / "profiles.json"
        ), mock.patch.object(QMessageBox, "information"), mock.patch.object(
            QMessageBox, "warning"
        ):
            from ui.connection_dialog import ConnectionDialog

            dlg = ConnectionDialog(ProfileManager())
            dlg.show()
            yield dlg
            dlg.close()
            dlg.deleteLater()


def _choose(dlg, proto):
    dlg._protocol_combo.setCurrentIndex(dlg._protocol_ids.index(proto))
    APP.processEvents()


@pytest.mark.parametrize("proto", ["gdrive", "onedrive", "sharepoint", "dropbox"])
def test_happy_e2e_an_oauth_service_shows_its_guide(dialog, proto):
    _choose(dialog, proto)
    assert dialog._oauth_help.isVisible()
    text = dialog._oauth_help.text()
    assert OH.GUIDES[proto].console_url in text
    assert "browser" in text.lower()


@pytest.mark.parametrize("proto", ["sftp", "smb", "s3"])
def test_edge_e2e_other_protocols_show_no_guide(dialog, proto):
    _choose(dialog, proto)
    assert not dialog._oauth_help.isVisible()
    assert not dialog._gdrive_import.isVisible()


def test_happy_e2e_import_client_file_fills_google_id_and_secret(dialog, tmp_path):
    path = tmp_path / "client_secret_123.json"
    path.write_text(json.dumps(_GOOGLE))
    _choose(dialog, "gdrive")
    assert dialog._gdrive_import.isVisible()
    with mock.patch("ui.connection_dialog.QFileDialog.getOpenFileName",
                    return_value=(str(path), "")):
        dialog._gdrive_import.click()
    assert dialog._gdrive_client_id.text() == "123-abc.apps.googleusercontent.com"
    assert dialog._gdrive_client_secret.text() == "GOCSPX-secret"


def test_sad_e2e_a_wrong_client_file_says_why_and_changes_nothing(dialog, tmp_path):
    path = tmp_path / "web.json"
    path.write_text(json.dumps({"web": _GOOGLE["installed"]}))
    _choose(dialog, "gdrive")
    dialog._gdrive_client_id.setText("kept")
    with mock.patch("ui.connection_dialog.QFileDialog.getOpenFileName",
                    return_value=(str(path), "")), \
            mock.patch("ui.connection_dialog.QMessageBox.warning") as warning:
        dialog._gdrive_import.click()
    assert dialog._gdrive_client_id.text() == "kept"
    assert warning.called and "Desktop app" in str(warning.call_args)


def test_edge_e2e_cancelling_the_file_choice_changes_nothing(dialog):
    _choose(dialog, "gdrive")
    dialog._gdrive_client_id.setText("kept")
    with mock.patch("ui.connection_dialog.QFileDialog.getOpenFileName", return_value=("", "")):
        dialog._gdrive_import.click()
    assert dialog._gdrive_client_id.text() == "kept"
