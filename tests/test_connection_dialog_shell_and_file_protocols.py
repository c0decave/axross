"""Connection Manager dialog: the fields of the SSH / FTP / shell-family
protocols (connection-type review of 2026-11-18).

* rsh logs in as the local user when no name is given (``rsh`` without
  ``-l``), but the dialog demanded a username.
* TFTP has no directory listing: without its file list a TFTP pane is
  always empty - and the dialog had no field for that list (nor for the
  size cap), so a TFTP connection from the dialog never showed a file.
* FTPS: "verify the certificate" existed on the profile only; a lab server
  with a self-signed certificate could not be used from the dialog.
* WinRM was always HTTPS with a verified certificate: the HTTP listener
  (5985, Windows' default) and the self-signed HTTPS listener (what
  ``winrm quickconfig -transport:https`` sets up) could not be used.
* rsync's "keep owner, permissions and times" had no field.
* The IP Version choice was shown for protocols whose backend ignores it;
  WMI showed a Port that is never used (DCOM's endpoint mapper is 135).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core.backend_registry import init_registry  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402

APP = QApplication.instance() or QApplication([])
init_registry()


@pytest.fixture
def dialog():
    from core.profiles import ProfileManager
    from ui.connection_dialog import ConnectionDialog

    warnings: list[str] = []
    with (
        mock.patch.object(
            QMessageBox, "warning", side_effect=lambda *a, **k: warnings.append(a[2])
        ),
        mock.patch.object(ConnectionDialog, "_validate_backend_available", return_value=True),
    ):
        dlg = ConnectionDialog(ProfileManager())
        dlg.show()
        APP.processEvents()

        def pick(proto: str):
            dlg._clear_fields()
            dlg._protocol_combo.setCurrentIndex(dlg._protocol_ids.index(proto))
            APP.processEvents()
            dlg._profile_name.setText(f"my-{proto}")
            warnings.clear()
            return dlg

        yield pick, warnings
        dlg.close()


def test_rsh_needs_no_username(dialog):
    pick, warnings = dialog
    dlg = pick("rsh")
    dlg._host.setText("oldbox")
    assert dlg._validate(), warnings
    assert dlg._build_profile().port == 514


def test_tftp_file_list_and_size_cap_are_fields(dialog):
    pick, _ = dialog
    dlg = pick("tftp")
    assert dlg._tftp_filelist.isVisible() and dlg._tftp_max_size.isVisible()
    dlg._host.setText("10.0.0.1")
    dlg._tftp_filelist.setText("pxelinux.0, configs/router.cfg")
    dlg._tftp_max_size.setValue(64)
    p = dlg._build_profile()
    assert p.tftp_filelist == "pxelinux.0, configs/router.cfg"
    assert p.tftp_filelist_enabled is True
    assert p.tftp_max_size_bytes == 64 * 1024 * 1024


def test_tftp_fields_load_from_the_profile(dialog):
    pick, _ = dialog
    dlg = pick("sftp")
    dlg._load_profile(ConnectionProfile(
        name="t", protocol="tftp", host="h", port=69, tftp_filelist="a.bin",
        tftp_filelist_enabled=True, tftp_max_size_bytes=2 * 1024 * 1024))
    assert dlg._tftp_filelist.text() == "a.bin"
    assert dlg._tftp_max_size.value() == 2
    p = dlg._build_profile()
    assert (p.tftp_filelist, p.tftp_filelist_enabled) == ("a.bin", True)


def test_tftp_without_a_list_lists_nothing(dialog):
    pick, _ = dialog
    dlg = pick("tftp")
    dlg._host.setText("h")
    assert dlg._build_profile().tftp_filelist_enabled is False


def test_ftps_certificate_check_is_a_field(dialog):
    pick, _ = dialog
    dlg = pick("ftps")
    assert dlg._tls_verify.isVisible() and dlg._tls_verify.isChecked()
    dlg._host.setText("lab")
    dlg._username.setText("u")
    dlg._tls_verify.setChecked(False)
    assert dlg._build_profile().ftps_verify_tls is False
    dlg._load_profile(ConnectionProfile(name="x", protocol="ftps", host="h", port=21,
                                        username="u", ftps_verify_tls=False))
    assert not dlg._tls_verify.isChecked()
    dlg._load_profile(ConnectionProfile(name="y", protocol="ftps", host="h", port=21,
                                        username="u"))
    assert dlg._tls_verify.isChecked()


def test_plain_ftp_shows_no_certificate_check(dialog):
    pick, _ = dialog
    dlg = pick("ftp")
    assert not dlg._tls_verify.isVisible()
    assert not dlg._winrm_https.isVisible()


def test_winrm_http_and_certificate_are_fields(dialog):
    pick, _ = dialog
    dlg = pick("winrm")
    assert dlg._winrm_https.isVisible() and dlg._winrm_https.isChecked()
    assert dlg._tls_verify.isVisible() and dlg._tls_verify.isChecked()
    assert dlg._port.value() == 5986
    dlg._winrm_https.setChecked(False)
    # The HTTP listener's port follows, and a certificate check means nothing.
    assert dlg._port.value() == 5985
    assert not dlg._tls_verify.isEnabled()
    dlg._host.setText("win")
    dlg._username.setText("Administrator")
    p = dlg._build_profile()
    assert (p.winrm_https, p.port) == (False, 5985)
    dlg._winrm_https.setChecked(True)
    assert dlg._port.value() == 5986
    dlg._tls_verify.setChecked(False)
    p = dlg._build_profile()
    assert (p.winrm_https, p.winrm_verify_tls) == (True, False)


def test_winrm_custom_port_is_kept_when_switching_scheme(dialog):
    pick, _ = dialog
    dlg = pick("winrm")
    dlg._port.setValue(8443)
    dlg._winrm_https.setChecked(False)
    assert dlg._port.value() == 8443


def test_winrm_fields_round_trip_through_profiles_json():
    p = ConnectionProfile(name="w", protocol="winrm", host="h", port=5985, username="u",
                          winrm_https=False, winrm_verify_tls=False)
    back = ConnectionProfile.from_dict(p.to_dict())
    assert (back.winrm_https, back.winrm_verify_tls) == (False, False)
    default = ConnectionProfile.from_dict(
        ConnectionProfile(name="w", protocol="winrm", host="h", username="u").to_dict())
    assert (default.winrm_https, default.winrm_verify_tls) == (True, True)
    odd = ConnectionProfile(name="w", protocol="winrm", host="h", port=5985, username="u")
    assert ConnectionProfile.from_dict(odd.to_dict()).winrm_https is True


def test_winrm_profile_saved_before_the_https_field_follows_its_port():
    # Saved before winrm_https existed: port 5985 is the HTTP listener.
    old = ConnectionProfile.from_dict(
        {"name": "w", "protocol": "winrm", "host": "h", "port": 5985, "username": "u"})
    assert old.winrm_https is False
    old = ConnectionProfile.from_dict(
        {"name": "w", "protocol": "winrm", "host": "h", "port": 5986, "username": "u"})
    assert old.winrm_https is True


def test_winrm_fields_reach_the_backend_and_the_session_key(monkeypatch):
    from core import connection_manager as CM

    made = []
    monkeypatch.setattr(CM, "load_backend_class",
                        lambda proto: lambda **kw: made.append(kw) or mock.Mock(connected=True))
    p = ConnectionProfile(name="w", protocol="winrm", host="h", port=5985, username="u",
                          winrm_https=False, winrm_verify_tls=False)
    CM.ConnectionManager()._create_session(p, "pw", "", None)
    assert made[-1]["use_https"] is False and made[-1]["verify_ssl"] is False
    mgr = CM.ConnectionManager()
    https = ConnectionProfile(name="w", protocol="winrm", host="h", port=5985, username="u")
    assert mgr._session_key(p) != mgr._session_key(https)
    unverified = ConnectionProfile(name="w", protocol="winrm", host="h", port=5985,
                                   username="u", winrm_verify_tls=False)
    assert mgr._session_key(unverified) != mgr._session_key(https)


def test_rsync_keep_metadata_is_a_field(dialog):
    pick, _ = dialog
    dlg = pick("rsync")
    assert dlg._rsync_preserve.isVisible() and not dlg._rsync_preserve.isChecked()
    dlg._host.setText("h")
    dlg._rsync_preserve.setChecked(True)
    assert dlg._build_profile().rsync_preserve_metadata is True
    dlg._load_profile(ConnectionProfile(name="r", protocol="rsync", host="h", port=873))
    assert not dlg._rsync_preserve.isChecked()


@pytest.mark.parametrize(
    "proto", ["winrm", "wmi", "tftp"])
def test_ip_version_is_hidden_where_the_backend_ignores_it(dialog, proto):
    pick, _ = dialog
    dlg = pick(proto)
    assert not dlg._addr_family.isVisible()
    assert dlg._build_profile().address_family == "auto"


@pytest.mark.parametrize(
    "proto", ["sftp", "scp", "ftp", "ftps", "rsync", "telnet", "cisco-telnet", "rsh"])
def test_ip_version_is_shown_where_the_backend_takes_it(dialog, proto):
    pick, _ = dialog
    dlg = pick(proto)
    assert dlg._addr_family.isVisible()


def test_wmi_shows_no_port_but_a_password(dialog):
    pick, warnings = dialog
    dlg = pick("wmi")
    assert not dlg._port.isVisible()
    assert dlg._simple_password.isVisible()
    dlg._host.setText("win")
    dlg._username.setText("CORP\\alice")
    assert dlg._validate(), warnings
