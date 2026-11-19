"""Connection Manager rows for SMB / DFS-N, NFS, iSCSI, MTP and Azure: what
the dialog shows is what the backend uses, and every profile field the
backend reads has a row.

Found in the connection review (2026-11):

* "IP Version" was shown for SMB, DFS-N, NFS, iSCSI and MTP, whose
  backends never read it (only SSH / SCP do): "IPv6 only" changed nothing.
* Azure showed two "Account:" rows - the Username row relabelled and the
  Account row - and only the second one counted for "Either Connection
  String or Account Name is required".
* MTP asked for a Host (only the device's label) and had no row for the
  device or the mounter the backend reads: every MTP profile mounted
  device "1" with the first mounter found.
* SMB's NTLM workstation name (smb_client_name) had no row, and DFS-N
  ignored it (always "WORKSTATION").
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
        mock.patch.object(QMessageBox, "warning",
                          side_effect=lambda *a, **k: warnings.append(a[2])),
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

        yield pick, warnings, dlg
        dlg.close()


@pytest.mark.parametrize("proto", ["smb", "dfsn", "nfs", "iscsi", "mtp"])
def test_sad_no_ip_version_row_where_the_backend_ignores_it(dialog, proto):
    pick, _warnings, dlg = dialog
    pick(proto)
    assert not dlg._addr_family.isVisible()


def test_happy_sftp_keeps_its_ip_version_row(dialog):
    pick, _warnings, dlg = dialog
    pick("sftp")
    assert dlg._addr_family.isVisible()


@pytest.mark.parametrize("proto", ["azure_blob", "azure_files"])
def test_sad_azure_shows_one_account_row(dialog, proto):
    pick, _warnings, dlg = dialog
    pick(proto)
    assert dlg._azure_account_name.isVisible()
    assert not dlg._username.isVisible()


def test_happy_an_old_azure_profile_with_the_account_as_username_loads_it(dialog):
    pick, _warnings, dlg = dialog
    pick("azure_blob")
    dlg._load_profile(ConnectionProfile(name="old", protocol="azure_blob", username="acct",
                                        azure_container="box"))
    assert dlg._azure_account_name.text() == "acct"


def test_sad_mtp_asks_for_the_device_not_a_host(dialog):
    pick, warnings, dlg = dialog
    pick("mtp")
    assert not dlg._host.isVisible() and not dlg._port.isVisible()
    assert dlg._mtp_device_id.isVisible() and dlg._mtp_mounter.isVisible()
    dlg._mtp_device_id.setText("2")
    dlg._mtp_mounter.setCurrentIndex(dlg._mtp_mounter.findData("simple-mtpfs"))
    assert dlg._validate(), warnings
    profile = dlg._build_profile()
    assert (profile.mtp_device_id, profile.mtp_mounter) == ("2", "simple-mtpfs")
    dlg._clear_fields()
    dlg._load_profile(profile)
    assert dlg._mtp_device_id.text() == "2"
    assert dlg._mtp_mounter.currentData() == "simple-mtpfs"


def test_sad_an_mtp_device_id_with_odd_characters_is_refused(dialog):
    pick, warnings, dlg = dialog
    pick("mtp")
    dlg._mtp_device_id.setText("1; rm -rf")
    assert not dlg._validate()
    assert "device" in warnings[-1].lower()


@pytest.mark.parametrize("proto", ["smb", "dfsn"])
def test_sad_the_smb_workstation_name_has_a_row(dialog, proto):
    pick, _warnings, dlg = dialog
    pick(proto)
    assert dlg._smb_client_name.isVisible()
    dlg._host.setText("fs1")
    dlg._smb_share.setText("data")
    dlg._smb_client_name.setText("LAPTOP7")
    assert dlg._build_profile().smb_client_name == "LAPTOP7"


def test_happy_dfsn_gets_a_name_of_its_own(dialog):
    """A DFS-N profile saved without a name was named "@corp.local"."""
    pick, _warnings, dlg = dialog
    pick("dfsn")
    dlg._profile_name.clear()
    dlg._host.setText("corp.local")
    dlg._smb_share.setText("dfs")
    assert dlg._build_profile().name == "\\\\corp.local\\dfs"


def test_sad_dfsn_sends_the_profile_s_workstation_name(monkeypatch):
    from core import connection_manager as cm

    seen = {}

    class _Dfs:
        def __init__(self, **kwargs):
            seen.update(kwargs)

    monkeypatch.setattr(cm, "load_backend_class", lambda proto: _Dfs)
    monkeypatch.setattr(cm, "_proxy_kwargs", lambda profile: {})
    profile = ConnectionProfile(name="d", protocol="dfsn", host="corp.local", port=445,
                                smb_share="dfs", smb_client_name="LAPTOP7")
    cm.ConnectionManager()._create_session(profile, "", "", None)
    assert seen["client_name"] == "LAPTOP7"


def test_happy_the_mtp_label_is_the_profile_name_without_a_host(monkeypatch):
    from core import connection_manager as cm

    seen = {}

    class _Mtp:
        def __init__(self, device, **kwargs):
            seen["device"] = device

    monkeypatch.setattr(cm, "load_backend_class", lambda proto: _Mtp)
    profile = ConnectionProfile(name="Pixel 9", protocol="mtp", mtp_device_id="2")
    cm.ConnectionManager()._create_session(profile, "", "", None)
    assert seen["device"].product == "Pixel 9" and seen["device"].device_id == "2"
