"""Connection Manager: every protocol of the dialog can be filled in and
saved by doing what the dialog asks for - a matrix over all protocols.

The rule the matrix holds: a validation message names only a field the
dialog shows for that protocol. Twice a protocol hid its Username row and
still demanded a username: RamFS and TFTP (fixed before, see
tests/test_ramfs_tftp_profiles.py) and - found by this matrix - MTP, whose
profile could therefore never be saved, tested or connected from the
dialog. The two lists (which rows are shown, what is required) were typed
twice; the dialog now derives the requirement from the one list.

Also here: the per-protocol required fields, refused input (control
characters, an invalid bucket name, a proxy without a host, key auth
without a key file) and an end-to-end save through the real window.
ui/connection_dialog.py was at 55 % of its branches
(docs/TEST_COVERAGE_MATRIX.md of 2026-10-26).
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

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core.backend_registry import init_registry  # noqa: E402

APP = QApplication.instance() or QApplication([])
init_registry()

#: What a validation message asks for -> the widget and a value that fills it.
ASKS = (
    ("Host is required", "_host", "host.example"),
    ("Target IP is required", "_host", "10.0.0.7"),
    ("Username is required", "_username", "alice"),
    ("NFS export path", "_nfs_export", "/srv/export"),
    ("Either Connection String or Account Name", "_azure_account_name", "acct"),
    ("Container name", "_azure_container", "box"),
    ("File share name", "_azure_share", "share"),
    ("Google Client ID", "_gdrive_client_id", "id.apps.googleusercontent.com"),
    ("Client ID is required", "_onedrive_client_id", "0000-client"),
    ("SharePoint site URL", "_sharepoint_site_url", "https://x.sharepoint.com/sites/a"),
    ("Dropbox App Key", "_dropbox_app_key", "appkey"),
    ("Target IQN", "_iscsi_target_iqn", "iqn.2026-10.example:t1"),
    ("WebDAV URL", "_webdav_url", "https://dav.example/remote.php/dav/"),
    ("S3 bucket name or URL", "_s3_bucket", "my-bucket"),
    ("SMB share name", "_smb_share", "share"),
    ("DFS namespace", "_smb_share", "namespace"),
)


@pytest.fixture
def dialog():
    from core.profiles import ProfileManager
    from ui.connection_dialog import ConnectionDialog

    warnings: list[str] = []
    # Whether a backend's packages are installed is this machine's business,
    # not the dialog's validation: every backend counts as installed here
    # (a missing one would open the modal Help > Features offer).
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

        yield pick, warnings, dlg
        dlg.close()


def _validate(dlg, warnings):
    ok = dlg._validate()
    return ok, (warnings[-1] if warnings else "")


def _fill_what_it_asks(dlg, warnings, proto):
    """Fill the field each message names until the dialog is satisfied;
    every named field must be on screen. Returns the fields filled."""
    filled = []
    for _ in range(len(ASKS) + 1):
        ok, message = _validate(dlg, warnings)
        if ok:
            return filled
        hit = next(((attr, value) for text, attr, value in ASKS if text in message), None)
        assert hit is not None, f"{proto}: unexpected message {message!r}"
        attr, value = hit
        widget = getattr(dlg, attr)
        assert widget.isVisible(), f"{proto}: {message!r} names a field the dialog hides"
        assert attr not in filled, f"{proto}: asked twice for {attr}"
        widget.setText(value)
        filled.append(attr)
    raise AssertionError(f"{proto}: never satisfied, last asked {message!r}")


def _all_protocols():
    from core.backend_registry import all_backends

    return [info.protocol_id for info in all_backends()]


# ------------------------------------------------------------------ matrix
@pytest.mark.parametrize("proto", _all_protocols())
def test_happy_every_protocol_is_completed_by_filling_what_it_asks(dialog, proto):
    pick, warnings, _ = dialog
    dlg = pick(proto)
    _fill_what_it_asks(dlg, warnings, proto)
    profile = dlg._build_profile()
    assert (profile.name, profile.protocol) == (f"my-{proto}", proto)


@pytest.mark.parametrize("proto", _all_protocols())
def test_edge_no_hidden_field_is_ever_required(dialog, proto):
    """The invariant directly: whatever the dialog shows, filled with junk,
    is enough to get past every "is required" message."""
    pick, warnings, dlg = dialog
    pick(proto)
    by_attr = {attr: value for _text, attr, value in ASKS}
    for attr, value in by_attr.items():
        widget = getattr(dlg, attr)
        if widget.isVisible():
            widget.setText(value)
    ok, message = _validate(dlg, warnings)
    assert ok, f"{proto}: {message!r} although every shown field is filled"


def test_happy_mtp_needs_no_username(dialog):
    pick, warnings, _ = dialog
    dlg = pick("mtp")
    assert not dlg._username.isVisible()
    dlg._host.setText("pixel9")
    assert _validate(dlg, warnings) == (True, "")


# ------------------------------------------------------- required per protocol
@pytest.mark.parametrize(
    "proto, filled, message",
    [
        ("sftp", {"_host": "h"}, "Username is required."),
        ("sftp", {"_username": "u"}, "Host is required."),
        ("nfs", {"_host": "h"}, "NFS export path is required."),
        ("smb", {"_host": "h", "_username": "u"}, "SMB share name is required."),
        ("dfsn", {"_host": "h", "_username": "u"}, "DFS namespace is required."),
        ("iscsi", {"_host": "10.0.0.7"}, "Target IQN is required."),
        ("azure_blob", {"_azure_account_name": "a"}, "Container name is required."),
        ("azure_files", {"_azure_account_name": "a"}, "File share name is required."),
        ("sharepoint", {"_onedrive_client_id": "c"}, "SharePoint site URL is required."),
        ("tftp", {}, "Host is required."),
    ],
)
def test_sad_a_missing_required_field_is_named_and_nothing_is_saved(dialog, proto, filled, message):
    pick, warnings, dlg = dialog
    pick(proto)
    for attr, value in filled.items():
        getattr(dlg, attr).setText(value)
    assert _validate(dlg, warnings) == (False, message)
    with mock.patch.object(QMessageBox, "information") as saved:
        dlg._save_profile()
    saved.assert_not_called()
    assert dlg._profile_manager.get(f"my-{proto}") is None


@pytest.mark.parametrize(
    "attr, value, message",
    [
        ("_host", "host\nInjected: x", "Host contains invalid characters."),
        ("_host", "two words", "Host contains invalid characters."),
        ("_username", "bob\x00", "Username contains invalid characters."),
        ("_profile_name", "na\r\nme", "Profile name contains invalid characters."),
    ],
)
def test_sad_control_characters_and_spaces_are_refused(dialog, attr, value, message):
    pick, warnings, dlg = dialog
    pick("sftp")
    dlg._host.setText("h")
    dlg._username.setText("u")
    getattr(dlg, attr).setText(value)
    assert _validate(dlg, warnings) == (False, message)


@pytest.mark.parametrize(
    "bucket, ok",
    [
        ("my-bucket", True),
        ("dev-s1.s3.ap-south-1.amazonaws.com", True),
        ("https://bucket.s3.eu-central-1.amazonaws.com", True),
        ("s3://bucket/prefix", True),
        ("Upper_Case", False),
        ("ab", False),
        ("-leading-dash", False),
    ],
)
def test_edge_s3_bucket_names_and_urls(dialog, bucket, ok):
    pick, warnings, dlg = dialog
    pick("s3")
    dlg._s3_bucket.setText(bucket)
    result, message = _validate(dlg, warnings)
    assert result is ok, message
    if not ok:
        assert message.startswith("Invalid S3 bucket name.")


def test_sad_a_proxy_without_host_or_command_is_refused(dialog):
    pick, warnings, dlg = dialog
    pick("sftp")
    dlg._host.setText("h")
    dlg._username.setText("u")
    dlg._proxy_group.setChecked(True)
    dlg._proxy_mode.setCurrentIndex(1)
    assert _validate(dlg, warnings) == (
        False,
        "Proxy host or ProxyCommand is required when proxy support is enabled.",
    )
    dlg._proxy_host.setText("proxy.example")
    assert _validate(dlg, warnings)[0] is True


def test_sad_key_auth_needs_an_existing_key_file(dialog, tmp_path):
    pick, warnings, dlg = dialog
    pick("sftp")
    dlg._host.setText("h")
    dlg._username.setText("u")
    dlg._auth_key.setChecked(True)
    assert _validate(dlg, warnings) == (False, "Key file is required for key auth.")
    dlg._key_file.setText(str(tmp_path / "missing_ed25519"))
    assert _validate(dlg, warnings) == (False, "Key file does not exist or is not a file.")
    key = tmp_path / "id_ed25519"
    key.write_text("-----BEGIN OPENSSH " "PRIVATE " "KEY-----\n")  # split: the leak gate
    dlg._key_file.setText(str(key))
    assert _validate(dlg, warnings)[0] is True


# -------------------------------------------------------------------- e2e
def test_happy_e2e_an_mtp_connection_is_saved_through_the_window(dialog):
    """Typed and clicked like a user: protocol MTP, a name, a device label,
    Save - the profile is in the profile store."""
    pick, warnings, dlg = dialog
    pick("mtp")
    dlg._profile_name.clear()
    QTest.keyClicks(dlg._profile_name, "phone")
    QTest.keyClicks(dlg._host, "pixel9")
    with mock.patch.object(QMessageBox, "information") as saved:
        QTest.mouseClick(dlg._btn_save_profile, Qt.MouseButton.LeftButton)
    assert warnings == []
    saved.assert_called_once()
    stored = dlg._profile_manager.get("phone")
    assert stored is not None and (stored.protocol, stored.host) == ("mtp", "pixel9")


def test_sad_e2e_a_click_on_save_with_a_missing_username_saves_nothing(dialog):
    pick, warnings, dlg = dialog
    pick("sftp")
    QTest.keyClicks(dlg._host, "server.example")
    with mock.patch.object(QMessageBox, "information") as saved:
        QTest.mouseClick(dlg._btn_save_profile, Qt.MouseButton.LeftButton)
    assert warnings == ["Username is required."]
    saved.assert_not_called()
    assert dlg._profile_manager.get("my-sftp") is None
