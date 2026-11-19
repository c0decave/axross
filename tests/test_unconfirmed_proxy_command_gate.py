"""An imported ProxyCommand that nobody confirmed runs nowhere.

Protocol review (round 1): the gate sat in ConnectionManager only. The
connection dialog's *Deploy SSH Key* builds its own SSHSession and
connected through an imported, unconfirmed ``ProxyCommand`` (someone
else's shell command) without the question Connect asks. The SFTP and
SCP sessions refuse it themselves now, and Deploy SSH Key asks first.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest import mock

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.profiles import ConnectionProfile  # noqa: E402


def _profile(marker: Path, protocol: str = "sftp", confirmed: bool = False) -> ConnectionProfile:
    return ConnectionProfile(
        name="imported", protocol=protocol, host="127.0.0.1", port=1, username="u",
        proxy_command=f"touch {marker}", proxy_command_confirmed=confirmed,
    )


@pytest.mark.parametrize("protocol", ["sftp", "scp"])
def test_sad_session_refuses_an_unconfirmed_proxy_command(tmp_path, protocol):
    from core.scp_client import SCPSession
    from core.ssh_client import SSHSession

    marker = tmp_path / "ran"
    cls = SSHSession if protocol == "sftp" else SCPSession
    session = cls(_profile(marker, protocol))
    with pytest.raises(PermissionError, match="ProxyCommand"):
        session.connect(password="pw")
    assert not marker.exists()


def test_happy_a_confirmed_proxy_command_is_run(tmp_path):
    from core.ssh_client import SSHSession

    marker = tmp_path / "ran"
    session = SSHSession(_profile(marker, confirmed=True))
    session._known_hosts_path = tmp_path / "known_hosts"
    with pytest.raises(Exception):  # touch is no SSH server
        session.connect(password="pw")
    assert marker.exists()


def test_sad_deploy_key_asks_before_running_it(tmp_path, monkeypatch):
    from PyQt6.QtWidgets import QApplication, QMessageBox

    from core.profiles import ProfileManager
    from ui import connection_dialog as cd

    _app = QApplication.instance() or QApplication([])  # noqa: F841
    monkeypatch.setattr("core.profiles.PROFILES_FILE", tmp_path / "profiles.json")
    ssh_dir = tmp_path / "home" / ".ssh"
    ssh_dir.mkdir(parents=True)
    (ssh_dir / "id_test.pub").write_text("ssh-ed25519 AAAA test\n")
    monkeypatch.setattr(cd.Path, "home", staticmethod(lambda: tmp_path / "home"))
    marker = tmp_path / "ran"
    dialog = cd.ConnectionDialog(ProfileManager())
    try:
        monkeypatch.setattr(dialog, "_validate", lambda: True)
        monkeypatch.setattr(dialog, "_build_profile", lambda: _profile(marker))
        from PyQt6.QtWidgets import QInputDialog

        monkeypatch.setattr(QInputDialog, "getItem",
                            staticmethod(lambda *a, **k: ("id_test.pub", True)))
        asked = []

        def question(*args, **kwargs):
            asked.append(args)
            return QMessageBox.StandardButton.No

        with mock.patch.object(cd.QMessageBox, "question", side_effect=question), \
                mock.patch.object(cd.QMessageBox, "critical"), \
                mock.patch.object(cd.QMessageBox, "information"):
            dialog._deploy_ssh_key()
        assert asked, "Deploy SSH Key ran an unconfirmed ProxyCommand without asking"
        assert not marker.exists()
    finally:
        dialog.deleteLater()


def test_sad_dialog_import_keeps_the_proxy_command(tmp_path, monkeypatch):
    """The dialog's SSH-config import filled the ProxyCommand field but left
    *Use:* at the default proxy: the profile it saved had no ProxyCommand
    and connected past the jump host (directly or via the default proxy)."""
    from PyQt6.QtWidgets import QApplication

    from core.profiles import ProfileManager
    from core.ssh_config import SSHHostConfig
    from ui.connection_dialog import ConnectionDialog

    _app = QApplication.instance() or QApplication([])  # noqa: F841
    monkeypatch.setattr("core.profiles.PROFILES_FILE", tmp_path / "profiles.json")
    dialog = ConnectionDialog(ProfileManager())
    try:
        dialog._apply_ssh_host_config(SSHHostConfig(
            alias="inner", hostname="10.0.0.5", proxy_command="ssh -W %h:%p bastion"))
        profile = dialog._build_profile()
        assert profile.proxy_command == "ssh -W %h:%p bastion"
        assert profile.proxy_mode == "custom"
        assert profile.proxy_command_confirmed is False
    finally:
        dialog.deleteLater()
