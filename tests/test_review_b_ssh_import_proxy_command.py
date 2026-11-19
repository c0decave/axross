"""Review B, item 7: a ProxyCommand from an imported SSH config ran on
Connect without a question.

The import (File → Import SSH Config, a file, a pasted config) built the
profile with ``proxy_command_confirmed`` at its default True; a config
"from the team" with ``ProxyCommand sh -c 'id > /tmp/x; nc %h %p'`` ran
at the first Connect. Now an imported ProxyCommand is unconfirmed: the
Connect asks first (core.connection_manager refuses it until then).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.profiles import ProfileManager  # noqa: E402
from core.ssh_config import parse_ssh_config  # noqa: E402

EVIL = """# "our bastion settings, import me"
Host build-box
    HostName 10.0.0.5
    User deploy
    ProxyCommand sh -c 'id > /tmp/axross_pwned; nc %h %p'

Host plain
    HostName 10.0.0.6
"""


@pytest.fixture
def manager(tmp_path, monkeypatch):
    monkeypatch.setattr("core.profiles.PROFILES_FILE", tmp_path / "profiles.json")
    return ProfileManager()


def test_sad_an_imported_proxy_command_is_not_confirmed(tmp_path, manager):
    from ui import main_window

    config = tmp_path / "config"
    config.write_text(EVIL)
    hosts = parse_ssh_config(config)
    with mock.patch.object(main_window, "QMessageBox"):
        main_window.MainWindow._import_ssh_hosts(SimpleNamespace(_profile_manager=manager),
                                                 hosts, str(config))
    evil = manager.get("build-box")
    assert evil.proxy_command and evil.proxy_command_confirmed is False
    # kept so across a restart
    again = ProfileManager().get("build-box")
    assert again.proxy_command_confirmed is False
    assert manager.get("plain").proxy_command_confirmed is True


def test_sad_the_connection_dialogs_import_leaves_it_unconfirmed(tmp_path, manager):
    from PyQt6.QtWidgets import QApplication

    from ui.connection_dialog import ConnectionDialog

    _app = QApplication.instance() or QApplication([])  # noqa: F841
    config = tmp_path / "config"
    config.write_text(EVIL)
    host = parse_ssh_config(config)[0]
    dialog = ConnectionDialog(manager)
    try:
        dialog._apply_ssh_host_config(host)
        dialog._proxy_mode.setCurrentIndex(1)  # the user picks "custom": the command is used
        profile = dialog._build_profile()
        assert profile.proxy_command and profile.proxy_command_confirmed is False
        # what the user types in themselves is theirs
        dialog._proxy_command.setText("ssh -W %h:%p my-jump")
        assert dialog._build_profile().proxy_command_confirmed is True
    finally:
        dialog.deleteLater()
