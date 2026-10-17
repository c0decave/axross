"""Telnet profiles may leave the username empty.

core/telnet_client.py ``_ShellSession._login`` handles a password-only
prompt and a no-auth shell, and core/telnet_cisco.py documents "leave
username empty" for IOS line-password mode. The connection dialog still
demanded a username for both, so such a profile could not be saved or
tested. Both now need only a host.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from tests.test_ramfs_tftp_profiles import dialog  # noqa: E402,F401 - fixture


@pytest.mark.parametrize("proto", ["telnet", "cisco-telnet"])
def test_happy_telnet_profile_without_a_username_validates(dialog, proto):
    pick, warnings = dialog
    dlg = pick(proto)
    dlg._host.setText("10.0.0.5")
    assert dlg._username.isVisible()  # a username can still be given
    assert dlg._validate() is True, warnings


@pytest.mark.parametrize("proto", ["telnet", "cisco-telnet"])
def test_sad_telnet_profile_without_a_host_is_refused(dialog, proto):
    pick, warnings = dialog
    dlg = pick(proto)
    assert dlg._validate() is False
    assert warnings == ["Host is required."]


def test_edge_telnet_with_a_username_still_validates(dialog):
    pick, warnings = dialog
    dlg = pick("telnet")
    dlg._host.setText("10.0.0.5")
    dlg._username.setText("admin")
    assert dlg._validate() is True, warnings


def test_edge_sftp_still_requires_a_username(dialog):
    pick, warnings = dialog
    dlg = pick("sftp")
    dlg._host.setText("h.example")
    assert dlg._validate() is False
    assert warnings == ["Username is required."]
