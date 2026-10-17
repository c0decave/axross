"""RAM-workspace and TFTP profiles can be created, and RAM workspaces stay apart.

Before:
* The connection dialog hides the Username row for RamFS and TFTP (and
  showed a Host row for RamFS, which has no host), but their validation
  fell into the generic branch that demands host and username: such a
  profile could not be saved or tested at all.
* The session key had no profile name, and a RamFS profile carries no other
  discriminator: two RAM workspaces were one shared session - files put in
  one showed up in the other, and closing either pane emptied both.

Now the dialog requires exactly what each of those protocols uses (RamFS:
nothing but a name; TFTP: a host), and a RamFS session is keyed by its
profile name.
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
from core.connection_manager import ConnectionManager  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402

APP = QApplication.instance() or QApplication([])
init_registry()


@pytest.fixture
def dialog():
    from core.profiles import ProfileManager
    from ui.connection_dialog import ConnectionDialog

    warnings: list[str] = []
    warn = mock.patch.object(
        QMessageBox, "warning", side_effect=lambda *a, **k: warnings.append(a[2])
    )
    with warn:
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


def test_happy_a_ramfs_profile_needs_only_a_name(dialog):
    pick, warnings = dialog
    dlg = pick("ramfs")
    assert not dlg._host.isVisible()
    assert not dlg._username.isVisible()
    assert dlg._validate() is True, warnings


def test_happy_a_tftp_profile_needs_a_host_but_no_username(dialog):
    pick, warnings = dialog
    dlg = pick("tftp")
    dlg._host.setText("10.0.0.5")
    assert not dlg._username.isVisible()
    assert dlg._validate() is True, warnings


def test_sad_a_tftp_profile_without_a_host_is_refused(dialog):
    pick, warnings = dialog
    dlg = pick("tftp")
    assert dlg._validate() is False
    assert warnings == ["Host is required."]


def test_edge_sftp_still_requires_a_username(dialog):
    pick, warnings = dialog
    dlg = pick("sftp")
    dlg._host.setText("h.example")
    assert dlg._validate() is False
    assert warnings == ["Username is required."]


def test_happy_two_ram_workspaces_are_two_sessions():
    cm = ConnectionManager()
    a = ConnectionProfile(name="ram-staging", protocol="ramfs", host="", port=0)
    b = ConnectionProfile(name="ram-scratch", protocol="ramfs", host="", port=0)
    sa = cm.connect(a)
    with sa.open_write("/staging-only.txt") as fh:
        fh.write(b"x")
    sb = cm.connect(b)
    try:
        assert sa is not sb
        assert [i.name for i in sb.list_dir("/")] == []
        cm.release(a)
        assert [i.name for i in sb.list_dir("/")] == []
    finally:
        cm.disconnect_all()


def test_edge_the_same_ram_workspace_twice_is_one_session():
    cm = ConnectionManager()
    a = ConnectionProfile(name="ram-staging", protocol="ramfs", host="", port=0)
    try:
        again = ConnectionProfile(name="ram-staging", protocol="ramfs", host="", port=0)
        assert cm.connect(a) is cm.connect(again)
    finally:
        cm.disconnect_all()


def test_edge_network_profiles_to_one_server_still_share_a_key():
    cm = ConnectionManager()
    a = ConnectionProfile(name="one", protocol="sftp", host="h", username="u")
    b = ConnectionProfile(name="two", protocol="sftp", host="h", username="u")
    assert cm._session_key(a) == cm._session_key(b)
