"""A dropped NFS (own client), MTP or iSCSI connection is noticed.

core.connection_manager reuses a session while ``session.connected`` is
true, and conn_health shows it as up. Measured before the fix:

* NfsUserSession.connected was ``self._nfs is not None``: a server that
  went away stayed "connected" for ever;
* MtpSession had no ``connected`` at all (LocalFS): an unplugged phone,
  whose FUSE mount answers ENOTCONN, was reused as it was;
* IscsiSession.connected read its own flags only: a target that dropped
  the session (sysfs state FAILED) or a file system unmounted under it
  stayed "connected".
"""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fake_nfsd import FakeNfsd  # noqa: E402

from core import iscsi_client  # noqa: E402
from core.connection_manager import ConnectionManager  # noqa: E402
from core.iscsi_client import IscsiSession  # noqa: E402
from core.mtp_client import MtpSession  # noqa: E402
from core.nfs_user_client import NfsUserSession  # noqa: E402


# --- NFS, axross's own client ---------------------------------------------------


@pytest.fixture
def nfsd(tmp_path):
    root = tmp_path / "export"
    root.mkdir()
    (root / "a.txt").write_bytes(b"alpha")
    server = FakeNfsd(str(root))
    yield server
    server.close()


def _nfs(server) -> NfsUserSession:
    return NfsUserSession("127.0.0.1", "/export", port=server.port, mount_port=server.port,
                          uid=1000, gid=1000, machine_name="test", timeout=5.0)


def test_happy_a_live_nfs_server_is_connected(nfsd):
    session = _nfs(nfsd)
    try:
        assert session.connected
        assert [i.name for i in session.list_dir("/")] == ["a.txt"]
    finally:
        session.close()


def test_sad_an_nfs_server_that_went_away_is_not_connected(nfsd):
    session = _nfs(nfsd)
    try:
        nfsd.drop()
        assert not session.connected
        assert not ConnectionManager._is_connected(session)
    finally:
        session.close()


# --- MTP ------------------------------------------------------------------------------


def _mtp(mount_dir: str, mounted: bool = True) -> MtpSession:
    session = MtpSession.__new__(MtpSession)
    session._mount_dir = mount_dir
    session._mounted = mounted
    session._close_lock = threading.Lock()
    session._device_label, session._device_id, session._mounter = "Pixel", "1", "jmtpfs"
    return session


def test_happy_a_mounted_device_is_connected(tmp_path, monkeypatch):
    monkeypatch.setattr(os.path, "ismount", lambda p: str(p) == str(tmp_path))
    assert _mtp(str(tmp_path)).connected


def test_sad_an_unplugged_device_is_not_connected(tmp_path, monkeypatch):
    # The FUSE mounter died with the device: the folder is no mount point
    # any more (or answers ENOTCONN, which os.path.ismount reads as False).
    monkeypatch.setattr(os.path, "ismount", lambda p: False)
    session = _mtp(str(tmp_path))
    assert not session.connected
    assert not ConnectionManager._is_connected(session)
    assert not _mtp(str(tmp_path), mounted=False).connected


# --- iSCSI ----------------------------------------------------------------------------

IQN = "iqn.2024-01.org.example:disk1"


def _iscsi(tmp_path, monkeypatch, *, state: str | None, mounted_in_proc: bool = True):
    sessions = tmp_path / "iscsi_session"
    sessions.mkdir()
    if state is not None:
        one = sessions / "session3"
        one.mkdir()
        (one / "targetname").write_text(IQN + "\n")
        (one / "state").write_text(state + "\n")
    other = sessions / "session1"
    other.mkdir()
    (other / "targetname").write_text("iqn.2024-01.org.example:other\n")
    (other / "state").write_text("LOGGED_IN\n")
    mount_point = str(tmp_path / "mnt")
    mounts = tmp_path / "mounts"
    mounts.write_text(f"/dev/sdz1 {mount_point} ext4 rw 0 0\n" if mounted_in_proc else "")
    monkeypatch.setattr(iscsi_client, "_ISCSI_SESSIONS", str(sessions))
    monkeypatch.setattr(iscsi_client, "_PROC_MOUNTS", str(mounts))
    session = IscsiSession.__new__(IscsiSession)
    session._target_iqn = IQN
    session._logged_in = True
    session._auto_mount = True
    session._mounted = True
    session._mount_point = mount_point
    return session


def test_happy_a_logged_in_mounted_target_is_connected(tmp_path, monkeypatch):
    assert _iscsi(tmp_path, monkeypatch, state="LOGGED_IN").connected


@pytest.mark.parametrize("state", ["FAILED", "FREE", None])
def test_sad_a_dropped_iscsi_session_is_not_connected(tmp_path, monkeypatch, state):
    session = _iscsi(tmp_path, monkeypatch, state=state)
    assert not session.connected
    assert not ConnectionManager._is_connected(session)


def test_sad_a_file_system_unmounted_under_the_session_is_not_connected(tmp_path, monkeypatch):
    assert not _iscsi(tmp_path, monkeypatch, state="LOGGED_IN", mounted_in_proc=False).connected


def test_happy_without_sysfs_the_flags_decide(tmp_path, monkeypatch):
    session = _iscsi(tmp_path, monkeypatch, state="LOGGED_IN")
    monkeypatch.setattr(iscsi_client, "_ISCSI_SESSIONS", str(tmp_path / "no-sysfs"))
    assert session.connected


# --- NFS, the kernel mount ------------------------------------------------------------


def test_sad_a_hung_kernel_nfs_mount_is_not_connected_and_does_not_hang(tmp_path, monkeypatch):
    """A hard NFS mount whose server is gone blocks every system call on it
    (D state): ``connected`` - asked on every reuse of the session and by
    the health probe - waited for ever. It answers after the probe time."""
    import time

    from core import nfs_client

    session = nfs_client.NfsSession.__new__(nfs_client.NfsSession)
    session._mounted = True
    session._mount_point = str(tmp_path)
    session._host, session._export = "h", "/x"
    release = threading.Event()
    real_listdir = os.listdir

    def hung(path):
        if str(path) == str(tmp_path):
            release.wait(30)
        return real_listdir(path)

    monkeypatch.setattr(nfs_client, "_LIVENESS_TIMEOUT", 0.5)
    monkeypatch.setattr(os, "listdir", hung)
    started = time.monotonic()
    try:
        assert not session.connected
        assert time.monotonic() - started < 5
    finally:
        release.set()
    assert session.connected


@pytest.mark.parametrize("stderr", ["sudo: a password is required",
                                    "mount.nfs: only root can do that",
                                    "mount: only root can use \"--options\" option"])
def test_sad_a_mount_without_root_rights_says_how_to_connect(monkeypatch, stderr):
    """Not root and no password-less sudo: the error was "Failed to mount
    NFS h:/x: sudo: a password is required" - no word that the profile's
    sender fields switch to axross's own client, which needs no mount."""
    import subprocess

    from core import nfs_client
    from core.user_errors import describe

    session = nfs_client.NfsSession.__new__(nfs_client.NfsSession)
    session._mount_host, session._mount_port = "h", 2049
    session._export, session._version, session._minor = "/x", 3, 0
    session._mount_point = "/tmp/never"

    def refused(cmd, check=True):
        raise subprocess.CalledProcessError(1, cmd, output="", stderr=stderr)

    monkeypatch.setattr(session, "_run", refused)
    with pytest.raises(PermissionError) as info:
        session._connect()
    text = describe(info.value)
    assert "root" in text and "own NFS client" in text
