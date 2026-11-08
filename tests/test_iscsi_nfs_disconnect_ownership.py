"""iSCSI and NFS disconnect undo only what axross did, and only once the
file system is off.

* iSCSI: a login that iscsiadm answered with exit 15 (the session exists
  already - the system's own, with the LUN mounted at /data) was marked
  logged in like one axross made, and disconnect logged that session out
  under the system's mount. Now a reused session is left as it was, and
  the log says why.
* iSCSI: a failed umount (busy) still marked the session unmounted, and
  disconnect logged out with the file system still mounted on the
  device. Now it stays logged in and mounted, and says so.
* NFS (kernel mount): umount runs with check=False, so its exit status was
  never read - a busy mount was marked unmounted. Now a failed umount
  keeps it marked mounted (and its mount point).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import nfs_client as NC  # noqa: E402
from core.iscsi_client import IscsiSession  # noqa: E402


def _iscsi(tmp_path, *, login_rc: int = 0, umount_rc: int = 0):
    calls: list[str] = []

    def run(cmd, *, check=True, capture=True, timeout=0):
        calls.append(" ".join(cmd))
        if "--login" in cmd and login_rc:
            raise subprocess.CalledProcessError(login_rc, cmd)
        if cmd[0] == "umount" and umount_rc:
            raise subprocess.CalledProcessError(umount_rc, cmd, stderr="target is busy")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    s = IscsiSession.__new__(IscsiSession)
    s.__dict__.update(_iface="", _iface_created=False, _tunnel=None, _proxied=False,
                      _portal_ip="10.0.0.5", _portal_port=3260, _target_iqn="iqn.x:lun",
                      _auto_mount=True, _device_path="/dev/sdb", _mounted=False,
                      _logged_in=False, _own_login=False, _tmp_dir_created=False,
                      _mount_point=str(tmp_path / "mnt"))
    s._run_privileged = run
    s._detect_filesystem = lambda: "ext4"
    s._existing_mountpoint_for_device = lambda: ""
    return s, calls


def _logouts(calls):
    return [c for c in calls if "--logout" in c]


def test_sad_a_reused_session_is_not_logged_out(tmp_path, caplog):
    s, calls = _iscsi(tmp_path, login_rc=15)
    s._login()
    s._mount()
    with caplog.at_level("INFO", logger="core.iscsi_client"):
        s.disconnect()
    assert _logouts(calls) == []
    assert any(c.startswith("umount") for c in calls)
    assert "existed before" in caplog.text
    assert not s.connected


def test_sad_a_failed_umount_stays_logged_in(tmp_path, caplog):
    s, calls = _iscsi(tmp_path, umount_rc=32)
    s._login()
    s._mount()
    with caplog.at_level("WARNING", logger="core.iscsi_client"):
        s.disconnect()
    assert _logouts(calls) == []
    assert s._mounted and s._logged_in
    assert "still mounted" in caplog.text


def test_happy_a_session_axross_made_is_logged_out(tmp_path):
    s, calls = _iscsi(tmp_path)
    s._login()
    s._mount()
    s.disconnect()
    assert len(_logouts(calls)) == 1
    assert not s._mounted and not s._logged_in


def test_edge_a_retried_disconnect_logs_out_once_umount_works(tmp_path):
    s, calls = _iscsi(tmp_path, umount_rc=32)
    s._login()
    s._mount()
    s.disconnect()
    assert _logouts(calls) == []
    s._run_privileged = lambda cmd, **kw: (calls.append(" ".join(cmd)),
                                           subprocess.CompletedProcess(cmd, 0, "", ""))[1]
    s.disconnect()
    assert len(_logouts(calls)) == 1


def _nfs(tmp_path, umount_rc: int):
    calls: list[list[str]] = []

    def run(cmd, check=True):
        calls.append(list(cmd))
        rc = umount_rc if cmd[0] == "umount" else 0
        return subprocess.CompletedProcess(cmd, rc, "", "umount: target is busy" if rc else "")

    s = NC.NfsSession.__new__(NC.NfsSession)
    mount_point = tmp_path / "private" / "nfs"  # remove_private_mount_point takes both
    mount_point.mkdir(parents=True)
    s.__dict__.update(_mounted=True, _own_mount=True, _mount_point=str(mount_point),
                      _tunnel=None)
    s._run = run
    return s, calls, mount_point


@pytest.mark.parametrize("rc", [16, 32])
def test_sad_nfs_failed_umount_stays_mounted(tmp_path, rc):
    s, calls, mount_point = _nfs(tmp_path, umount_rc=rc)
    s.disconnect()
    assert calls == [["umount", str(mount_point)]]
    assert s._mounted
    assert mount_point.is_dir()


def test_happy_nfs_umount_marks_unmounted_and_removes_the_mount_point(tmp_path):
    s, _calls, mount_point = _nfs(tmp_path, umount_rc=0)
    s.disconnect()
    assert not s._mounted
    assert not mount_point.exists()
