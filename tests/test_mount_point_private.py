"""NFS / iSCSI mount points live in a folder only their user can enter.

Both backends mounted (as root, via sudo) on
``tempfile.mkdtemp(prefix="axross-nfs-")`` / ``"axross-iscsi-"`` directly
in /tmp. mkdtemp's 0700 only holds until the mount: from then on the
mounted file system's root mode (typically 0755) guards the path, so
every local user could browse the export through /tmp. The mount point
is now a folder inside a fresh 0700 folder.
"""

from __future__ import annotations

import os
import stat
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import iscsi_client as IC  # noqa: E402
from core import nfs_client as NC  # noqa: E402


class _Recorder:
    def __init__(self):
        self.calls = []

    def __call__(self, cmd, *_a, **_kw):
        self.calls.append(cmd)

        class _Done:
            returncode = 0
            stdout = ""
            stderr = ""

        return _Done()


def _nfs(monkeypatch, **kw):
    rec = _Recorder()
    monkeypatch.setattr(NC.NfsSession, "_run", lambda self, cmd, check=True: rec(cmd))
    return NC.NfsSession("nfs.example", "/export", **kw), rec


def _iscsi(monkeypatch, **kw):
    monkeypatch.setattr(IC.IscsiSession, "connect", lambda self: None)
    return IC.IscsiSession("10.0.0.9", "iqn.2020-01.example:t", **kw)


def _assert_private(mount_point: str) -> None:
    parent = os.path.dirname(mount_point)
    info = os.stat(parent)
    assert stat.S_IMODE(info.st_mode) == 0o700
    assert info.st_uid == os.getuid()
    # Not a world-enterable folder such as /tmp itself.
    assert os.path.realpath(parent) != os.path.realpath(tempfile.gettempdir())


@pytest.mark.parametrize("make", [_nfs, _iscsi], ids=["nfs", "iscsi"])
def test_happy_own_mount_point_sits_in_a_private_folder_and_is_removed(monkeypatch, make):
    made = make(monkeypatch)
    session = made[0] if isinstance(made, tuple) else made
    mount_point = session._mount_point
    _assert_private(mount_point)
    parent = os.path.dirname(mount_point)
    session._mounted = False
    session.disconnect()
    assert not os.path.exists(mount_point)
    assert not os.path.exists(parent)


@pytest.mark.parametrize("make", [_nfs, _iscsi], ids=["nfs", "iscsi"])
def test_sad_a_given_mount_point_is_used_as_is_and_kept(monkeypatch, tmp_path, make):
    target = tmp_path / "mine"
    target.mkdir()
    made = make(monkeypatch, mount_point=str(target))
    session = made[0] if isinstance(made, tuple) else made
    assert session._mount_point == str(target)
    session._mounted = False
    session.disconnect()
    assert target.is_dir()


@pytest.mark.parametrize("make", [_nfs, _iscsi], ids=["nfs", "iscsi"])
def test_edge_a_mount_still_in_place_is_never_removed(monkeypatch, make):
    made = make(monkeypatch)
    session = made[0] if isinstance(made, tuple) else made
    mount_point = session._mount_point
    # Stands in for an unmount that failed: the export is still there.
    Path(mount_point, "server-file").write_text("data")
    session._mounted = False
    session.disconnect()
    assert Path(mount_point, "server-file").read_text() == "data"
    os.unlink(os.path.join(mount_point, "server-file"))
    os.rmdir(mount_point)
    os.rmdir(os.path.dirname(mount_point))
