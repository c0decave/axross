"""MTP: the session reaches the device's mount folder and nothing else.

MtpSession is LocalFS over the FUSE mount; its docstring promised
"LocalFS rooted at the tempdir", but LocalFS has no root. The review of
2026-10-17 (B14) listed /etc and read /etc/hostname through an MTP
session. Every path is now checked against the mount folder (after
resolving '..' and symlinks); outside is PermissionError, and exists /
is_dir answer False.
"""

from __future__ import annotations

import os
import threading

import pytest

from core.mtp_client import MtpSession


@pytest.fixture
def mtp(tmp_path):
    mount = tmp_path / "mount"
    mount.mkdir()
    (mount / "DCIM").mkdir()
    (mount / "DCIM" / "a.jpg").write_bytes(b"jpg")
    outside = tmp_path / "outside.txt"
    outside.write_text("host secret")
    s = MtpSession.__new__(MtpSession)
    s._mount_dir = str(mount)
    s._mounted = False
    s._close_lock = threading.Lock()
    s._device_label, s._device_id, s._mounter = "Pixel", "1", "jmtpfs"
    return s, mount, outside


def test_happy_the_device_is_read_and_written(mtp):
    s, mount, _ = mtp
    assert [i.name for i in s.list_dir(s.home())] == ["DCIM"]
    assert s.open_read(str(mount / "DCIM" / "a.jpg")).read() == b"jpg"
    with s.open_write(str(mount / "DCIM" / "b.jpg")) as handle:
        handle.write(b"new")
    s.copy(str(mount / "DCIM" / "b.jpg"), str(mount / "c.jpg"))
    s.rename(str(mount / "c.jpg"), str(mount / "d.jpg"))
    assert s.exists(str(mount / "d.jpg")) and s.is_dir(str(mount / "DCIM"))


def test_sad_a_host_path_is_refused(mtp):
    s, mount, outside = mtp
    for call in (
        lambda: s.list_dir("/etc"),
        lambda: s.open_read(str(outside)),
        lambda: s.stat(str(outside)),
        lambda: s.open_write(str(outside.parent / "new.txt")),
        lambda: s.remove(str(outside)),
    ):
        with pytest.raises(PermissionError):
            call()
    assert not s.exists(str(outside)) and not s.is_dir("/etc")
    assert outside.read_text() == "host secret"


def test_sad_moving_or_copying_out_of_the_device_is_refused(mtp):
    s, mount, outside = mtp
    with pytest.raises(PermissionError):
        s.copy(str(mount / "DCIM" / "a.jpg"), str(outside.parent / "x.jpg"))
    with pytest.raises(PermissionError):
        s.rename(str(mount / "DCIM" / "a.jpg"), str(outside.parent / "x.jpg"))
    with pytest.raises(PermissionError):
        s.copy(str(outside), str(mount / "in.txt"))
    assert (mount / "DCIM" / "a.jpg").exists() and not (mount / "in.txt").exists()


def test_edge_dotdot_and_a_symlink_out_are_refused(mtp):
    s, mount, outside = mtp
    with pytest.raises(PermissionError):
        s.open_read(str(mount / "DCIM" / ".." / ".." / "outside.txt"))
    os.symlink(str(outside), str(mount / "link.txt"))
    with pytest.raises(PermissionError):
        s.open_read(str(mount / "link.txt"))
    with pytest.raises(OSError):
        s.symlink(str(outside), str(mount / "another.txt"))
    assert s.parent(s.home()) and s.home() == str(mount)
