"""NFS / iSCSI kernel-mount backends: symlinks, FIFOs, normalize().

Review round 3 found:

* NFS ``list_dir`` / ``stat`` never set ``is_link`` / ``link_target``
  (LocalFS and iSCSI do): an atomic save took ``link.conf`` for a regular
  file and replaced the link with a regular file of the link's mode, 0777.
* NFS and iSCSI ``open_read`` (and ``checksum``) of a FIFO without a
  writer blocked forever - and with it the transfer worker. They now
  open as LocalFS does and refuse anything but a regular file.
* NFS ``normalize("/")`` was ``"//"`` (POSIX normpath keeps a leading
  double slash), ``"/dir"`` became ``"//dir"``; it was not idempotent.
"""

from __future__ import annotations

import os
import stat
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.iscsi_client import IscsiSession  # noqa: E402
from core.nfs_client import NfsSession  # noqa: E402


def _nfs(root) -> NfsSession:
    s = NfsSession.__new__(NfsSession)
    s._mount_point = str(root)
    s._mounted = True
    s._host = "h"
    s._export = "/e"
    return s


def _iscsi(root) -> IscsiSession:
    s = IscsiSession.__new__(IscsiSession)
    s._mount_point = str(root)
    return s


def test_sad_nfs_lists_and_stats_symlinks_as_links(tmp_path) -> None:
    (tmp_path / "real.conf").write_text("old")
    os.symlink("real.conf", tmp_path / "link.conf")
    (tmp_path / "dir").mkdir()
    os.symlink("dir", tmp_path / "dirlink")
    s = _nfs(tmp_path)
    items = {i.name: i for i in s.list_dir("/")}
    assert items["link.conf"].is_link and items["link.conf"].link_target == "real.conf"
    assert items["dirlink"].is_link and items["dirlink"].link_target == "dir"
    assert not items["real.conf"].is_link and not items["dir"].is_link
    st = s.stat("/link.conf")
    assert st.is_link and st.link_target == "real.conf"


def test_sad_nfs_atomic_save_keeps_the_symlink(tmp_path) -> None:
    from core.atomic_io import atomic_write

    (tmp_path / "real.conf").write_text("old")
    os.chmod(tmp_path / "real.conf", 0o600)
    os.symlink("real.conf", tmp_path / "link.conf")
    atomic_write(_nfs(tmp_path), "/link.conf", b"new")
    assert os.path.islink(tmp_path / "link.conf")
    assert (tmp_path / "real.conf").read_text() == "new"
    assert stat.S_IMODE(os.stat(tmp_path / "real.conf").st_mode) != 0o777


def _returns_within(fn, seconds: float = 3.0):
    result: list = []

    def run():
        try:
            result.append(fn())
        except Exception as exc:  # noqa: BLE001 - handed back to the test
            result.append(exc)

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(seconds)
    assert not t.is_alive(), "blocked on the FIFO"
    return result[0]


@pytest.mark.parametrize(
    "call",
    [
        lambda root: _nfs(root).open_read("/pipe"),
        lambda root: _nfs(root).checksum("/pipe"),
        lambda root: _iscsi(root).open_read("/pipe"),
        lambda root: _iscsi(root).checksum("/pipe"),
    ],
    ids=["nfs-open_read", "nfs-checksum", "iscsi-open_read", "iscsi-checksum"],
)
def test_sad_mount_backends_refuse_a_fifo_instead_of_blocking(tmp_path, call) -> None:
    os.mkfifo(tmp_path / "pipe")
    try:
        result = _returns_within(lambda: call(tmp_path))
        assert isinstance(result, OSError) and "not a regular file" in str(result)
    finally:
        # Unblock a thread still waiting in open() on the old code.
        fd = os.open(tmp_path / "pipe", os.O_RDWR | os.O_NONBLOCK)
        os.close(fd)


def test_edge_nfs_normalize_is_idempotent_and_never_doubles_the_root() -> None:
    s = NfsSession.__new__(NfsSession)
    assert s.normalize("/") == "/"
    assert s.normalize("") == "/"
    assert s.normalize("/dir") == "/dir"
    assert s.normalize("dir/sub/") == "/dir/sub"
    assert s.normalize("//dir//x/..") == "/dir"
    for p in ("/", "/dir", "a/b", "//x"):
        assert s.normalize(s.normalize(p)) == s.normalize(p)
    assert s.join(s.normalize("/dir"), "f") == "/dir/f"
