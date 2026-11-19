"""A name no POSIX folder can hold ("../x", "a/b", a NUL inside) from an
SFTP, SCP or SVN listing is no longer dropped with only a log line: it is
listed as an unusable row under a NUL-marked name, as S3 and Azure list a
key under an empty segment. The folder copy shows a refused row for it,
and no backend call through it reaches the server (core.backend_guard):
EINVAL, and exists/is_dir answer no."""
from __future__ import annotations

import errno
import os
import stat
import time

import pytest

paramiko = pytest.importorskip("paramiko")

from core.backend import SessionLifecycle  # noqa: E402
from core.path_policy import UNADDRESSABLE_MARK, safe_join  # noqa: E402
from core.ssh_client import SSHSession  # noqa: E402


def _attr(name: str, mode: int = stat.S_IFREG | 0o644):
    a = paramiko.SFTPAttributes()
    a.filename = name
    a.st_mode = mode
    a.st_size = 3
    a.st_mtime = a.st_atime = int(time.time())
    a.st_uid = a.st_gid = 0
    return a


class _FakeSftp:
    def __init__(self, names):
        self.names = names
        self.calls = []

    def listdir_attr(self, path):
        self.calls.append(("listdir_attr", path))
        return [_attr(n) for n in self.names]

    def lstat(self, path):
        self.calls.append(("lstat", path))
        return _attr("dir", stat.S_IFDIR | 0o755)

    def __getattr__(self, name):
        def call(*args, **kwargs):
            self.calls.append((name, *args))
            raise AssertionError(f"reached the server: {name}{args}")
        return call


def _sftp(names):
    s = SSHSession.__new__(SSHSession)
    fake = _FakeSftp(names)
    s._get_sftp_client = lambda: fake
    return s, fake


def test_happy_the_listing_has_a_row_for_each():
    session, _ = _sftp(["ok.txt", "../x", "a/b"])
    names = [i.name for i in session.list_dir("/srv")]
    assert names == ["ok.txt", UNADDRESSABLE_MARK + "../x", UNADDRESSABLE_MARK + "a/b"]
    for name in names[1:]:
        with pytest.raises(ValueError):
            safe_join(session, "/srv", name)


def test_happy_the_folder_copy_shows_a_refused_row(tmp_path):
    from PyQt6.QtCore import QCoreApplication

    app = QCoreApplication.instance() or QCoreApplication([])  # noqa: F841
    from core.local_fs import LocalFS
    from core.transfer_manager import TransferManager
    from core.transfer_worker import TransferDirection

    session, _ = _sftp(["ok.txt", "../x"])
    mgr = TransferManager(max_parallel=1)
    try:
        mgr._worker.enqueue = lambda job: None
        jobs = mgr._transfer_directory(session, LocalFS(), "/srv",
                                       os.path.join(str(tmp_path), "srv"),
                                       TransferDirection.DOWNLOAD)
    finally:
        mgr.shutdown()
    refused = [j for j in jobs if j.error_message]
    assert len(refused) == 1 and "not usable" in refused[0].error_message
    assert not (tmp_path / "x").exists()


class _Recorder(SessionLifecycle):
    """A backend whose every call is recorded (none may get a marked path)."""

    calls: list = []

    def separator(self):
        return "/"

    def join(self, *parts):
        return "/".join(parts)

    def _hit(self, *args):
        type(self).calls.append(args)
        return None

    def remove(self, path, recursive=False):
        return self._hit("remove", path)

    def rename(self, src, dst):
        return self._hit("rename", src, dst)

    def open_read(self, path):
        return self._hit("open_read", path)

    def stat(self, path):
        return self._hit("stat", path)

    def list_dir(self, path):
        return self._hit("list_dir", path) or []

    def open_write(self, path, append=False):
        return self._hit("open_write", path)

    def mkdir(self, path):
        return self._hit("mkdir", path)

    def chmod(self, path, mode):
        return self._hit("chmod", path)

    def checksum(self, path, algorithm="sha256"):
        return self._hit("checksum", path)

    def readlink(self, path):
        return self._hit("readlink", path)

    def copy(self, src, dst):
        return self._hit("copy", src, dst)

    def hardlink(self, target, link_path):
        return self._hit("hardlink", target, link_path)

    def symlink(self, target, link_path):
        return self._hit("symlink", target, link_path)

    def exists(self, path):
        self._hit("exists", path)
        return True

    def is_dir(self, path):
        self._hit("is_dir", path)
        return True


MARKED = "/srv/" + UNADDRESSABLE_MARK + "../x"


@pytest.mark.parametrize("call", [
    lambda b: b.remove(MARKED, recursive=True), lambda b: b.rename(MARKED, "/srv/y"),
    lambda b: b.rename("/srv/y", MARKED), lambda b: b.open_read(MARKED),
    lambda b: b.stat(MARKED), lambda b: b.list_dir(MARKED),
    lambda b: b.open_write(MARKED), lambda b: b.mkdir(MARKED), lambda b: b.chmod(MARKED, 0o600),
    lambda b: b.checksum(MARKED), lambda b: b.readlink(MARKED), lambda b: b.copy(MARKED, "/y"),
    lambda b: b.hardlink(MARKED, "/y"), lambda b: b.symlink("t", MARKED),
])
def test_sad_no_call_through_a_marked_name_reaches_the_backend(call):
    _Recorder.calls = []
    with pytest.raises(OSError) as info:
        call(_Recorder())
    assert info.value.errno == errno.EINVAL
    assert _Recorder.calls == []


def test_edge_exists_and_is_dir_answer_no_and_a_symlink_target_is_data():
    _Recorder.calls = []
    backend = _Recorder()
    assert backend.exists(MARKED) is False and backend.is_dir(MARKED) is False
    assert _Recorder.calls == []
    backend.symlink("weird\x00target", "/srv/link")  # the target is data, not a path
    assert _Recorder.calls == [("symlink", "weird\x00target", "/srv/link")]
