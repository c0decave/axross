"""The root and "file/" on the backends that map paths themselves.

Measured before (review round 6, repros gaps/remove_root.py and
gaps/trailing_slash_mutations.py):

* ``remove("/", recursive=True)`` emptied the whole NFS export and iSCSI
  LUN, ``remove(mount folder)`` the whole MTP device - RamFS, SQLite and
  NFS without a mount refused it;
* on RamFS, SQLite, NFS, iSCSI and NFS without a mount ``remove("g/")``
  deleted the FILE g and ``open_read("g/")`` read it: the slash was
  normalized away. stat(2) of "file/" is ENOTDIR, and so it is now for
  stat, open_read, remove, rename, list_dir and chmod;
* writing under a file on NFS / iSCSI was a FileExistsError (makedirs),
  not NotADirectoryError.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import test_backend_conformance as C  # noqa: E402

MAPPED = ("ramfs", "sqlite", "nfs", "iscsi", "mtp", "nfs_user_v3", "nfs_user_v4")


@pytest.fixture(params=MAPPED)
def t(request, tmp_path):
    target = C.MAKERS[request.param](tmp_path)
    try:
        b = target.backend
        b.mkdir(target.J("d"))
        with b.open_write(target.J("d", "f")) as fh:
            fh.write(b"hello")
        with b.open_write(target.J("g")) as fh:
            fh.write(b"other")
        yield target
    finally:
        for done in target.cleanup:
            try:
                done()
            except Exception:  # noqa: BLE001 - cleanup only
                pass


def _intact(t) -> None:
    with t.backend.open_read(t.J("g")) as fh:
        assert fh.read() == b"other"
    with t.backend.open_read(t.J("d", "f")) as fh:
        assert fh.read() == b"hello"


def test_sad_removing_the_root_is_refused(t):
    with pytest.raises(OSError):
        t.backend.remove(t.root, recursive=True)
    _intact(t)
    if t.local_dir is not None:
        assert os.path.isdir(t.local_dir)


@pytest.mark.parametrize("op", ["stat", "open_read", "remove", "rename", "list_dir", "chmod"])
def test_sad_a_file_path_ending_in_a_slash_is_not_the_file(t, op):
    b, slashed = t.backend, t.J("g") + "/"
    calls = {
        "stat": lambda: b.stat(slashed),
        "open_read": lambda: b.open_read(slashed).close(),
        "remove": lambda: b.remove(slashed),
        "rename": lambda: b.rename(slashed, t.J("moved")),
        "list_dir": lambda: b.list_dir(slashed),
        "chmod": lambda: b.chmod(slashed, 0o600),
    }
    with pytest.raises(NotADirectoryError):
        calls[op]()
    _intact(t)
    assert not b.exists(t.J("moved"))


def test_edge_exists_of_a_file_path_ending_in_a_slash_is_false(t):
    assert t.backend.exists(t.J("g")) is True
    assert t.backend.exists(t.J("g") + "/") is False


def test_happy_a_folder_path_ending_in_a_slash_still_works(t):
    b, slashed = t.backend, t.J("d") + "/"
    assert b.stat(slashed).is_dir
    assert [i.name for i in b.list_dir(slashed)] == ["f"]
    b.remove(slashed, recursive=True)
    assert not b.exists(t.J("d"))


def test_sad_writing_under_a_file_is_not_a_directory(t):
    with pytest.raises(NotADirectoryError):
        with t.backend.open_write(t.J("g", "x")) as fh:
            fh.write(b"x")
    _intact(t)


@pytest.mark.parametrize("op", ["open_write", "stat", "mkdir", "remove"])
def test_sad_sqlite_a_non_utf8_name_is_an_oserror(tmp_path, op):
    """Round 6: a name with surrogate escapes (a non-UTF-8 local file
    system) raised UnicodeEncodeError from the SQLite binding - no
    OSError, so a copy job ended instead of failing that one file."""
    import errno

    t = C.MAKERS["sqlite"](tmp_path)
    name = t.J("bad\udcff.txt")
    with pytest.raises(OSError) as exc_info:
        getattr(t.backend, op)(name)
    assert exc_info.value.errno == errno.EILSEQ


# -- every backend (review round 7) ---------------------------------------------
#
# Measured before (repro conf/test_root_all_backends.py): the guards above
# covered 7 backends. remove("/", recursive=True) wiped the root on SMB, FTP,
# vsftpd, SFTP, OneDrive and Azure Files, SCP and Telnet built
# ``rm -rf -- /``; remove("g/") and rename("g/") acted on the FILE g on FTP,
# SMB, WebDAV, Google Drive, OneDrive, Dropbox, Azure Files, SCP, Telnet and
# rsh. Now one guard (core.backend_guard) wraps every backend class.


@pytest.fixture(params=sorted(C.MAKERS))
def every(request, tmp_path):
    target = C.MAKERS[request.param](tmp_path)
    try:
        b = target.backend
        b.mkdir(target.J("d"))
        with b.open_write(target.J("d", "f")) as fh:
            fh.write(b"hello")
        with b.open_write(target.J("g")) as fh:
            fh.write(b"other")
        yield target
    finally:
        for done in target.cleanup:
            try:
                done()
            except Exception:  # noqa: BLE001 - cleanup only
                pass


@pytest.mark.parametrize("root", ["/", "//", "/.", "/d/.."])
def test_sad_removing_the_root_never_reaches_any_backend(every, root):
    """The backend's own remove is never called for the root - checked
    through a subclass whose remove only records, so a guard that failed
    here could not run ``rm -rf /`` on this machine (the shell backends
    and LocalFS work on the local file system)."""
    b = every.backend
    reached = []

    class Recording(type(b)):
        def remove(self, path, recursive=False):
            reached.append(path)

    original = b.__class__
    b.__class__ = Recording
    try:
        with pytest.raises(PermissionError):
            b.remove(root, recursive=True)
    finally:
        b.__class__ = original
    assert reached == []
    _intact(every)


def test_sad_removing_a_root_folder_keeps_everything(every):
    """End to end where the test's root is the backend's root."""
    from core.backend_guard import is_root_path

    if not is_root_path(every.backend, every.root):
        pytest.skip(f"{every.name}: the test folder {every.root} is no root")
    with pytest.raises(OSError):
        every.backend.remove(every.root, recursive=True)
    _intact(every)


@pytest.mark.parametrize("op", ["stat", "open_read", "remove", "rename", "list_dir"])
def test_sad_a_file_path_ending_in_a_slash_is_not_the_file_anywhere(every, op):
    b, slashed = every.backend, every.J("g") + "/"
    calls = {
        "stat": lambda: b.stat(slashed),
        "open_read": lambda: b.open_read(slashed).close(),
        "remove": lambda: b.remove(slashed),
        "rename": lambda: b.rename(slashed, every.J("moved")),
        "list_dir": lambda: b.list_dir(slashed),
    }
    with pytest.raises(NotADirectoryError):
        calls[op]()
    _intact(every)
    assert not b.exists(every.J("moved"))


def test_happy_a_folder_path_ending_in_a_slash_works_anywhere(every):
    b, slashed = every.backend, every.J("d") + "/"
    assert b.stat(slashed).is_dir
    assert [i.name for i in b.list_dir(slashed)] == ["f"]
    with b.open_read(every.J("d", "f")) as fh:
        assert fh.read() == b"hello"
    b.rename(slashed, every.J("e"))
    assert [i.name for i in b.list_dir(every.J("e") + "/")] == ["f"]
    b.remove(every.J("e") + "/", recursive=True)
    assert not b.exists(every.J("e"))


def test_edge_a_missing_path_ending_in_a_slash_is_still_not_found(every):
    with pytest.raises(FileNotFoundError):
        every.backend.stat(every.J("nothing") + "/")


def test_edge_an_ordinary_path_costs_no_extra_stat(tmp_path):
    """The guard asks only for a path that ends in '/'; calls a backend
    makes on itself inside a guarded call are not checked again."""
    from core.ram_fs import RamFsSession

    stats = []

    class Counting(RamFsSession):
        def stat(self, path):
            stats.append(path)
            return super().stat(path)

    b = Counting(f"guard-cost-{os.getpid()}")
    try:
        b.mkdir("/d")
        with b.open_write("/d/f") as fh:
            fh.write(b"x")
        stats.clear()
        b.list_dir("/d")
        with b.open_read("/d/f") as fh:
            fh.read()
        b.rename("/d/f", "/d/g")
        assert stats == []
        b.list_dir("/d/")  # a non-empty listing: no stat either
        assert stats == []
        b.remove("/d/", recursive=True)
        assert stats == ["/d/"]  # one, not one per entry
    finally:
        b.disconnect()


@pytest.mark.parametrize("path,root", [
    ("/", True), ("//", True), ("/.", True), ("/a/..", True), ("", True), (".", True),
    ("/a", False), ("/a/", False), ("a", False), ("..", False),
])
def test_edge_what_counts_as_the_root(path, root):
    from core.backend_guard import is_root_path
    from core.ram_fs import RamFsSession

    assert is_root_path(RamFsSession.__new__(RamFsSession), path) is root


def test_edge_a_drive_root_counts_on_a_backslash_backend():
    from core.backend_guard import is_root_path

    class Win:
        def separator(self):
            return "\\"

    assert is_root_path(Win(), "C:\\") and is_root_path(Win(), "c:")
    assert not is_root_path(Win(), "C:\\Users")
