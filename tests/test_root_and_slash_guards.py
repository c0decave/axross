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
