"""NfsUserSession forgets the cached handle of a rename's destination.

rename() dropped only the SOURCE path from the session's path-to-handle
cache. A save that writes a temp file and renames it over ``a.txt`` left
``a.txt`` mapped to the handle of the file it replaced: when that inode
lives on (a second hard link, or still open elsewhere) every later read
of ``a.txt`` returned the old bytes and the next write went into the
other link's file. The destination is forgotten now too, with everything
below it when it was a folder.
"""

from __future__ import annotations

import itertools
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import nfs3_rpc as R  # noqa: E402
from core.nfs_user_client import NfsUserSession  # noqa: E402


class _Ino:
    def __init__(self, ids, kind, data=b""):
        self.id, self.kind, self.data, self.entries = next(ids), kind, bytearray(data), {}


class _FakeNfs:
    """Inodes and directories; a name is an entry pointing at an inode."""

    def __init__(self):
        self._ids = itertools.count(1)
        self.inodes: dict[int, _Ino] = {}

    def mk(self, kind, data=b""):
        i = _Ino(self._ids, kind, data)
        self.inodes[i.id] = i
        return i

    @staticmethod
    def fh(i):
        return i.id.to_bytes(8, "big")

    def ino(self, h):
        i = self.inodes.get(int.from_bytes(h, "big"))
        if i is None:
            raise R.make_nfs_error(70, "STALE")
        return i

    @staticmethod
    def attr(i):
        return R.Fattr(type=R.NF3DIR if i.kind == "d" else R.NF3REG, mode=0o644, nlink=1,
                       uid=0, gid=0, size=len(i.data), used=0, fileid=i.id,
                       atime=1, mtime=1, ctime=1)

    def lookup(self, d, name):
        e = self.ino(d).entries.get(name)
        if e is None:
            raise R.make_nfs_error(2, "LOOKUP")
        return self.fh(e), self.attr(e)

    def getattr(self, h):
        return self.attr(self.ino(h))

    def setattr(self, h, size=None, mode=None):
        if size is not None:
            del self.ino(h).data[size:]

    def create(self, d, name, mode=0o644, exclusive=False):
        e = self.mk("f")
        self.ino(d).entries[name] = e
        return self.fh(e), self.attr(e)

    def write(self, h, off, data):
        b = self.ino(h).data
        b[off:off + len(data)] = data
        return len(data)

    def read(self, h, off, n):
        b = bytes(self.ino(h).data[off:off + n])
        return b, off + len(b) >= len(self.ino(h).data)

    def rename(self, sd, sn, dd, dn):
        self.ino(dd).entries[dn] = self.ino(sd).entries.pop(sn)

    def remove(self, d, name, directory=False):
        self.ino(d).entries.pop(name)

    def readdirplus(self, d, *a):
        return [R.DirEntry(n, e.id, self.attr(e), self.fh(e))
                for n, e in self.ino(d).entries.items()]


def _session(nfs: _FakeNfs, root) -> NfsUserSession:
    s = NfsUserSession.__new__(NfsUserSession)
    s._nfs, s._root, s._info = nfs, nfs.fh(root), R.FsInfo()
    s._handles, s._lock = {(): nfs.fh(root)}, threading.RLock()
    return s


def _hard_linked():
    nfs = _FakeNfs()
    root, backup = nfs.mk("d"), nfs.mk("d")
    root.entries["backup"] = backup
    f = nfs.mk("f", b"OLD")
    root.entries["a.txt"] = f
    backup.entries["a.txt"] = f  # a second hard link keeps the inode alive
    return nfs, root, backup


def test_sad_a_save_by_rename_reads_and_writes_the_new_file():
    nfs, root, backup = _hard_linked()
    s = _session(nfs, root)
    s.list_dir("/")  # the pane lists the folder: handles cached
    with s.open_write("/.tmp-1") as w:
        w.write(b"NEW")
    s.rename("/.tmp-1", "/a.txt")
    assert s.open_read("/a.txt").read() == b"NEW"
    with s.open_write("/a.txt") as w:
        w.write(b"EDITED")
    assert bytes(root.entries["a.txt"].data) == b"EDITED"
    assert bytes(backup.entries["a.txt"].data) == b"OLD"


def test_edge_a_folder_replaced_by_rename_forgets_its_children():
    nfs = _FakeNfs()
    root, old, new = nfs.mk("d"), nfs.mk("d"), nfs.mk("d")
    keep = nfs.mk("d")
    root.entries.update({"dst": old, "src": new, "keep": keep})
    old.entries["x.txt"] = nfs.mk("f", b"old x")
    keep.entries["dst"] = old  # the old folder lives on elsewhere
    new.entries["x.txt"] = nfs.mk("f", b"new x")
    s = _session(nfs, root)
    assert s.open_read("/dst/x.txt").read() == b"old x"  # caches /dst and /dst/x.txt
    s.rename("/src", "/dst")
    assert s.open_read("/dst/x.txt").read() == b"new x"


def test_happy_rename_to_a_new_name_reads_through():
    nfs = _FakeNfs()
    root = nfs.mk("d")
    root.entries["a.txt"] = nfs.mk("f", b"A")
    s = _session(nfs, root)
    s.list_dir("/")
    s.rename("/a.txt", "/b.txt")
    assert s.open_read("/b.txt").read() == b"A"
    assert not s.exists("/a.txt")
