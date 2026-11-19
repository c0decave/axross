"""Rename and unlink of a file still open for writing on a writable mount.

Review (buffer mode, the adapter driven directly):
A) a file created, written and renamed before close: the rename failed
   with ENOENT although getattr said the file was there (it was only in
   the session's buffer);
B) written, fsync'd, renamed, written again, closed: the final content
   landed under the OLD name, the new name kept the stale first half
   (the commit used the path the session was opened with);
C) open, unlink, keep writing, close (the temp-file idiom): the deleted
   file came back.

Now open write sessions follow a rename (also of a folder above them), a
file that is not on the backend yet is renamed in the session only, and
an unlinked open file is orphaned: written to, never committed.
"""

from __future__ import annotations

import errno
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import fuse_mount as FM  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


def _fs(root: Path, mode: str = "buffer") -> FM.BackendFuseFS:
    return FM.BackendFuseFS(LocalFS(), str(root), writeable=True, write_mode=mode)


def _files(root: Path) -> dict[str, bytes]:
    return {
        str(p.relative_to(root)): p.read_bytes()
        for p in sorted(root.rglob("*")) if p.is_file()
    }


def test_happy_a_created_file_renamed_before_close_lands_under_the_new_name(tmp_path):
    fs = _fs(tmp_path)
    fh = fs.create("/a.tmp", 0o644)
    fs.write("/a.tmp", b"data", 0, fh)
    fs.rename("/a.tmp", "/a.txt")
    assert fs.getattr("/a.txt", fh)["st_size"] == 4
    with pytest.raises(OSError) as err:
        fs.getattr("/a.tmp")
    assert err.value.errno == errno.ENOENT
    fs.flush("/a.txt", fh)
    fs.release("/a.txt", fh)
    assert _files(tmp_path) == {"a.txt": b"data"}


def test_happy_a_committed_file_renamed_and_written_again_keeps_it_all(tmp_path):
    fs = _fs(tmp_path)
    fh = fs.create("/b.tmp", 0o644)
    fs.write("/b.tmp", b"part1 ", 0, fh)
    fs.fsync("/b.tmp", 0, fh)
    fs.rename("/b.tmp", "/b.txt")
    fs.write("/b.txt", b"part2", 6, fh)
    fs.flush("/b.txt", fh)
    fs.release("/b.txt", fh)
    assert _files(tmp_path) == {"b.txt": b"part1 part2"}


def test_edge_a_file_open_below_a_renamed_folder_follows_it(tmp_path):
    (tmp_path / "d").mkdir()
    fs = _fs(tmp_path)
    fh = fs.create("/d/f", 0o644)
    fs.write("/d/f", b"one", 0, fh)
    fs.fsync("/d/f", 0, fh)
    fs.rename("/d", "/e")
    fs.write("/e/f", b" two", 3, fh)
    fs.flush("/e/f", fh)
    fs.release("/e/f", fh)
    assert _files(tmp_path) == {"e/f": b"one two"}


def test_hostile_an_unlinked_open_file_does_not_come_back(tmp_path):
    fs = _fs(tmp_path)
    fh = fs.create("/scratch", 0o600)
    fs.write("/scratch", b"x", 0, fh)
    fs.fsync("/scratch", 0, fh)
    fs.unlink("/scratch")
    fs.write("/scratch", b"yy", 1, fh)
    assert fs.read("/scratch", 3, 0, fh) == b"xyy"  # still readable by its holder
    fs.flush("/scratch", fh)
    fs.release("/scratch", fh)
    assert _files(tmp_path) == {}


def test_edge_an_unlinked_file_that_was_never_committed_unlinks(tmp_path):
    fs = _fs(tmp_path)
    fh = fs.create("/new", 0o600)
    fs.write("/new", b"x", 0, fh)
    fs.unlink("/new")
    with pytest.raises(OSError):
        fs.getattr("/new")
    fs.flush("/new", fh)
    fs.release("/new", fh)
    assert _files(tmp_path) == {}


def test_edge_a_file_renamed_over_an_open_one_orphans_that_one(tmp_path):
    fs = _fs(tmp_path)
    old = fs.create("/target", 0o644)
    fs.write("/target", b"old", 0, old)
    fs.fsync("/target", 0, old)
    (tmp_path / "src").write_bytes(b"new")
    fs.rename("/src", "/target")
    fs.write("/target", b"OLD", 0, old)
    fs.flush("/target", old)
    fs.release("/target", old)
    assert _files(tmp_path) == {"target": b"new"}


def test_happy_stream_mode_rename_before_close(tmp_path):
    fs = _fs(tmp_path, mode="stream")
    fh = fs.create("/s.tmp", 0o644)
    fs.write("/s.tmp", b"abc", 0, fh)
    fs.rename("/s.tmp", "/s.txt")
    fs.write("/s.txt", b"def", 3, fh)
    fs.flush("/s.txt", fh)
    fs.release("/s.txt", fh)
    assert _files(tmp_path) == {"s.txt": b"abcdef"}
