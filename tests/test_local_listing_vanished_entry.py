"""An entry removed between readdir and lstat is not listed.

Round-5 review: LocalFS.list_dir turned a file that vanished while the
folder was being listed (a browser cache, a build) into an "unstattable"
'?' row: the pane showed a row that did not exist, and a folder copy
failed a job for a file that was simply gone. Such an entry is now left
out; one whose lstat fails for another reason (EACCES) stays as before.
"""

from __future__ import annotations

import errno
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.local_fs import LocalFS  # noqa: E402


class _Wrap:
    def __init__(self, it, on_entry):
        self.it, self.on_entry = it, on_entry

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.it.close()

    def __iter__(self):
        for entry in self.it:
            yield self.on_entry(entry)


def _listing(monkeypatch, folder: Path, on_entry):
    real = os.scandir
    monkeypatch.setattr(os, "scandir", lambda p: _Wrap(real(p), on_entry))
    return {i.name: i for i in LocalFS().list_dir(str(folder))}


# -- happy ------------------------------------------------------------------------------------


def test_happy_a_file_removed_while_listed_is_left_out(tmp_path, monkeypatch):
    (tmp_path / "keep.txt").write_text("x")
    (tmp_path / "vanishing.tmp").write_text("x")

    def gone(entry):
        if entry.name == "vanishing.tmp":
            os.remove(entry.path)
        return entry

    items = _listing(monkeypatch, tmp_path, gone)
    assert set(items) == {"keep.txt"}
    assert not items["keep.txt"].stat_error


# -- sad --------------------------------------------------------------------------------------


class _Refusing:
    """A DirEntry whose lstat is refused (EACCES)."""

    def __init__(self, entry):
        self._entry = entry
        self.name, self.path = entry.name, entry.path

    def is_dir(self, follow_symlinks=True):
        return False

    def is_symlink(self):
        return False

    def stat(self, follow_symlinks=True):
        raise PermissionError(errno.EACCES, "Permission denied", self.path)


def test_sad_an_entry_that_cannot_be_statted_is_still_listed(tmp_path, monkeypatch):
    (tmp_path / "locked.bin").write_text("x")
    items = _listing(monkeypatch, tmp_path, _Refusing)
    assert set(items) == {"locked.bin"}
    assert items["locked.bin"].stat_error


# -- edge -------------------------------------------------------------------------------------


def test_edge_a_dangling_symlink_is_listed(tmp_path, monkeypatch):
    os.symlink(str(tmp_path / "nowhere"), str(tmp_path / "dangling"))
    items = _listing(monkeypatch, tmp_path, lambda e: e)
    assert set(items) == {"dangling"} and items["dangling"].is_link


def test_edge_the_watcher_signature_leaves_the_vanished_entry_out_too(tmp_path, monkeypatch):
    from core import watch

    (tmp_path / "keep.txt").write_text("x")
    (tmp_path / "vanishing.tmp").write_text("x")

    def gone(entry):
        if entry.name == "vanishing.tmp":
            os.remove(entry.path)
        return entry

    real = os.scandir
    monkeypatch.setattr(os, "scandir", lambda p: _Wrap(real(p), gone))
    snapshot = watch._local_snapshot(str(tmp_path))
    assert set(snapshot.entries) == {"keep.txt"}
