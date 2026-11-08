"""Rsync rename() onto itself keeps the file.

core/rsync_client.py renames by download + upload + remove of the source.
With src == dst the upload went onto the source and the remove that
followed deleted the only copy: ``rename("/t/a.txt", "/t/a.txt")`` (or
"/t//a.txt", "/t/./a.txt") lost the file. rename(2) onto itself changes
nothing; now neither does this. A folder moved into itself is refused
(EINVAL) before anything is copied.
"""

from __future__ import annotations

import errno

import pytest

from core.rsync_client import RsyncSession


class _Recording(RsyncSession):
    """No daemon: a fixed tree; every rsync run and remove is recorded."""

    def __init__(self, tree: dict[str, bool]):  # noqa: D107 - path -> is_dir
        self.tree = dict(tree)
        self.runs: list[list[str]] = []
        self.removed: list[str] = []
        self._preserve_metadata = False

    def stat(self, path):
        from models.file_item import FileItem

        if path not in self.tree:
            raise FileNotFoundError(errno.ENOENT, "not found", path)
        return FileItem(name=path.rsplit("/", 1)[-1], is_dir=self.tree[path])

    def is_dir(self, path):
        return self.tree.get(path, False)

    def _build_url(self, path):
        return "rsync://host/mod" + path

    def _run_rsync(self, args, timeout=None):
        self.runs.append(list(args))
        return ""

    def remove(self, path, recursive=False):
        self.removed.append(path)


TREE = {"/t": True, "/t/a.txt": False, "/t/proj": True, "/t/proj/sub": True}


@pytest.mark.parametrize("dst", ["/t/a.txt", "/t//a.txt", "/t/./a.txt"])
def test_sad_rename_onto_itself_removes_nothing(dst):
    s = _Recording(TREE)
    s.rename("/t/a.txt", dst)
    assert s.runs == [] and s.removed == []


def test_edge_rename_of_a_missing_path_onto_itself_is_not_found():
    s = _Recording(TREE)
    with pytest.raises(FileNotFoundError):
        s.rename("/t/nope", "/t/nope")
    assert s.runs == [] and s.removed == []


def test_sad_a_folder_into_itself_is_refused():
    s = _Recording(TREE)
    with pytest.raises(OSError) as ctx:
        s.rename("/t/proj", "/t/proj/sub/proj")
    assert ctx.value.errno == errno.EINVAL
    assert s.runs == [] and s.removed == []


def test_happy_a_rename_to_another_name_still_moves():
    s = _Recording(TREE)
    s.rename("/t/a.txt", "/t/b.txt")
    assert len(s.runs) == 2 and s.removed == ["/t/a.txt"]
