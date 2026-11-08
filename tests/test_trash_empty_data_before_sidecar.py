"""Empty Trash removes an entry's data before its sidecar, and reports what
it could not remove.

``empty_trash`` removed the trash folder's entries in listing order, so an
entry's sidecar could go first. When the recursive removal of its data then
failed part way (EBUSY on a mount inside it, a file another user owns in a
sticky folder), the half-deleted data was no longer listed in the Trash
window, and every later Empty Trash kept it as "no sidecar": hidden for
good. Now the sidecar goes only after the data is gone, and the entries
that stay are reported (:class:`core.trash.EmptyTrashIncomplete`).
"""

from __future__ import annotations

import os

import pytest

from core import trash as T
from core.local_fs import LocalFS


class _FS(LocalFS):
    """Lists sidecars first (scandir order is arbitrary) and fails the
    recursive removal of the data folders named in *busy*."""

    def __init__(self, home: str, busy: set[str] | None = None) -> None:
        super().__init__()
        self._home = home
        self.busy = busy or set()

    def home(self) -> str:
        return self._home

    def list_dir(self, path):
        items = super().list_dir(path)
        return sorted(items, key=lambda i: not i.name.endswith(T.META_SUFFIX))

    def remove(self, path, recursive=False):
        if os.path.basename(path) in self.busy:
            raise OSError(16, "Device or resource busy", path)
        return super().remove(path, recursive)


def _trash_folder(fs: _FS, home, name: str) -> str:
    folder = home / name / "sub"
    folder.mkdir(parents=True)
    (folder / "f.txt").write_text("x")
    return T.trash(fs, str(home / name))


def test_sad_a_failed_data_removal_keeps_the_entry_listed(tmp_path):
    fs = _FS(str(tmp_path))
    tid = _trash_folder(fs, tmp_path, "project")
    fs.busy = {tid}
    with pytest.raises(T.EmptyTrashIncomplete) as caught:
        T.empty_trash(fs)
    assert [trash_id for trash_id, _ in caught.value.failed] == [tid]
    assert caught.value.removed == 0
    assert "busy" in str(caught.value)
    assert [e.trash_id for e in T.list_trash(fs)] == [tid]  # still in the Trash window

    fs.busy = set()  # the next Empty Trash finishes the job
    assert T.empty_trash(fs) == 1
    assert os.listdir(tmp_path / T.TRASH_DIRNAME) == []


def test_sad_one_entry_that_stays_does_not_stop_the_others(tmp_path):
    fs = _FS(str(tmp_path))
    stuck = _trash_folder(fs, tmp_path, "a")
    gone = _trash_folder(fs, tmp_path, "b")
    fs.busy = {stuck}
    with pytest.raises(T.EmptyTrashIncomplete) as caught:
        T.empty_trash(fs)
    assert caught.value.removed == 1
    assert [trash_id for trash_id, _ in caught.value.failed] == [stuck]
    left = sorted(os.listdir(tmp_path / T.TRASH_DIRNAME))
    assert left == sorted([stuck, stuck + T.META_SUFFIX])
    assert gone not in left


def test_happy_empty_trash_removes_every_entry_whatever_the_listing_order(tmp_path):
    fs = _FS(str(tmp_path))
    _trash_folder(fs, tmp_path, "a")
    (tmp_path / "f.txt").write_text("x")
    T.trash(fs, str(tmp_path / "f.txt"))
    assert T.empty_trash(fs) == 2
    assert os.listdir(tmp_path / T.TRASH_DIRNAME) == []


def test_edge_a_sidecar_without_data_is_removed_and_not_counted(tmp_path):
    fs = _FS(str(tmp_path))
    (tmp_path / "f.txt").write_text("x")
    tid = T.trash(fs, str(tmp_path / "f.txt"))
    os.remove(tmp_path / T.TRASH_DIRNAME / tid)
    assert T.empty_trash(fs) == 0
    assert os.listdir(tmp_path / T.TRASH_DIRNAME) == []


def test_edge_data_without_a_sidecar_still_stays(tmp_path):
    fs = _FS(str(tmp_path))
    root = tmp_path / T.TRASH_DIRNAME
    root.mkdir()
    orphan = root / ("0" * 32)
    orphan.write_text("the only copy")
    assert T.empty_trash(fs) == 0
    assert orphan.read_text() == "the only copy"
