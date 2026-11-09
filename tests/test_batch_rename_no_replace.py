"""Batch Rename never replaces a file another program saves meanwhile.

Review round 6 (N2): the last step of each entry was "exists? then
rename()" - a plain rename. A file saved under the new name between the
check and the rename was replaced (LocalFS os.rename, SFTP posix-rename)
and lost. The same held for the rollback to the old name. Both go through
core.server_ops.rename_no_replace now: the other file stays, the entry
goes back (or to a visible ``name (n)``) and the error report says so.
"""

from __future__ import annotations

import os

import pytest
from PyQt6.QtWidgets import QApplication

from core import local_fs as local_fs_module
from core.local_fs import LocalFS
from ui.batch_rename_dialog import BatchRenameDialog

_APP: list = []


class _RacyFS(LocalFS):
    """Another program saves a file under one of *names* right before
    each rename into it - after any check the dialog made."""

    def __init__(self, *names: str):
        super().__init__()
        self._names = set(names)

    def _race(self, dst: str) -> None:
        name = os.path.basename(dst)
        if name in self._names:
            self._names.discard(name)
            with open(dst, "w") as handle:
                handle.write("the other program's file")

    def rename(self, src: str, dst: str) -> None:
        self._race(dst)
        super().rename(src, dst)

    def rename_no_replace(self, src: str, dst: str) -> None:
        self._race(dst)
        local_fs_module.rename_no_replace(src, dst)


@pytest.fixture
def folder(tmp_path):
    if not _APP:
        _APP.append(QApplication.instance() or QApplication([]))
    (tmp_path / "IMG_1.jpg").write_text("photo 1")
    return tmp_path


def _run(fs, folder, pairs):
    dialog = BatchRenameDialog(fs, str(folder), list(fs.list_dir(str(folder))))
    try:
        return dialog._rename_all(pairs, {old for old, _ in pairs},
                                  {"done": 0, "total": len(pairs), "phase": ""})
    finally:
        dialog.deleteLater()


def _contents(folder):
    return {p.name: p.read_text() for p in folder.iterdir()}


def test_sad_a_file_saved_under_the_new_name_meanwhile_is_kept(folder):
    outcome = _run(_RacyFS("holiday_1.jpg"), folder, [("IMG_1.jpg", "holiday_1.jpg")])
    assert outcome[0] == "done" and outcome[1] == 0
    assert "already exists" in outcome[2][0]
    assert _contents(folder) == {"holiday_1.jpg": "the other program's file",
                                 "IMG_1.jpg": "photo 1"}


def test_edge_the_rollback_does_not_replace_a_file_saved_under_the_old_name(folder):
    outcome = _run(_RacyFS("holiday_1.jpg", "IMG_1.jpg"), folder,
                   [("IMG_1.jpg", "holiday_1.jpg")])
    assert outcome[1] == 0 and "kept as" in outcome[2][0]
    assert _contents(folder) == {"holiday_1.jpg": "the other program's file",
                                 "IMG_1.jpg": "the other program's file",
                                 "IMG_1 (1).jpg": "photo 1"}


def test_happy_a_free_name_is_renamed(folder):
    assert _run(LocalFS(), folder, [("IMG_1.jpg", "holiday_1.jpg")]) == ("done", 1, [])
    assert _contents(folder) == {"holiday_1.jpg": "photo 1"}
