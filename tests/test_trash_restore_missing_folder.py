"""Restoring from the trash recreates the folder the entry came from.

Measured before: trash ``work/proj/f.txt``, then remove ``work`` (empty
it and delete it, or delete it for good), then Restore ``f.txt``: the
restore failed with "No such file or directory: '<trash>/<id>' ->
'work/proj/f.txt'" on LocalFS and "parent missing" on RamFS - the
message even named the trash entry as the missing file. The rename into a
folder that no longer exists cannot succeed; nothing created it. Ctrl+Z
of the trashing failed the same way (core.undo restores through
core.trash.restore).

Now restore recreates the missing folders first (and removes them again
when the move still fails); a file standing where a folder should be is
refused and the entry stays in the trash.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import trash as T  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402


class _LocalBase(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.fs = LocalFS()
        self.fs.home = lambda: str(self.root)

    def _trash_nested(self) -> tuple[str, Path]:
        target = self.root / "work" / "proj" / "f.txt"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"data")
        return T.trash(self.fs, str(target)), target


class RestoreMissingFolderTest(_LocalBase):
    def test_happy_a_file_comes_back_into_its_recreated_folders(self) -> None:
        trash_id, target = self._trash_nested()
        shutil.rmtree(self.root / "work")
        self.assertEqual(T.restore(self.fs, trash_id), str(target))
        self.assertEqual(target.read_bytes(), b"data")
        self.assertEqual(T.list_trash(self.fs), [])

    def test_happy_undo_of_the_trashing_restores_into_a_removed_folder(self) -> None:
        from core.undo import UndoPlan, apply_undo

        trash_id, target = self._trash_nested()
        shutil.rmtree(self.root / "work")
        plan = UndoPlan(operation_id="op", operation="trash", reversible=True,
                        action="restore_from_trash", reason="restore", source=str(target),
                        trash_id=trash_id)
        self.assertEqual(apply_undo(plan, self.fs), str(target))
        self.assertEqual(target.read_bytes(), b"data")

    def test_sad_a_file_where_the_folder_was_is_refused_and_the_entry_kept(self) -> None:
        trash_id, target = self._trash_nested()
        shutil.rmtree(self.root / "work")
        (self.root / "work").write_bytes(b"a file now")
        with self.assertRaises(OSError) as ctx:
            T.restore(self.fs, trash_id)
        self.assertIn("not a folder", str(ctx.exception))
        self.assertEqual((self.root / "work").read_bytes(), b"a file now")
        self.assertEqual([e.trash_id for e in T.list_trash(self.fs)], [trash_id])

    def test_edge_a_failed_move_removes_the_folders_it_created(self) -> None:
        trash_id, target = self._trash_nested()
        shutil.rmtree(self.root / "work")
        with mock.patch.object(self.fs, "rename", side_effect=PermissionError(13, "denied")):
            with self.assertRaises(OSError):
                T.restore(self.fs, trash_id)
        self.assertFalse((self.root / "work").exists())
        self.assertEqual([e.trash_id for e in T.list_trash(self.fs)], [trash_id])

    def test_edge_an_explicit_target_in_a_new_folder(self) -> None:
        trash_id, _target = self._trash_nested()
        elsewhere = self.root / "new" / "place" / "g.txt"
        self.assertEqual(T.restore(self.fs, trash_id, target=str(elsewhere)), str(elsewhere))
        self.assertEqual(elsewhere.read_bytes(), b"data")

    def test_edge_existing_folders_are_left_as_they_are(self) -> None:
        trash_id, target = self._trash_nested()
        (self.root / "work" / "proj" / "other.txt").write_bytes(b"o")
        T.restore(self.fs, trash_id)
        self.assertEqual(sorted(os.listdir(target.parent)), ["f.txt", "other.txt"])


class RestoreMissingFolderRamTest(unittest.TestCase):
    def test_edge_ramfs_file_and_folder_entries(self) -> None:
        ram = RamFsSession()
        ram.mkdir("/a/b", parents=True)
        with ram.open_write("/a/b/x.txt") as fh:
            fh.write(b"x")
        ram.mkdir("/a/b/dir")
        with ram.open_write("/a/b/dir/y.txt") as fh:
            fh.write(b"y")
        file_id = T.trash(ram, "/a/b/x.txt")
        dir_id = T.trash(ram, "/a/b/dir")
        ram.remove("/a", recursive=True)
        self.assertEqual(T.restore(ram, dir_id), "/a/b/dir")
        self.assertEqual(T.restore(ram, file_id), "/a/b/x.txt")
        with ram.open_read("/a/b/dir/y.txt") as fh:
            self.assertEqual(fh.read(), b"y")


class _ObjectStoreLike(RamFsSession):
    """Keys, not folders: a rename lands wherever it is told, and the
    "folder" of a key disappears with its last key. Records mkdir calls."""

    def __init__(self) -> None:
        super().__init__()
        self.mkdirs: list[str] = []

    def rename(self, src, dst):
        parent = self.parent(dst)
        if not self.exists(parent):
            super().mkdir(parent, parents=True, exist_ok=True)
        super().rename(src, dst)

    def mkdir(self, path, parents=False, exist_ok=False):
        self.mkdirs.append(path)
        super().mkdir(path, parents=parents, exist_ok=exist_ok)


class RestoreWithoutFolderNeedTest(unittest.TestCase):
    def test_edge_a_backend_that_needs_no_folder_gets_no_folder_created(self) -> None:
        store = _ObjectStoreLike()
        store.mkdir("/bucket/a", parents=True)
        with store.open_write("/bucket/a/k.txt") as fh:
            fh.write(b"k")
        trash_id = T.trash(store, "/bucket/a/k.txt")
        RamFsSession.remove(store, "/bucket", recursive=True)
        store.mkdirs.clear()
        self.assertEqual(T.restore(store, trash_id), "/bucket/a/k.txt")
        self.assertEqual(store.mkdirs, [])


class RestoreMissingFolderBrowserTest(_LocalBase):
    """e2e: the Show Trash window's Restore button."""

    @classmethod
    def setUpClass(cls) -> None:
        from PyQt6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication([])

    def test_happy_restore_button_brings_the_file_back(self) -> None:
        from PyQt6.QtCore import Qt
        from PyQt6.QtTest import QTest

        from ui.trash_browser import TrashBrowserDialog

        _trash_id, target = self._trash_nested()
        shutil.rmtree(self.root / "work")
        with mock.patch("ui.trash_browser.QMessageBox") as box:
            dlg = TrashBrowserDialog(self.fs)
            self.addCleanup(dlg.close)
            end = time.monotonic() + 10
            while dlg._table.model().rowCount() == 0 and time.monotonic() < end:
                self.app.processEvents()
                time.sleep(0.01)
            dlg._table.selectRow(0)
            QTest.mouseClick(dlg._restore_btn, Qt.MouseButton.LeftButton)
            end = time.monotonic() + 10
            while (dlg.busy or not target.exists()) and time.monotonic() < end:
                self.app.processEvents()
                time.sleep(0.01)
            self.assertFalse(box.warning.called, box.warning.call_args)
        self.assertEqual(target.read_bytes(), b"data")


if __name__ == "__main__":
    unittest.main()
