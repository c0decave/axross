"""Move to Trash (and every local move) works across file systems.

Measured before: ``core.trash.trash`` moved the entry with
``server_side_move``, whose only primitive on LocalFS is ``os.rename``.
For a file on another file system than ``~/.axross-trash`` (a USB stick,
a second disk, /tmp on tmpfs) the kernel answers EXDEV, and
``_rename_fallback_allowed`` deliberately turns that into no fallback --
so "Move to Trash" failed for every such file, and restoring an entry to
such a place failed the same way.

Now a local move that gets EXDEV copies the entry (a folder with its
links as links) to a free destination and removes the source; a failed
copy leaves the source untouched and no partial destination.
"""

from __future__ import annotations

import errno
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import trash as T  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.server_ops import server_side_move  # noqa: E402


class _TwoMountsFS(LocalFS):
    """LocalFS whose rename fails with EXDEV between ``mount`` and the
    rest, as the kernel does between two file systems."""

    def __init__(self, mount: Path) -> None:
        super().__init__()
        self.mount = str(mount)

    def _on_mount(self, path: str) -> bool:
        return os.path.abspath(path).startswith(self.mount + os.sep)

    def rename(self, src: str, dst: str) -> None:
        if self._on_mount(src) != self._on_mount(dst):
            raise OSError(errno.EXDEV, os.strerror(errno.EXDEV), src, None, dst)
        super().rename(src, dst)

    def home(self) -> str:
        return os.environ["HOME"]


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.home = self.tmp / "home"
        self.stick = self.tmp / "usbstick"
        self.home.mkdir()
        self.stick.mkdir()
        self.fs = _TwoMountsFS(self.stick)
        self.root = str(self.home / ".axross-trash")


class TrashAcrossFilesystemsTest(_Base):
    def test_happy_a_file_on_another_file_system_goes_to_the_trash(self) -> None:
        victim = self.stick / "notes.txt"
        victim.write_text("x")
        tid = T.trash(self.fs, str(victim), root=self.root)
        self.assertFalse(victim.exists())
        self.assertEqual((Path(self.root) / tid).read_text(), "x")
        self.assertEqual([e.trash_id for e in T.list_trash(self.fs, root=self.root)], [tid])

    def test_happy_a_folder_moves_with_its_links_kept_as_links(self) -> None:
        folder = self.stick / "project"
        (folder / "sub").mkdir(parents=True)
        (folder / "sub" / "a.txt").write_text("a")
        os.symlink("sub/a.txt", folder / "link")
        tid = T.trash(self.fs, str(folder), root=self.root)
        moved = Path(self.root) / tid
        self.assertFalse(folder.exists())
        self.assertEqual((moved / "sub" / "a.txt").read_text(), "a")
        self.assertTrue((moved / "link").is_symlink())
        self.assertEqual(os.readlink(moved / "link"), "sub/a.txt")

    def test_happy_restore_back_onto_the_other_file_system(self) -> None:
        victim = self.stick / "notes.txt"
        victim.write_text("x")
        tid = T.trash(self.fs, str(victim), root=self.root)
        restored = T.restore(self.fs, tid, root=self.root)
        self.assertEqual(restored, str(victim))
        self.assertEqual(victim.read_text(), "x")

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root reads anything")
    def test_sad_a_copy_that_fails_leaves_the_source_and_no_partial_entry(self) -> None:
        folder = self.stick / "project"
        folder.mkdir()
        (folder / "ok.txt").write_text("ok")
        locked = folder / "locked.txt"
        locked.write_text("secret")
        os.chmod(locked, 0)
        self.addCleanup(os.chmod, locked, stat.S_IRUSR | stat.S_IWUSR)
        with self.assertRaises(OSError):
            T.trash(self.fs, str(folder), root=self.root)
        self.assertEqual((folder / "ok.txt").read_text(), "ok")
        self.assertTrue(locked.exists())
        self.assertEqual(os.listdir(self.root), [])


class LocalMoveAcrossFilesystemsTest(_Base):
    def test_sad_an_existing_destination_is_never_replaced(self) -> None:
        src = self.stick / "a.txt"
        dst = self.home / "a.txt"
        src.write_text("new")
        dst.write_text("old")
        with self.assertRaises(OSError):
            server_side_move(self.fs, str(src), str(dst), overwrite=True)
        self.assertEqual(src.read_text(), "new")
        self.assertEqual(dst.read_text(), "old")

    def test_edge_other_rename_errors_still_propagate_without_a_copy(self) -> None:
        class _Denied(LocalFS):
            def rename(self, src, dst):
                raise PermissionError(errno.EACCES, "denied", src)

        src = self.stick / "a.txt"
        src.write_text("x")
        with self.assertRaises(PermissionError):
            server_side_move(_Denied(), str(src), str(self.home / "a.txt"))
        self.assertTrue(src.exists())
        self.assertFalse((self.home / "a.txt").exists())

    def test_edge_exdev_from_a_remote_backend_is_not_copied_locally(self) -> None:
        class _Remote:
            name = "SFTP: x"

            def exists(self, path):
                return False

            def rename(self, src, dst):
                raise OSError(errno.EXDEV, os.strerror(errno.EXDEV), src)

        src = self.stick / "a.txt"
        src.write_text("x")
        with self.assertRaises(OSError):
            server_side_move(_Remote(), str(src), str(self.home / "a.txt"))
        self.assertTrue(src.exists())
        self.assertFalse((self.home / "a.txt").exists())

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root deletes anything")
    def test_edge_a_source_that_cannot_be_removed_keeps_the_complete_copy(self) -> None:
        folder = self.stick / "project"
        (folder / "sub").mkdir(parents=True)
        (folder / "sub" / "a.txt").write_text("a")
        os.chmod(folder / "sub", 0o555)  # its entries cannot be deleted
        self.addCleanup(os.chmod, folder / "sub", 0o755)
        dst = self.home / "project"
        with self.assertRaises(OSError) as ctx:
            server_side_move(self.fs, str(folder), str(dst))
        self.assertIn(str(dst), str(ctx.exception))
        self.assertEqual((dst / "sub" / "a.txt").read_text(), "a")

    def test_edge_a_symlink_itself_is_moved_not_its_target(self) -> None:
        target = self.stick / "big.bin"
        target.write_bytes(b"data")
        link = self.stick / "link"
        os.symlink(target, link)
        server_side_move(self.fs, str(link), str(self.home / "link"))
        self.assertTrue((self.home / "link").is_symlink())
        self.assertFalse(os.path.lexists(link))
        self.assertEqual(target.read_bytes(), b"data")


if __name__ == "__main__":
    unittest.main()
