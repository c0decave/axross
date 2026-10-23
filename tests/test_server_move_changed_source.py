"""A same-backend move that has to copy keeps a source that changed meanwhile.

Reported: ``server_side_move`` copies and then deletes in two places - a
local move across file systems (EXDEV: Move to Trash from a USB stick, a
rename onto another disk) and a backend without a rename primitive. Both
removed the source right after the copy without looking at it again, so
data written to it while it was being copied (a log line, a file added to
a folder) was in neither place afterwards.

Now both compare the source before and after the copy (size of a file;
names and sizes of a local folder's entries) and, when it changed, take
their copy back and raise; the source stays as it is.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import server_ops  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.server_ops import server_side_move  # noqa: E402
from tests.test_move_across_filesystems import _TwoMountsFS  # noqa: E402

LATE = b"LATE LOG LINE\n"


class _NoRename(LocalFS):
    """A backend whose protocol has no rename: moves copy + delete."""

    def rename(self, src: str, dst: str) -> None:
        raise NotImplementedError("no rename")


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.stick = self.tmp / "usbstick"
        self.home = self.tmp / "home"
        self.stick.mkdir()
        self.home.mkdir()

    def write_during(self, name: str, target: Path, data: bytes = LATE):
        """Patch ``server_ops.shutil.<name>`` so a writer adds *data* to
        *target* once, right after the outermost real call copied it
        (``copytree`` calls itself for each subfolder)."""
        real = getattr(shutil, name)
        depth = [0]

        def copy_then_write(*args, **kwargs):
            depth[0] += 1
            try:
                result = real(*args, **kwargs)
            finally:
                depth[0] -= 1
            if depth[0] == 0:
                with open(target, "ab") as writer:
                    writer.write(data)
            return result

        return mock.patch.object(server_ops.shutil, name, side_effect=copy_then_write)


class AcrossDevicesTest(_Base):
    def test_happy_an_unchanged_file_moves(self) -> None:
        src = self.stick / "app.log"
        src.write_bytes(b"line\n")
        server_side_move(_TwoMountsFS(self.stick), str(src), str(self.home / "app.log"))
        self.assertFalse(src.exists())
        self.assertEqual((self.home / "app.log").read_bytes(), b"line\n")

    def test_sad_a_file_written_during_the_copy_is_kept(self) -> None:
        src = self.stick / "app.log"
        src.write_bytes(b"line\n")
        dst = self.home / "app.log"
        with self.write_during("copy2", src), self.assertRaisesRegex(
            OSError, "changed while it was copied"
        ):
            server_side_move(_TwoMountsFS(self.stick), str(src), str(dst))
        self.assertEqual(src.read_bytes(), b"line\n" + LATE)
        self.assertFalse(dst.exists())

    def test_sad_a_file_added_to_a_folder_during_the_copy_is_kept(self) -> None:
        folder = self.stick / "project"
        (folder / "sub").mkdir(parents=True)
        (folder / "sub" / "a.txt").write_bytes(b"a")
        dst = self.home / "project"
        with self.write_during("copytree", folder / "sub" / "new.txt"), self.assertRaisesRegex(
            OSError, "changed while it was copied"
        ):
            server_side_move(_TwoMountsFS(self.stick), str(folder), str(dst))
        self.assertEqual((folder / "sub" / "new.txt").read_bytes(), LATE)
        self.assertEqual((folder / "sub" / "a.txt").read_bytes(), b"a")
        self.assertFalse(dst.exists())

    def test_edge_a_folder_with_a_link_to_a_folder_moves(self) -> None:
        outside = self.tmp / "outside"
        outside.mkdir()
        (outside / "big.bin").write_bytes(b"B" * 10)
        folder = self.stick / "project"
        folder.mkdir()
        (folder / "a.txt").write_bytes(b"a")
        os.symlink(outside, folder / "ln")
        server_side_move(_TwoMountsFS(self.stick), str(folder), str(self.home / "project"))
        self.assertFalse(folder.exists())
        self.assertTrue((self.home / "project" / "ln").is_symlink())
        self.assertEqual((outside / "big.bin").read_bytes(), b"B" * 10)


class NoRenameFallbackTest(_Base):
    def test_happy_an_unchanged_file_moves(self) -> None:
        src = self.home / "a.txt"
        src.write_bytes(b"data")
        server_side_move(_NoRename(), str(src), str(self.home / "b.txt"))
        self.assertFalse(src.exists())
        self.assertEqual((self.home / "b.txt").read_bytes(), b"data")

    def test_sad_a_file_written_during_the_copy_is_kept(self) -> None:
        src = self.home / "a.txt"
        src.write_bytes(b"data")
        dst = self.home / "b.txt"
        real = server_ops.server_side_copy

        def copy_then_write(*args, **kwargs):
            real(*args, **kwargs)
            with open(src, "ab") as writer:
                writer.write(LATE)

        with mock.patch.object(server_ops, "server_side_copy", side_effect=copy_then_write):
            with self.assertRaisesRegex(OSError, "changed while it was copied"):
                server_side_move(_NoRename(), str(src), str(dst))
        self.assertEqual(src.read_bytes(), b"data" + LATE)
        self.assertFalse(dst.exists())

    def test_sad_a_copy_that_came_out_short_keeps_the_source(self) -> None:
        # The audit of 2026-10-22: copy + delete compared the source's size
        # before and after, never what the copy holds.
        src = self.home / "a.txt"
        src.write_bytes(b"0123456789")
        dst = self.home / "b.txt"

        def short_copy(_backend, a, b, **_kwargs):
            Path(b).write_bytes(Path(a).read_bytes()[:4])

        with mock.patch.object(server_ops, "server_side_copy", side_effect=short_copy):
            with self.assertRaisesRegex(OSError, "only 4 of 10 bytes"):
                server_side_move(_NoRename(), str(src), str(dst))
        self.assertEqual(src.read_bytes(), b"0123456789")
        self.assertFalse(dst.exists())

    def test_edge_a_folder_or_link_has_no_size_to_compare(self) -> None:
        # ext4 folders never shrink: a used folder can report 12288 bytes,
        # its fresh copy 4096. That is not a short copy, so a folder's (and
        # a link's) own size is never compared.
        folder = self.home / "d"
        folder.mkdir()
        link = self.home / "l"
        link.symlink_to(folder)
        self.assertIsNone(server_ops._file_size(LocalFS(), str(folder)))
        self.assertIsNone(server_ops._file_size(LocalFS(), str(link)))
        server_ops.refuse_short_copy("/src", 12288, None, "/dst")  # nothing raised

    def test_edge_an_empty_file_moves(self) -> None:
        src = self.home / "a.txt"
        src.write_bytes(b"")
        server_side_move(_NoRename(), str(src), str(self.home / "empty.txt"))
        self.assertEqual((self.home / "empty.txt").read_bytes(), b"")
        self.assertFalse(src.exists())


if __name__ == "__main__":
    unittest.main()
