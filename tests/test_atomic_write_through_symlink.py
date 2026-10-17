"""Saving through a symlink writes the file the link points at.

Measured before: ``atomic_write`` / ``atomic_write_stream`` wrote a temp
file next to the LINK and renamed it over the link path. ``~/.bashrc ->
dotfiles/bashrc`` saved from the editor turned into a regular file, the
real target kept its old content, and the new file got the symlink's
lstat mode 0777 (world-writable) because the previous mode was read with
lstat from the link.

Now the destination is resolved first: the temp goes next to the final
target, the target's own mode is kept, and the link stays a link.
"""

from __future__ import annotations

import errno
import io
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.atomic_io import atomic_write, atomic_write_stream  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


@unittest.skipUnless(hasattr(os, "symlink") and os.name == "posix", "POSIX symlinks")
class AtomicWriteThroughSymlinkTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.fs = LocalFS()
        (self.tmp / "dotfiles").mkdir()
        self.target = self.tmp / "dotfiles" / "bashrc"
        self.target.write_bytes(b"old\n")
        os.chmod(self.target, 0o640)
        self.link = self.tmp / ".bashrc"
        os.symlink(self.target, self.link)

    def _assert_saved_through(self, link: Path, target: Path, data: bytes) -> None:
        self.assertTrue(stat.S_ISLNK(os.lstat(link).st_mode), "the link was replaced")
        self.assertEqual(target.read_bytes(), data)
        self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o640)

    def _leftovers(self) -> list[str]:
        return sorted(
            p.name
            for d in (self.tmp, self.tmp / "dotfiles")
            for p in d.iterdir()
            if p.name.startswith(".tmp-")
        )

    def test_happy_atomic_write_updates_the_target_and_keeps_the_link(self) -> None:
        atomic_write(self.fs, str(self.link), b"new\n")
        self._assert_saved_through(self.link, self.target, b"new\n")
        self.assertEqual(self._leftovers(), [])

    def test_happy_atomic_write_stream_updates_the_target_and_keeps_the_link(self) -> None:
        atomic_write_stream(self.fs, str(self.link), io.BytesIO(b"streamed\n"))
        self._assert_saved_through(self.link, self.target, b"streamed\n")

    def test_happy_a_plain_file_keeps_its_mode_as_before(self) -> None:
        atomic_write(self.fs, str(self.target), b"direct\n")
        self.assertEqual(self.target.read_bytes(), b"direct\n")
        self.assertEqual(stat.S_IMODE(os.stat(self.target).st_mode), 0o640)

    def test_edge_a_relative_link_resolves_against_its_own_folder(self) -> None:
        rel = self.tmp / "rel-link"
        os.symlink("dotfiles/bashrc", rel)
        atomic_write(self.fs, str(rel), b"rel\n")
        self._assert_saved_through(rel, self.target, b"rel\n")

    def test_edge_a_chain_of_links_ends_at_the_file(self) -> None:
        second = self.tmp / "second"
        os.symlink(self.link, second)
        atomic_write(self.fs, str(second), b"chain\n")
        self.assertTrue(stat.S_ISLNK(os.lstat(second).st_mode))
        self._assert_saved_through(self.link, self.target, b"chain\n")

    def test_edge_a_dangling_link_creates_its_target(self) -> None:
        dangling = self.tmp / "dangling"
        new_target = self.tmp / "dotfiles" / "new.conf"
        os.symlink(new_target, dangling)
        atomic_write(self.fs, str(dangling), b"fresh\n")
        self.assertTrue(stat.S_ISLNK(os.lstat(dangling).st_mode))
        self.assertEqual(new_target.read_bytes(), b"fresh\n")
        # A new file gets the default mode, never the link's 0777.
        self.assertNotEqual(stat.S_IMODE(os.stat(new_target).st_mode) & 0o002, 0o002)

    def test_sad_a_link_loop_fails_and_changes_nothing(self) -> None:
        a, b = self.tmp / "loop-a", self.tmp / "loop-b"
        os.symlink(b, a)
        os.symlink(a, b)
        with self.assertRaises(OSError) as ctx:
            atomic_write(self.fs, str(a), b"x")
        self.assertEqual(ctx.exception.errno, errno.ELOOP)
        self.assertTrue(stat.S_ISLNK(os.lstat(a).st_mode))
        self.assertTrue(stat.S_ISLNK(os.lstat(b).st_mode))
        self.assertEqual(self._leftovers(), [])

    def test_sad_a_link_that_cannot_be_read_is_written_through_not_replaced(self) -> None:
        class _NoReadlink(LocalFS):
            def readlink(self, path):
                raise OSError(errno.EPERM, "readlink not permitted")

        atomic_write(_NoReadlink(), str(self.link), b"through\n")
        self._assert_saved_through(self.link, self.target, b"through\n")


if __name__ == "__main__":
    unittest.main()
