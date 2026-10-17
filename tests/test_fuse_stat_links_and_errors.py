"""What getattr reports for a symlink and for a stat that failed.

Measured before, on a FUSE mount of LocalFS:

* ``latest.tar -> release-1.2.3.tar`` (100 000 bytes) had st_size 17 -
  the length of the link text, since the backend's stat is an lstat and
  _stat_dict ignored is_link - while reads served the target. ``cp``
  produced a 17-byte file. A link to a folder was shown as a file.
* One transient stat failure (a timeout) was answered ENOENT; ``echo x
  >> log.txt`` then went through create() with an empty buffer and the
  commit replaced the whole file with "x".

A link now reports its target's attributes, and only "not found" is
ENOENT; any other failure is EIO and nothing is created.
"""

from __future__ import annotations

import errno
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import fuse_mount as FM  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


class _FlakyFS(LocalFS):
    """stat() of one name fails once with *exc*, like a network hiccup."""

    def __init__(self, exc: OSError) -> None:
        super().__init__()
        self.exc = exc
        self.left = 1

    def stat(self, path):
        if path.endswith("log.txt") and self.left:
            self.left -= 1
            raise self.exc
        return super().stat(path)


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def fuse(self, fs=None) -> FM.BackendFuseFS:
        return FM.BackendFuseFS(fs or LocalFS(), str(self.tmp), writeable=True, ttl_stat=0,
                                ttl_listing=0)


class SymlinkStatTest(_Base):
    def setUp(self) -> None:
        super().setUp()
        (self.tmp / "release.tar").write_bytes(b"x" * 100_000)
        os.symlink("release.tar", self.tmp / "latest.tar")
        (self.tmp / "real-dir").mkdir()
        os.symlink("real-dir", self.tmp / "dir-link")

    def test_happy_a_link_to_a_file_has_the_target_size(self) -> None:
        attrs = self.fuse().getattr("/latest.tar")
        self.assertTrue(stat.S_ISREG(attrs["st_mode"]))
        self.assertEqual(attrs["st_size"], 100_000)

    def test_happy_a_link_to_a_folder_is_a_folder(self) -> None:
        self.assertTrue(stat.S_ISDIR(self.fuse().getattr("/dir-link")["st_mode"]))

    def test_edge_a_listing_does_not_cache_the_link_size(self) -> None:
        fs = self.fuse()
        list(fs.readdir("/", None))
        self.assertEqual(fs.getattr("/latest.tar")["st_size"], 100_000)

    def test_edge_a_chain_of_links_and_an_absolute_link(self) -> None:
        os.symlink("latest.tar", self.tmp / "chain.tar")
        os.symlink(self.tmp / "release.tar", self.tmp / "abs.tar")
        fs = self.fuse()
        self.assertEqual(fs.getattr("/chain.tar")["st_size"], 100_000)
        self.assertEqual(fs.getattr("/abs.tar")["st_size"], 100_000)

    def test_sad_a_dangling_link_is_not_found(self) -> None:
        os.symlink("gone.tar", self.tmp / "dangling.tar")
        with self.assertRaises(OSError) as ctx:
            self.fuse().getattr("/dangling.tar")
        self.assertEqual(ctx.exception.errno, errno.ENOENT)

    def test_sad_a_link_loop_is_an_error_not_a_hang(self) -> None:
        os.symlink("loop-b", self.tmp / "loop-a")
        os.symlink("loop-a", self.tmp / "loop-b")
        with self.assertRaises(OSError) as ctx:
            self.fuse().getattr("/loop-a")
        self.assertIn(ctx.exception.errno, (errno.ELOOP, errno.ENOENT))


class StatErrorTest(_Base):
    def test_sad_a_timeout_is_eio_not_enoent(self) -> None:
        (self.tmp / "log.txt").write_bytes(b"line1\n")
        fs = self.fuse(_FlakyFS(OSError(errno.ETIMEDOUT, "Connection timed out")))
        with self.assertRaises(OSError) as ctx:
            fs.getattr("/log.txt")
        self.assertEqual(ctx.exception.errno, errno.EIO)

    def test_sad_a_socket_timeout_without_errno_is_eio(self) -> None:
        (self.tmp / "log.txt").write_bytes(b"line1\n")
        fs = self.fuse(_FlakyFS(TimeoutError("timed out")))
        with self.assertRaises(OSError) as ctx:
            fs.getattr("/log.txt")
        self.assertEqual(ctx.exception.errno, errno.EIO)

    def test_edge_permission_denied_is_eacces(self) -> None:
        (self.tmp / "log.txt").write_bytes(b"line1\n")
        fs = self.fuse(_FlakyFS(PermissionError(errno.EACCES, "denied")))
        with self.assertRaises(OSError) as ctx:
            fs.getattr("/log.txt")
        self.assertEqual(ctx.exception.errno, errno.EACCES)

    def test_happy_a_missing_file_is_still_enoent(self) -> None:
        with self.assertRaises(OSError) as ctx:
            self.fuse().getattr("/nothing.txt")
        self.assertEqual(ctx.exception.errno, errno.ENOENT)

    def test_edge_a_plain_not_found_error_without_errno_is_enoent(self) -> None:
        """Several backends say "not found" with a bare OSError."""
        fs = self.fuse(_FlakyFS(OSError("404 Not Found: log.txt")))
        with self.assertRaises(OSError) as ctx:
            fs.getattr("/log.txt")
        self.assertEqual(ctx.exception.errno, errno.ENOENT)


def _fuse_usable() -> bool:
    return (
        FM.FUSE_AVAILABLE
        and os.path.exists("/dev/fuse")
        and (shutil.which("fusermount3") or shutil.which("fusermount")) is not None
    )


@unittest.skipUnless(_fuse_usable(), "needs FUSE (fusepy, /dev/fuse, fusermount)")
class RealMountTest(_Base):
    def _mount(self, fs) -> Path:
        mnt = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, mnt, ignore_errors=True)
        handle = FM.mount(fs, str(mnt), root=str(self.tmp), writeable=True,
                          ttl_stat=0.0, ttl_listing=0.0)
        self.addCleanup(handle.unmount)
        for _ in range(50):
            if os.path.ismount(mnt):
                break
            time.sleep(0.1)
        if not os.path.ismount(mnt):
            self.skipTest("FUSE mount did not come up")
        return mnt

    def test_happy_a_file_read_through_a_link_is_whole(self) -> None:
        payload = os.urandom(100_000)
        (self.tmp / "release.tar").write_bytes(payload)
        os.symlink("release.tar", self.tmp / "latest.tar")
        mnt = self._mount(LocalFS())
        self.assertEqual((mnt / "latest.tar").read_bytes(), payload)

    def test_sad_an_append_after_a_stat_timeout_keeps_the_file(self) -> None:
        (self.tmp / "log.txt").write_bytes(b"line1\nline2\n")
        mnt = self._mount(_FlakyFS(OSError(errno.ETIMEDOUT, "Connection timed out")))
        subprocess.run(["sh", "-c", f"echo line3 >> '{mnt}/log.txt'"], capture_output=True,
                       timeout=30)
        time.sleep(0.3)
        content = (self.tmp / "log.txt").read_bytes()
        self.assertTrue(content.startswith(b"line1\nline2\n"), content)


if __name__ == "__main__":
    unittest.main()
