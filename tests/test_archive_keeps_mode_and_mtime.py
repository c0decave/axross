"""An extracted archive member keeps its permission bits and time.

Measured before: extracting a tar gave 0644 and "now" for a 0755 tool from
2020 (archive.py wrote every member with ``open(dest, "wb")``). A member
is created with its own rwx bits less the umask - never set-id, never
wider than stored - so a 0600 member is never readable by others, even
while it is written.
"""

from __future__ import annotations

import io
import os
import shutil
import stat
import sys
import tarfile
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import archive as A  # noqa: E402

OLD = 1_600_000_000


def _mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        old = os.umask(0o022)
        self.addCleanup(os.umask, old)


def _tar_with(path: Path, name: str, data: bytes, mode: int, mtime: int) -> None:
    with tarfile.open(path, "w:gz") as tf:
        info = tarfile.TarInfo(name)
        info.size, info.mode, info.mtime = len(data), mode, mtime
        tf.addfile(info, io.BytesIO(data))


class ExtractTest(_Base):
    def setUp(self) -> None:
        super().setUp()
        self.target = self.tmp / "x"

    def test_happy_a_tar_member_keeps_its_mode_and_time(self) -> None:
        arc = self.tmp / "tool.tar.gz"
        _tar_with(arc, "tool/run.sh", b"#!/bin/sh\n", 0o755, OLD)
        A.extract(str(arc), str(self.target))
        dst = self.target / "tool" / "run.sh"
        self.assertEqual(_mode(dst), 0o755)
        self.assertEqual(os.stat(dst).st_mtime, OLD)

    def test_sad_a_private_tar_member_stays_private(self) -> None:
        arc = self.tmp / "k.tar.gz"
        _tar_with(arc, "id_ed25519", b"key", 0o600, OLD)
        A.extract(str(arc), str(self.target))
        self.assertEqual(_mode(self.target / "id_ed25519"), 0o600)

    def test_edge_a_world_writable_setuid_member_is_narrowed(self) -> None:
        arc = self.tmp / "w.tar.gz"
        _tar_with(arc, "w", b"w", 0o4777, OLD)
        A.extract(str(arc), str(self.target))
        self.assertEqual(_mode(self.target / "w"), 0o755)

    def test_edge_partial_extraction_keeps_mode_too(self) -> None:
        arc = self.tmp / "p.tar.gz"
        _tar_with(arc, "d/run.sh", b"x", 0o700, OLD)
        A.extract_members(str(arc), str(self.target), ["d"])
        self.assertEqual(_mode(self.target / "d" / "run.sh"), 0o700)

    def test_happy_a_zip_from_unix_keeps_mode_and_time(self) -> None:
        arc = self.tmp / "z.zip"
        info = zipfile.ZipInfo("bin/tool", date_time=(2020, 1, 2, 3, 4, 6))
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | 0o750) << 16
        with zipfile.ZipFile(arc, "w") as zf:
            zf.writestr(info, b"z")
        A.extract(str(arc), str(self.target))
        dst = self.target / "bin" / "tool"
        self.assertEqual(_mode(dst), 0o750)
        self.assertEqual(time.localtime(os.stat(dst).st_mtime)[:6], (2020, 1, 2, 3, 4, 6))

    def test_edge_a_zip_without_unix_mode_gets_the_default(self) -> None:
        arc = self.tmp / "w.zip"
        with zipfile.ZipFile(arc, "w") as zf:
            info = zipfile.ZipInfo("f.txt", date_time=(2020, 1, 2, 3, 4, 6))
            info.create_system = 0  # MS-DOS: no Unix mode stored
            zf.writestr(info, b"z")
        A.extract(str(arc), str(self.target))
        self.assertEqual(_mode(self.target / "f.txt"), 0o644)


if __name__ == "__main__":
    unittest.main()
