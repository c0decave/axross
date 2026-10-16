"""core.secure_storage.keep_unreadable_copy: a store file its loader could
not read is copied aside before a save replaces it."""

from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import secure_storage as SS  # noqa: E402


class KeepUnreadableCopyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.path = self.dir / "store.json"

    def _copies(self) -> list[Path]:
        return sorted(self.dir.glob("store.json.unreadable-*"))

    def test_happy_the_copy_holds_the_original_bytes_and_is_private(self) -> None:
        self.path.write_bytes(b'{"truncated": ')
        os.chmod(self.path, 0o644)
        self.assertTrue(SS.keep_unreadable_copy(self.path))
        copies = self._copies()
        self.assertEqual(len(copies), 1)
        self.assertEqual(copies[0].read_bytes(), b'{"truncated": ')
        self.assertEqual(stat.S_IMODE(copies[0].stat().st_mode), 0o600)
        self.assertEqual(self.path.read_bytes(), b'{"truncated": ', "the original stays")

    def test_sad_a_copy_that_cannot_be_made_says_so(self) -> None:
        self.path.write_bytes(b"\xff\xfe")
        with mock.patch.object(SS.os, "open", side_effect=PermissionError("read-only dir")):
            self.assertFalse(SS.keep_unreadable_copy(self.path))
        self.assertEqual(self._copies(), [])

    def test_sad_a_failed_write_removes_the_partial_copy(self) -> None:
        self.path.write_bytes(b"x" * 10)
        with mock.patch.object(SS.shutil, "copyfileobj", side_effect=OSError("disk full")):
            self.assertFalse(SS.keep_unreadable_copy(self.path))
        self.assertEqual(self._copies(), [])

    def test_edge_no_file_means_nothing_to_keep(self) -> None:
        self.assertTrue(SS.keep_unreadable_copy(self.path))
        self.assertEqual(self._copies(), [])

    def test_edge_two_copies_in_the_same_second_do_not_collide(self) -> None:
        self.path.write_bytes(b"one")
        self.assertTrue(SS.keep_unreadable_copy(self.path))
        self.path.write_bytes(b"two")
        self.assertTrue(SS.keep_unreadable_copy(self.path))
        self.assertEqual(sorted(p.read_bytes() for p in self._copies()), [b"one", b"two"])


if __name__ == "__main__":
    unittest.main()
