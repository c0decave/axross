"""An unreadable visit_history.json is kept, not overwritten.

Found in review: ``_load`` gave an empty history for a truncated or
non-list file, and the next ``record_visit`` - every connect - replaced
the file with that one new host, erasing the operator's trail of where
they had been. A non-UTF-8 file raised UnicodeDecodeError out of
``where_was_i`` (the scripting API's ``axross.where_was_i()``), because
only JSONDecodeError was caught.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import visit_history as VH  # noqa: E402


class UnreadableHistoryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "visit_history.json"
        patcher = mock.patch.object(VH, "HISTORY_FILE", self.path)
        patcher.start()
        self.addCleanup(patcher.stop)

    def copies(self) -> list[Path]:
        return sorted(self.path.parent.glob("visit_history.json.unreadable-*"))

    def test_happy_a_readable_history_grows_without_a_copy(self) -> None:
        VH.record_visit("sftp", "a", "u")
        VH.record_visit("sftp", "b", "u")
        self.assertEqual(sorted(v.host for v in VH.where_was_i()), ["a", "b"])
        self.assertEqual(self.copies(), [])

    def test_sad_recording_over_an_unreadable_file_keeps_a_copy_of_it(self) -> None:
        for content in (
            b'[{"protocol": "sftp", "host": "a", "username": "u", "last_seen": 1}, {"pro',
            b'[{"protocol": "sftp", "host": "\xff"}]',
            b'{"protocol": "sftp"}',
            b'[{"protocol": "sftp", "host": "a"}, 7]',
        ):
            with self.subTest(content=content[:30]):
                for old in self.copies():
                    old.unlink()
                self.path.write_bytes(content)
                VH.record_visit("sftp", "new", "u")
                self.assertEqual([c.read_bytes() for c in self.copies()], [content])
                self.assertIn("new", [v.host for v in VH.where_was_i()])

    def test_sad_no_save_when_the_unreadable_file_cannot_be_kept(self) -> None:
        self.path.write_bytes(b'[{"protocol": "sftp", "ho')
        with mock.patch.object(VH, "keep_unreadable_copy", return_value=False):
            VH.record_visit("sftp", "new", "u")  # never fails the caller
        self.assertEqual(self.path.read_bytes(), b'[{"protocol": "sftp", "ho')
        partial = json.dumps([{"protocol": "sftp", "host": "a"}, 7]).encode()
        self.path.write_bytes(partial)
        with mock.patch.object(VH, "keep_unreadable_copy", return_value=False):
            with self.assertRaises(OSError):
                VH.clear("a")
        self.assertEqual(self.path.read_bytes(), partial)

    def test_sad_clearing_one_host_from_a_partly_invalid_file_keeps_a_copy(self) -> None:
        partial = json.dumps(
            [{"protocol": "sftp", "host": "a"}, {"protocol": "sftp", "host": "b"}, "junk"]
        ).encode()
        self.path.write_bytes(partial)
        self.assertEqual(VH.clear("a"), 1)
        self.assertEqual([c.read_bytes() for c in self.copies()], [partial])
        self.assertEqual([v.host for v in VH.where_was_i()], ["b"])

    def test_edge_reading_a_non_utf8_file_gives_no_visits_and_changes_nothing(self) -> None:
        self.path.write_bytes(b'[{"host": "\xff"}]')
        self.assertEqual(VH.where_was_i(), [])
        self.assertIsNone(VH.where_was_i("x"))
        self.assertEqual(self.path.read_bytes(), b'[{"host": "\xff"}]')
        self.assertEqual(self.copies(), [])

    def test_edge_clearing_everything_needs_no_copy(self) -> None:
        self.path.write_text(json.dumps([{"protocol": "sftp", "host": "a"}]))
        self.assertEqual(VH.clear(), 1)
        self.assertFalse(self.path.exists())
        self.assertEqual(self.copies(), [])


if __name__ == "__main__":
    unittest.main()
