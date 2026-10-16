"""An unreadable bookmarks file is set aside, never overwritten.

Measured before: a bookmarks.json that failed to parse (a hand edit with a
trailing comma, a half-synced copy) was logged and the manager started
empty. The next change -- adding one bookmark -- saved that empty tree over
the file, destroying every bookmark it still held. A file that was not
UTF-8 was worse: the UnicodeDecodeError escaped ``load`` and
``BookmarkManager()`` raised, which the main window does at startup.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import bookmarks as BM  # noqa: E402

_BROKEN = b'[{"name": "prod logs", "path": "/var/log", "backend_name": "Local"},]'


class UnreadableBookmarksTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.file = self.tmp / "bookmarks.json"
        patcher = mock.patch.object(BM, "BOOKMARKS_FILE", self.file)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _set_aside(self) -> list[Path]:
        return sorted(p for p in self.tmp.iterdir() if p.name.startswith("bookmarks.json.unreadable-"))

    def test_happy_a_valid_file_loads_and_saves_without_a_side_copy(self) -> None:
        mgr = BM.BookmarkManager()
        mgr.add(BM.Bookmark(name="home", path="/home"))
        again = BM.BookmarkManager()
        self.assertEqual([b.name for b in again.all()], ["home"])
        self.assertEqual(self._set_aside(), [])

    def test_sad_a_broken_file_survives_the_next_save(self) -> None:
        self.file.write_bytes(_BROKEN)
        mgr = BM.BookmarkManager()
        self.assertEqual(mgr.all(), [])
        mgr.add(BM.Bookmark(name="new", path="/tmp"))

        kept = self._set_aside()
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0].read_bytes(), _BROKEN)
        self.assertEqual([b.name for b in BM.BookmarkManager().all()], ["new"])

    def test_sad_a_non_utf8_file_does_not_stop_the_manager(self) -> None:
        raw = b"\xff\xfe\x00not json"
        self.file.write_bytes(raw)
        mgr = BM.BookmarkManager()
        self.assertEqual(mgr.all(), [])
        self.assertEqual([p.read_bytes() for p in self._set_aside()], [raw])

    def test_edge_a_json_object_instead_of_a_list_is_set_aside(self) -> None:
        self.file.write_text('{"name": "x"}', encoding="utf-8")
        BM.BookmarkManager().add(BM.Bookmark(name="y", path="/y"))
        self.assertEqual([p.read_text() for p in self._set_aside()], ['{"name": "x"}'])

    def test_edge_no_file_at_all_sets_nothing_aside(self) -> None:
        mgr = BM.BookmarkManager()
        self.assertEqual(mgr.all(), [])
        self.assertEqual(self._set_aside(), [])

    def test_edge_two_broken_loads_keep_both_copies(self) -> None:
        self.file.write_bytes(b"[1,")
        BM.BookmarkManager()
        self.file.write_bytes(b"[2,")
        BM.BookmarkManager()
        self.assertEqual(sorted(p.read_bytes() for p in self._set_aside()), [b"[1,", b"[2,"])


if __name__ == "__main__":
    unittest.main()
