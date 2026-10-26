"""record_visit reads visit_history.json once and encodes it in C.

Every mutating scripting call on a profile's backend (copy, move, remove,
write, read ...) records a visit, two for copy and move. Each record read
the whole history twice - once to update it, once more inside ``_save`` to
learn whether the file had been taken in completely - and wrote it through
``json.dump``, which streams through the pure-Python encoder: 28 ms per
call with a full history (200 hosts x 20 operations, 0.5 MB), measured.
Now the completeness found by the first read is handed to ``_save`` and
the text is encoded with ``json.dumps`` (the C encoder, the same bytes).
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import visit_history as VH  # noqa: E402


class _Counting:
    """Counts the reads of the history file and its replacements."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.reads = 0
        self.writes = 0

    def __enter__(self):
        read_text, replace = Path.read_text, VH.os.replace
        counter = self

        def counted_read(p, *a, **kw):
            if Path(p) == counter.path:
                counter.reads += 1
            return read_text(p, *a, **kw)

        def counted_replace(src, dst, *a, **kw):
            if Path(dst) == counter.path:
                counter.writes += 1
            return replace(src, dst, *a, **kw)

        self._patches = [mock.patch.object(Path, "read_text", counted_read),
                         mock.patch.object(VH.os, "replace", counted_replace)]
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc) -> None:
        for p in self._patches:
            p.stop()


def _full_history(hosts: int = 200) -> list[dict]:
    return [{
        "protocol": "sftp", "host": f"host{h}.example", "username": "alice",
        "last_path": f"/var/log/app{h}", "last_seen": 1_700_000_000.5 + h, "visit_count": 20,
        "recent_ops": [{"ts": 1_700_000_000.25 + h, "verb": "copy",
                        "desc": f"copy /srv/data/fïle{k}.txt"} for k in range(20)],
    } for h in range(hosts)]


class RecordVisitCostTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "visit_history.json"
        patcher = mock.patch.object(VH, "HISTORY_FILE", self.path)
        patcher.start()
        self.addCleanup(patcher.stop)

    def copies(self) -> list[Path]:
        return sorted(self.path.parent.glob("visit_history.json.unreadable-*"))

    def test_happy_one_read_one_write_and_the_former_bytes(self) -> None:
        self.path.write_text(json.dumps(_full_history(), indent=2))
        with _Counting(self.path) as count:
            for i in range(5):
                VH.record_visit("sftp", "host7.example", "alice", path=f"/srv/f{i}",
                                verb="copy", desc=f"copy f{i}")
        self.assertEqual((count.reads, count.writes), (5, 5))
        text = self.path.read_text(encoding="utf-8")
        former = io.StringIO()
        json.dump(json.loads(text), former, indent=2)  # what the streaming writer wrote
        self.assertEqual(text, former.getvalue())
        newest = VH.where_was_i("host7.example")
        self.assertEqual((newest.last_path, newest.visit_count, newest.recent_ops[0]["desc"]),
                         ("/srv/f4", 25, "copy f4"))
        self.assertEqual(len(VH.where_was_i()), 200)

    def test_sad_an_unreadable_file_is_still_kept_after_one_read(self) -> None:
        content = b'[{"protocol": "sftp", "host": "a", "username": "u", "last_seen": 1}, 7]'
        self.path.write_bytes(content)
        with _Counting(self.path) as count:
            VH.record_visit("sftp", "new", "u")
        self.assertEqual((count.reads, count.writes), (1, 1))
        self.assertEqual([c.read_bytes() for c in self.copies()], [content])
        self.assertEqual(sorted(v.host for v in VH.where_was_i()), ["a", "new"])

    def test_sad_no_write_when_the_unreadable_file_cannot_be_kept(self) -> None:
        self.path.write_bytes(b'[{"protocol": "sftp", "ho')
        with mock.patch.object(VH, "keep_unreadable_copy", return_value=False), \
                _Counting(self.path) as count:
            VH.record_visit("sftp", "new", "u")  # never fails the caller
        self.assertEqual((count.reads, count.writes), (1, 0))
        self.assertEqual(self.path.read_bytes(), b'[{"protocol": "sftp", "ho')
        partial = json.dumps([{"protocol": "sftp", "host": "a"}, 7]).encode()
        self.path.write_bytes(partial)
        with mock.patch.object(VH, "keep_unreadable_copy", return_value=False), \
                _Counting(self.path) as count:
            with self.assertRaises(OSError):
                VH.clear("a")
        self.assertEqual((count.reads, count.writes), (1, 0))
        self.assertEqual(self.path.read_bytes(), partial)

    def test_edge_no_file_yet_and_clearing_one_host_read_at_most_once(self) -> None:
        with _Counting(self.path) as count:
            VH.record_visit("sftp", "a", "u")
            VH.record_visit("sftp", "b", "u")
        self.assertEqual((count.reads, count.writes), (1, 2))  # the first found no file
        with _Counting(self.path) as count:
            self.assertEqual(VH.clear("a"), 1)
        self.assertEqual((count.reads, count.writes), (1, 1))
        self.assertEqual([v.host for v in VH.where_was_i()], ["b"])

    def test_edge_a_file_that_changed_meanwhile_is_not_judged_by_an_old_read(self) -> None:
        """The completeness handed to _save is the one of the read made under
        the same lock; a _save without it still reads the file itself."""
        self.path.write_bytes(b'[{"protocol": "sftp", "host": "a"}, 7]')
        with VH._locked_history_update():
            VH._save({}, complete=True)  # the caller vouches for the file
        self.assertEqual(self.copies(), [])
        self.path.write_bytes(b'[{"protocol": "sftp", "host": "a"}, 7]')
        with VH._locked_history_update():
            VH._save({})  # nobody vouches: read and keep a copy, as before
        self.assertEqual(len(self.copies()), 1)


if __name__ == "__main__":
    unittest.main()
