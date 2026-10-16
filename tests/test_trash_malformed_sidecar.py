"""One malformed trash sidecar no longer makes the whole trash unlistable.

Found in review: ``list_trash`` coerced ``size`` with a bare ``int()``
(ValueError / TypeError / OverflowError for "big", [1], 1e400), sorted
naive local timestamps together with a timezone-aware one (TypeError) and
``_read_meta`` let a deeply nested sidecar raise RecursionError. Any of
these escaped list_trash; the Trash browser catches only OSError, so one
such file on a server - written by another tool or planted - hid every
other entry and left nothing restorable from the UI.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import trash as T  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


class MalformedSidecarTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.fs = LocalFS()
        self.ids = []
        for i in range(3):
            p = self.tmp / f"f{i}.txt"
            p.write_text("x" * (i + 1))
            self.ids.append(T.trash(self.fs, str(p), root=str(self.tmp)))
        self.trash_dir = Path(T._resolve_root(self.fs, str(self.tmp)))

    def meta(self, trash_id: str) -> Path:
        return self.trash_dir / f"{trash_id}{T.META_SUFFIX}"

    def patch_meta(self, trash_id: str, **fields) -> None:
        data = json.loads(self.meta(trash_id).read_text())
        data.update(fields)
        self.meta(trash_id).write_text(json.dumps(data))

    def listed(self):
        return T.list_trash(self.fs, root=str(self.tmp))

    def test_happy_well_formed_sidecars_are_listed_with_their_sizes(self) -> None:
        entries = {e.trash_id: e for e in self.listed()}
        self.assertEqual(sorted(entries), sorted(self.ids))
        self.assertEqual(sorted(e.size for e in entries.values()), [1, 2, 3])

    def test_sad_a_size_of_the_wrong_type_keeps_the_entry_restorable(self) -> None:
        for size in ("big", [1], {"a": 1}, 1e400, -5):
            with self.subTest(size=size):
                if size == 1e400:
                    data = json.loads(self.meta(self.ids[0]).read_text())
                    data["size"] = "INF"
                    raw = json.dumps(data).replace('"INF"', "1e400")
                    self.meta(self.ids[0]).write_text(raw)
                else:
                    self.patch_meta(self.ids[0], size=size)
                entries = {e.trash_id: e for e in self.listed()}
                self.assertEqual(sorted(entries), sorted(self.ids))
                self.assertEqual(entries[self.ids[0]].size, 0)
                self.patch_meta(self.ids[0], size=1)

    def test_sad_a_timezone_aware_timestamp_does_not_break_the_order(self) -> None:
        self.patch_meta(self.ids[1], trashed_at="2000-01-01T00:00:00+05:00")
        entries = self.listed()
        self.assertEqual(sorted(e.trash_id for e in entries), sorted(self.ids))
        self.assertEqual(entries[-1].trash_id, self.ids[1], "the oldest entry sorts last")
        self.assertIsNone(entries[-1].trashed_at.tzinfo)

    def test_edge_a_deeply_nested_sidecar_is_skipped_alone(self) -> None:
        self.meta(self.ids[2]).write_text("[" * (T.MAX_META_SIZE - 1))
        self.assertEqual(sorted(e.trash_id for e in self.listed()), sorted(self.ids[:2]))

    def test_edge_wrong_typed_text_fields_are_listed_as_text(self) -> None:
        self.patch_meta(self.ids[0], original_path=["a"], trashed_at=5, label=None)
        entry = {e.trash_id: e for e in self.listed()}[self.ids[0]]
        self.assertEqual(entry.original_path, "")
        self.assertIsInstance(entry.trashed_at, datetime)


if __name__ == "__main__":
    unittest.main()
