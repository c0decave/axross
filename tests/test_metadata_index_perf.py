"""Metadata index: one transaction per batch instead of one per entry.

Measured before the change: ``index_dir`` over 10 059 entries took 9.9 s,
most of it opening a SQLite connection, running the schema script and
committing once per entry. The rows written must stay exactly the same.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import metadata_index as MI  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

BID = "LocalFS:Local"


def _rows(db) -> list[tuple]:
    with sqlite3.connect(str(db)) as conn:
        return sorted(
            conn.execute(
                "SELECT backend_id, path, name, size, is_dir, extension, modified FROM metadata"
            ).fetchall()
        )


class _Tree(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "tree"
        self.db = self.tmp / "meta.sqlite"
        for d in range(3):
            for i in range(20):
                p = self.root / f"d{d}" / "sub" / f"f{i}.{'txt' if i % 2 else 'BIN'}"
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(b"x" * i)

    def index(self, **kw) -> int:
        return MI.index_dir(LocalFS(), str(self.root), backend_id=BID, db_path=self.db, **kw)

    def _expected(self) -> list[tuple]:
        out = []
        for dirpath, dirs, files in os.walk(self.root):
            for name in dirs + files:
                p = Path(dirpath) / name
                st = p.lstat()
                is_dir = p.is_dir()
                ext = "" if is_dir else MI._extension(name)
                mod = datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds")
                out.append((BID, str(p), name, 0 if is_dir else st.st_size, int(is_dir), ext, mod))
        return sorted(out)


class MetadataBatchTest(_Tree):
    def test_happy_rows_are_exactly_what_the_tree_holds(self) -> None:
        self.assertEqual(self.index(), 66)
        got = [r[:3] + (r[3] if not r[4] else 0,) + r[4:] for r in _rows(self.db)]
        self.assertEqual(got, self._expected())

    def test_happy_few_connections_for_a_whole_walk(self) -> None:
        real = sqlite3.connect
        with mock.patch.object(MI.sqlite3, "connect", side_effect=real) as conn:
            self.index()
        self.assertLessEqual(conn.call_count, 3)

    def test_sad_a_crash_mid_walk_keeps_the_rows_written_so_far(self) -> None:
        calls = []
        real = LocalFS.list_dir

        def flaky(fs, path):
            calls.append(path)
            if len(calls) == 4:
                raise RuntimeError("backend exploded")
            return real(fs, path)

        with mock.patch.object(LocalFS, "list_dir", flaky), self.assertRaises(RuntimeError):
            self.index()
        self.assertGreater(len(_rows(self.db)), 0)

    def test_edge_cancel_keeps_exactly_the_reported_rows(self) -> None:
        seen = []
        n = self.index(cancel=lambda: len(seen) >= 7, progress=lambda *a: seen.append(a))
        self.assertEqual(len(_rows(self.db)), n)

    def test_edge_a_rejected_entry_does_not_lose_the_batch(self) -> None:
        real = MI._checked_row
        target = str(self.root / "d1" / "sub" / "f3.txt")

        def picky(backend_id, path, **kw):
            if path == target:
                raise ValueError("refused")
            return real(backend_id, path, **kw)

        with mock.patch.object(MI, "_checked_row", picky):
            self.index()
        self.assertEqual(len(_rows(self.db)), 65)

    def test_edge_single_upsert_still_works(self) -> None:
        MI.upsert(self.db, BID, "/x/y.txt", name="y.txt", size=3, is_dir=False)
        self.assertEqual(_rows(self.db)[0][:6], (BID, "/x/y.txt", "y.txt", 3, 0, "txt"))


if __name__ == "__main__":
    unittest.main()
