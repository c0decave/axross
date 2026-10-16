"""CAS rebuild / duplicates: faster, with the same results.

Measured before the change (10 000 files): every indexed file opened its
own SQLite connection, ran the schema script and committed; a second
rebuild re-hashed every unchanged file; ``duplicates`` ran one query and
one connection per group. Each speed-up below is held against a reference
that computes the answer the slow way.
"""

from __future__ import annotations

import dataclasses
import hashlib
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

from core import cas as CAS  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

BID = "LocalFS:Local"


def _rows(db) -> list[tuple]:
    with sqlite3.connect(str(db)) as conn:
        return sorted(
            conn.execute("SELECT backend_id, path, algorithm, value, size FROM cas").fetchall()
        )


def _reference_duplicates(db, algorithm: str = "sha256") -> list[list]:
    """The pre-optimisation algorithm: one SELECT per duplicate value."""
    with sqlite3.connect(str(db)) as conn:
        values = [
            r[0]
            for r in conn.execute(
                "SELECT value FROM cas WHERE algorithm=? GROUP BY value HAVING COUNT(*) >= 2",
                (algorithm,),
            )
        ]
        return [
            [
                (r[0], r[1])
                for r in conn.execute(
                    "SELECT backend_id, path FROM cas WHERE algorithm=? AND value=?",
                    (algorithm, v),
                )
            ]
            for v in values
        ]


class _Tree(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "tree"
        self.db = self.tmp / "cas.sqlite"
        self.fs = LocalFS()
        for d in range(4):
            for i in range(25):
                p = self.root / f"d{d}" / f"f{i}.bin"
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(b"dup-%d" % (i % 7) if i % 3 == 0 else b"u-%d-%d" % (d, i))

    def rebuild(self, **kw) -> int:
        return CAS.rebuild(self.fs, str(self.root), backend_id=BID, db_path=self.db, **kw)

    def _expected_rows(self) -> list[tuple]:
        out = []
        for dirpath, _dirs, files in os.walk(self.root):
            for name in files:
                p = Path(dirpath) / name
                data = p.read_bytes()
                out.append((BID, str(p), "sha256", hashlib.sha256(data).hexdigest(), len(data)))
        return sorted(out)


# --------------------------------------------------------------------------
# Same results
# --------------------------------------------------------------------------


class EquivalenceTest(_Tree):
    def test_happy_the_index_holds_exactly_the_hashes_of_the_tree(self) -> None:
        self.assertEqual(self.rebuild(), 100)
        self.assertEqual(_rows(self.db), self._expected_rows())

    def test_happy_duplicates_match_the_one_query_per_group_reference(self) -> None:
        self.rebuild()
        CAS.upsert(self.db, "Other:x", "/o/a", "md5", "abc", 1)
        CAS.upsert(self.db, "Other:x", "/o/b", "md5", "abc", 1)
        for algo in ("sha256", "md5", "etag"):
            # Same groups in the same (value) order; the rows of a group are
            # in survivor order now (tests/test_cas_survivor.py), so compare
            # them as sets.
            got = [{(e.backend_id, e.path) for e in g} for g in CAS.duplicates(self.db, algo)]
            want = [set(g) for g in _reference_duplicates(self.db, algo)]
            self.assertEqual(got, want, algo)

    def test_edge_duplicates_on_an_empty_index(self) -> None:
        self.assertEqual(CAS.duplicates(self.db), [])

    def test_edge_algorithm_name_is_case_insensitive(self) -> None:
        self.rebuild()
        self.assertEqual(len(CAS.duplicates(self.db, "SHA256")), len(CAS.duplicates(self.db)))


# --------------------------------------------------------------------------
# Fewer connections
# --------------------------------------------------------------------------


class BatchingTest(_Tree):
    def test_a_rebuild_does_not_open_a_connection_per_file(self) -> None:
        real = sqlite3.connect
        with mock.patch.object(CAS.sqlite3, "connect", side_effect=real) as conn:
            self.rebuild()
        self.assertLessEqual(conn.call_count, 5)

    def test_sad_a_crash_mid_walk_keeps_what_was_hashed(self) -> None:
        real = LocalFS.checksum
        calls = []

        def flaky(fs, path, algorithm="sha256"):
            calls.append(path)
            if len(calls) == 40:
                raise RuntimeError("backend exploded")
            return real(fs, path, algorithm)

        with mock.patch.object(LocalFS, "checksum", flaky), self.assertRaises(RuntimeError):
            self.rebuild()
        self.assertEqual(len(_rows(self.db)), 39)

    def test_edge_cancel_keeps_the_rows_indexed_so_far(self) -> None:
        seen = []
        n = self.rebuild(cancel=lambda: len(seen) >= 10, progress=lambda *a: seen.append(a))
        self.assertEqual(len(_rows(self.db)), n)
        self.assertGreaterEqual(n, 9)

    def test_edge_a_rejected_row_does_not_lose_the_batch(self) -> None:
        bad = self.root / "d0" / "f1.bin"
        real = LocalFS.checksum

        def odd(fs, path, algorithm="sha256"):
            return "sha256:" + "x" * 300 if path == str(bad) else real(fs, path, algorithm)

        with mock.patch.object(LocalFS, "checksum", odd):
            self.assertEqual(self.rebuild(), 99)
        self.assertEqual(len(_rows(self.db)), 99)


# --------------------------------------------------------------------------
# Unchanged files are not hashed again
# --------------------------------------------------------------------------


class IncrementalTest(_Tree):
    def _count_hashes(self, **kw) -> tuple[int, int]:
        real = LocalFS.checksum
        hashed = []

        def counting(fs, path, algorithm="sha256"):
            hashed.append(path)
            return real(fs, path, algorithm)

        with mock.patch.object(LocalFS, "checksum", counting):
            n = self.rebuild(**kw)
        return n, len(hashed)

    def test_happy_a_second_rebuild_hashes_nothing_unchanged(self) -> None:
        self.rebuild()
        self.assertEqual(self._count_hashes(), (100, 0))
        self.assertEqual(_rows(self.db), self._expected_rows())

    def test_sad_a_changed_file_is_hashed_again(self) -> None:
        self.rebuild()
        p = self.root / "d1" / "f2.bin"
        p.write_bytes(b"new content, other size")
        self.assertEqual(self._count_hashes(), (100, 1))
        self.assertEqual(_rows(self.db), self._expected_rows())

    def test_sad_same_size_but_a_new_mtime_is_hashed_again(self) -> None:
        self.rebuild()
        p = self.root / "d1" / "f2.bin"
        old = p.read_bytes()
        p.write_bytes(bytes(reversed(old)))
        st = p.stat()
        os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 2_000_000_000))
        self.assertEqual(self._count_hashes(), (100, 1))
        self.assertEqual(_rows(self.db), self._expected_rows())

    def test_edge_rehash_forces_every_file(self) -> None:
        self.rebuild()
        self.assertEqual(self._count_hashes(rehash=True), (100, 100))

    def test_edge_a_backend_without_mtimes_is_always_hashed(self) -> None:
        class NoMtime(LocalFS):
            def list_dir(self, path):
                epoch = datetime.fromtimestamp(0)
                return [dataclasses.replace(it, modified=epoch) for it in super().list_dir(path)]

        self.fs = NoMtime()
        self.rebuild()
        self.assertEqual(self._count_hashes()[1], 100)

    def test_edge_an_old_index_without_mtimes_is_migrated_and_rehashed_once(self) -> None:
        with sqlite3.connect(str(self.db)) as conn:
            conn.execute(
                "CREATE TABLE cas (backend_id TEXT NOT NULL, path TEXT NOT NULL, "
                "algorithm TEXT NOT NULL, value TEXT NOT NULL, size INTEGER NOT NULL "
                "DEFAULT 0, indexed_at TEXT NOT NULL, PRIMARY KEY (backend_id, path, algorithm))"
            )
            conn.execute(
                "INSERT INTO cas VALUES (?, ?, 'sha256', 'stale', 1, '2026-01-01T00:00:00')",
                (BID, str(self.root / "d0" / "f0.bin")),
            )
        self.assertEqual(self._count_hashes(), (100, 100))
        self.assertEqual(_rows(self.db), self._expected_rows())
        self.assertEqual(self._count_hashes(), (100, 0))

    def test_edge_the_first_rebuild_does_not_create_the_db_before_the_walk(self) -> None:
        # An index stored inside the scanned tree must not index itself.
        self.db = self.root / "cas.sqlite"
        self.assertEqual(self.rebuild(), 100)


# --------------------------------------------------------------------------
# Verification before deleting: cheap reject first
# --------------------------------------------------------------------------


class StillHoldsTest(_Tree):
    def test_a_size_mismatch_is_rejected_without_hashing(self) -> None:
        self.rebuild()
        p = self.root / "d2" / "f4.bin"
        entry = next(e for e in CAS.list_for_backend(self.db, BID) if e.path == str(p))
        p.write_bytes(b"longer than before, definitely")
        with mock.patch.object(LocalFS, "checksum") as chk:
            self.assertFalse(CAS._still_holds(self.fs, entry))
        chk.assert_not_called()

    def test_an_intact_file_still_passes(self) -> None:
        self.rebuild()
        entry = CAS.list_for_backend(self.db, BID)[0]
        self.assertTrue(CAS._still_holds(self.fs, entry))


if __name__ == "__main__":
    unittest.main()
