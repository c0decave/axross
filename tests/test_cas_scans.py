"""Duplicate index history: every rebuild is a recorded scan.

The index can be inspected on its own: which scans built it (root, backend,
start / end, files, duplicate groups, status), the duplicates of one scan or
of one folder, removing one scan from the index, clearing the whole index.
An index written before scans were recorded is migrated in place; its rows
belong to an "earlier scans" pseudo entry.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import cas as CAS  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

BID = "LocalFS:Local"

# The schema as it shipped before modification times were stored.
OLD_SCHEMA = (
    "CREATE TABLE cas (backend_id TEXT NOT NULL, path TEXT NOT NULL, "
    "algorithm TEXT NOT NULL, value TEXT NOT NULL, size INTEGER NOT NULL "
    "DEFAULT 0, indexed_at TEXT NOT NULL, PRIMARY KEY (backend_id, path, algorithm))"
)
# The schema with mtime, before scans were recorded.
MTIME_SCHEMA = (
    "CREATE TABLE cas (backend_id TEXT NOT NULL, path TEXT NOT NULL, "
    "algorithm TEXT NOT NULL, value TEXT NOT NULL, size INTEGER NOT NULL DEFAULT 0, "
    "indexed_at TEXT NOT NULL, mtime REAL, PRIMARY KEY (backend_id, path, algorithm))"
)


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.db = self.tmp / "cas.sqlite"
        self.fs = LocalFS()

    def _tree(self, name: str, files: dict[str, bytes]) -> Path:
        root = self.tmp / name
        for rel, data in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        return root

    def rebuild(self, root: Path, **kw) -> int:
        return CAS.rebuild(self.fs, str(root), backend_id=BID, db_path=self.db, **kw)


# --------------------------------------------------------------------------
# Migration of existing databases
# --------------------------------------------------------------------------


class MigrationTest(_Base):
    def _old_db(self, schema: str, rows: list[tuple]) -> None:
        with sqlite3.connect(str(self.db)) as conn:
            conn.execute(schema)
            for row in rows:
                conn.execute(
                    f"INSERT INTO cas VALUES ({', '.join('?' * len(row))})",
                    row,
                )

    def test_happy_an_old_schema_database_opens_and_its_rows_are_earlier_scans(self) -> None:
        self._old_db(
            OLD_SCHEMA,
            [
                (BID, "/x/a", "sha256", "v1", 3, "2026-01-01T00:00:00"),
                (BID, "/x/b", "sha256", "v1", 3, "2026-01-01T00:00:00"),
                (BID, "/x/c", "sha256", "v2", 3, "2026-01-01T00:00:00"),
            ],
        )
        (group,) = CAS.duplicates(self.db)
        self.assertEqual({e.path for e in group}, {"/x/a", "/x/b"})
        self.assertTrue(all(e.mtime is None and e.scan_id is None for e in group))
        scans = CAS.list_scans(self.db)
        self.assertEqual(len(scans), 1)
        earlier = scans[0]
        self.assertEqual(earlier.scan_id, CAS.EARLIER_SCANS)
        self.assertEqual(earlier.status, CAS.SCAN_EARLIER)
        self.assertEqual(earlier.files_in_index, 3)
        self.assertEqual(earlier.duplicate_groups, 1)
        with sqlite3.connect(str(self.db)) as conn:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(cas)")}
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
        self.assertTrue({"mtime", "scan_id"} <= cols)
        self.assertIn("scans", tables)

    def test_happy_a_rebuild_fills_mtime_and_moves_rows_into_a_scan(self) -> None:
        root = self._tree("t", {"a": b"same", "b": b"same"})
        self._old_db(
            OLD_SCHEMA,
            [(BID, str(root / "a"), "sha256", "stale", 4, "2026-01-01T00:00:00")],
        )
        self.rebuild(root)
        (group,) = CAS.duplicates(self.db)
        self.assertTrue(all(e.mtime is not None for e in group))
        scans = CAS.list_scans(self.db)
        self.assertEqual([s.status for s in scans], [CAS.SCAN_COMPLETE])  # no rows left over
        self.assertEqual({e.scan_id for e in group}, {scans[0].scan_id})

    def test_edge_the_mtime_schema_is_migrated_too(self) -> None:
        self._old_db(
            MTIME_SCHEMA,
            [
                (BID, "/m/a", "sha256", "v", 1, "2026-01-01T00:00:00", 5.0),
                (BID, "/m/b", "sha256", "v", 1, "2026-01-01T00:00:00", 4.0),
            ],
        )
        (group,) = CAS.duplicates(self.db)
        self.assertEqual([e.path for e in group], ["/m/b", "/m/a"])  # older first
        self.assertEqual(CAS.list_scans(self.db)[0].scan_id, CAS.EARLIER_SCANS)

    def test_sad_migration_runs_once_and_is_idempotent(self) -> None:
        self._old_db(OLD_SCHEMA, [])
        for _ in range(3):
            self.assertEqual(CAS.duplicates(self.db), [])
        self.assertEqual(CAS.list_scans(self.db), [])


# --------------------------------------------------------------------------
# Scans are recorded
# --------------------------------------------------------------------------


class ScanRecordTest(_Base):
    def test_happy_a_complete_rebuild_is_recorded(self) -> None:
        root = self._tree("t", {"a": b"x", "b": b"x", "c": b"y"})
        self.assertEqual(self.rebuild(root), 3)
        (scan,) = CAS.list_scans(self.db)
        self.assertEqual(scan.status, CAS.SCAN_COMPLETE)
        self.assertEqual((scan.root, scan.backend_id, scan.algorithm), (str(root), BID, "sha256"))
        self.assertEqual(scan.files_indexed, 3)
        self.assertEqual(scan.files_in_index, 3)
        self.assertEqual(scan.duplicate_groups, 1)
        self.assertIsNotNone(scan.started_at)
        self.assertIsNotNone(scan.finished_at)
        self.assertLessEqual(scan.started_at, scan.finished_at)

    def test_happy_a_cancelled_rebuild_is_recorded_as_cancelled(self) -> None:
        root = self._tree("t", {f"f{i}": b"%d" % i for i in range(10)})
        seen = []
        n = self.rebuild(root, cancel=lambda: len(seen) >= 3, progress=lambda *a: seen.append(a))
        (scan,) = CAS.list_scans(self.db)
        self.assertEqual(scan.status, CAS.SCAN_CANCELLED)
        self.assertEqual(scan.files_indexed, n)

    def test_sad_a_cancel_before_any_file_still_records_the_scan(self) -> None:
        root = self._tree("t", {"a": b"x"})
        self.assertEqual(self.rebuild(root, cancel=lambda: True), 0)
        (scan,) = CAS.list_scans(self.db)
        self.assertEqual((scan.status, scan.files_indexed), (CAS.SCAN_CANCELLED, 0))

    def test_sad_a_failed_rebuild_is_recorded_as_failed_and_still_raises(self) -> None:
        root = self._tree("t", {"a": b"x", "b": b"y"})
        with (
            mock.patch.object(LocalFS, "checksum", side_effect=RuntimeError("exploded")),
            self.assertRaises(RuntimeError),
        ):
            self.rebuild(root)
        (scan,) = CAS.list_scans(self.db)
        self.assertEqual(scan.status, CAS.SCAN_FAILED)
        self.assertIn("exploded", scan.error)

    def test_edge_newest_scan_first_and_an_unchanged_rescan_takes_the_rows(self) -> None:
        root = self._tree("t", {"a": b"x", "b": b"x"})
        self.rebuild(root)
        with mock.patch.object(LocalFS, "checksum") as chk:
            self.rebuild(root)  # nothing changed: nothing hashed ...
        chk.assert_not_called()
        second, first = CAS.list_scans(self.db)
        self.assertGreater(second.scan_id, first.scan_id)
        # ... but the rows now belong to the newest scan that saw them.
        self.assertEqual((second.files_in_index, first.files_in_index), (2, 0))
        self.assertEqual(second.files_indexed, 2)

    def test_edge_the_first_rebuild_still_does_not_index_its_own_database(self) -> None:
        root = self._tree("t", {"a": b"x"})
        self.db = root / "cas.sqlite"
        self.assertEqual(self.rebuild(root), 1)


# --------------------------------------------------------------------------
# Filters: one scan, one folder
# --------------------------------------------------------------------------


class FilterTest(_Base):
    def setUp(self) -> None:
        super().setUp()
        self.one = self._tree("one", {"a": b"in-one", "b": b"in-one", "c": b"across"})
        self.two = self._tree("two", {"d": b"across", "e": b"in-two", "f": b"in-two"})
        self.rebuild(self.one)
        self.rebuild(self.two)
        self.second, self.first = CAS.list_scans(self.db)

    def _paths(self, groups) -> list[set[str]]:
        return sorted(({Path(e.path).name for e in g} for g in groups), key=sorted)

    def test_happy_all_scans(self) -> None:
        self.assertEqual(self._paths(CAS.duplicates(self.db)), [{"a", "b"}, {"c", "d"}, {"e", "f"}])

    def test_happy_one_scan_shows_every_group_it_has_a_copy_in(self) -> None:
        got = self._paths(CAS.duplicates(self.db, scan_id=self.first.scan_id))
        self.assertEqual(got, [{"a", "b"}, {"c", "d"}])
        self.assertEqual(self.first.duplicate_groups, 2)
        self.assertEqual(self.second.duplicate_groups, 2)

    def test_happy_only_duplicates_inside_a_folder(self) -> None:
        got = self._paths(CAS.duplicates(self.db, folder=str(self.two)))
        self.assertEqual(got, [{"e", "f"}])  # c/d crosses the folder edge

    def test_sad_an_unknown_scan_has_no_duplicates(self) -> None:
        self.assertEqual(CAS.duplicates(self.db, scan_id=999_999), [])

    def test_sad_an_empty_folder_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            CAS.duplicates(self.db, folder="")

    def test_edge_the_folder_match_is_on_whole_path_components(self) -> None:
        sibling = self._tree("one-more", {"x": b"in-one"})
        self.rebuild(sibling)
        got = self._paths(CAS.duplicates(self.db, folder=str(self.one)))
        self.assertIn({"a", "b"}, got)
        self.assertNotIn("x", {n for g in got for n in g})  # /one-more is not inside /one

    def test_edge_the_folder_match_is_case_sensitive_and_takes_a_trailing_slash(self) -> None:
        self.assertEqual(CAS.duplicates(self.db, folder=str(self.two).upper()), [])
        self.assertEqual(
            self._paths(CAS.duplicates(self.db, folder=str(self.two) + "/")), [{"e", "f"}]
        )

    def test_edge_algorithm_none_means_every_algorithm(self) -> None:
        CAS.upsert(self.db, "Other:x", "/o/a", "md5", "abc", 1)
        CAS.upsert(self.db, "Other:x", "/o/b", "md5", "abc", 1)
        algos = sorted({g[0].algorithm for g in CAS.duplicates(self.db, None)})
        self.assertEqual(algos, ["md5", "sha256"])

    def test_edge_rows_without_a_recorded_scan_are_the_earlier_scans(self) -> None:
        CAS.upsert(self.db, "Other:x", "/o/a", "md5", "abc", 1)
        CAS.upsert(self.db, "Other:x", "/o/b", "md5", "abc", 1)
        (group,) = CAS.duplicates(self.db, None, scan_id=CAS.EARLIER_SCANS)
        self.assertEqual({e.path for e in group}, {"/o/a", "/o/b"})
        self.assertEqual(CAS.list_scans(self.db)[-1].scan_id, CAS.EARLIER_SCANS)


# --------------------------------------------------------------------------
# Remove one scan, clear everything
# --------------------------------------------------------------------------


class RemoveAndClearTest(_Base):
    def setUp(self) -> None:
        super().setUp()
        self.one = self._tree("one", {"a": b"1", "b": b"1"})
        self.two = self._tree("two", {"c": b"2", "d": b"2"})
        self.rebuild(self.one)
        self.rebuild(self.two)
        self.second, self.first = CAS.list_scans(self.db)

    def test_happy_removing_a_scan_drops_its_rows_and_its_entry_only(self) -> None:
        self.assertEqual(CAS.remove_scan(self.db, self.first.scan_id), 2)
        self.assertEqual([s.scan_id for s in CAS.list_scans(self.db)], [self.second.scan_id])
        (group,) = CAS.duplicates(self.db)
        self.assertTrue(all(e.path.startswith(str(self.two)) for e in group))
        self.assertTrue((self.one / "a").exists())  # files are never touched

    def test_happy_clear_whole_index(self) -> None:
        self.assertEqual(CAS.clear_index(self.db), 4)
        self.assertEqual(CAS.list_scans(self.db), [])
        self.assertEqual(CAS.duplicates(self.db), [])
        self.assertTrue((self.two / "c").exists())

    def test_sad_removing_an_unknown_scan_removes_nothing(self) -> None:
        self.assertEqual(CAS.remove_scan(self.db, 424242), 0)
        self.assertEqual(len(CAS.list_scans(self.db)), 2)

    def test_edge_removing_the_earlier_scans_pseudo_entry(self) -> None:
        CAS.upsert(self.db, "Other:x", "/o/a", "md5", "abc", 1)
        self.assertEqual(CAS.remove_scan(self.db, CAS.EARLIER_SCANS), 1)
        self.assertNotIn(CAS.EARLIER_SCANS, [s.scan_id for s in CAS.list_scans(self.db)])
        self.assertEqual(len(CAS.list_scans(self.db)), 2)

    def test_edge_a_removed_scan_id_is_never_reused(self) -> None:
        CAS.remove_scan(self.db, self.second.scan_id)
        self.rebuild(self.two)
        newest = CAS.list_scans(self.db)[0]
        self.assertGreater(newest.scan_id, self.second.scan_id)

    def test_edge_clear_on_a_missing_database_is_zero(self) -> None:
        self.db = self.tmp / "nowhere" / "cas.sqlite"
        self.assertEqual(CAS.clear_index(self.db), 0)


if __name__ == "__main__":
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    unittest.main()
