"""Duplicate Finder: which copy survives, and "select all, delete" keeps it.

Operator decision: the copy that stays is the OLDEST by modification time;
a tie goes to the shorter full path, then to the alphabetically first path.
A copy without a modification time sorts after every dated copy. Groups are
returned (and shown) in that order, so "the first" on screen is the survivor.

Selecting every copy of a group and deleting no longer refuses the group:
the first copy is kept automatically, the others go to the axross trash -
still through the per-file re-verification that a genuine survivor exists.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import cas as CAS  # noqa: E402
from core import trash as T  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

BID = "LocalFS:Local"


def _e(path: str, mtime=None, value: str = "h1", backend: str = "local") -> CAS.CasEntry:
    return CAS.CasEntry(
        backend_id=backend,
        path=path,
        algorithm="sha256",
        value=value,
        size=10,
        indexed_at=datetime(2026, 1, 1),
        mtime=mtime,
    )


# --------------------------------------------------------------------------
# The order: oldest first, then shorter path, then path; undated last
# --------------------------------------------------------------------------


class SurvivorOrderTest(unittest.TestCase):
    def test_happy_the_oldest_copy_comes_first(self) -> None:
        group = [_e("/new", 300.0), _e("/old", 100.0), _e("/mid", 200.0)]
        self.assertEqual([e.path for e in CAS.order_by_survivor(group)], ["/old", "/mid", "/new"])

    def test_edge_a_tie_on_mtime_goes_to_the_shorter_path(self) -> None:
        group = [_e("/a/deeper/copy.txt", 100.0), _e("/a/copy.txt", 100.0)]
        self.assertEqual(CAS.order_by_survivor(group)[0].path, "/a/copy.txt")

    def test_edge_a_tie_on_mtime_and_length_goes_alphabetically(self) -> None:
        group = [_e("/b/x", 100.0), _e("/a/x", 100.0)]
        self.assertEqual([e.path for e in CAS.order_by_survivor(group)], ["/a/x", "/b/x"])

    def test_sad_copies_without_mtime_sort_after_dated_ones_then_by_path(self) -> None:
        group = [_e("/zz", None), _e("/new", 900.0), _e("/a", None), _e("/old", 100.0)]
        self.assertEqual(
            [e.path for e in CAS.order_by_survivor(group)], ["/old", "/new", "/a", "/zz"]
        )

    def test_edge_no_copy_has_an_mtime_falls_back_to_the_path_rule(self) -> None:
        group = [_e("/long/path"), _e("/b"), _e("/a")]
        self.assertEqual([e.path for e in CAS.order_by_survivor(group)], ["/a", "/b", "/long/path"])
        self.assertTrue(CAS.has_undated(group))
        self.assertFalse(CAS.has_undated([_e("/a", 1.0), _e("/b", 2.0)]))


class DuplicatesComeInSurvivorOrderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.db = self.tmp / "cas.sqlite"
        self.root = self.tmp / "tree"
        self.root.mkdir()

    def _write(self, rel: str, mtime: float, data: bytes = b"same\n") -> Path:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        os.utime(p, (mtime, mtime))
        return p

    def test_happy_rows_carry_their_mtime_and_the_oldest_is_first(self) -> None:
        # Created newest-first, so insertion order would put the newest first.
        self._write("a-newest.txt", 3_000_000.0)
        self._write("b-middle.txt", 2_000_000.0)
        oldest = self._write("c-oldest.txt", 1_000_000.0)
        CAS.rebuild(LocalFS(), str(self.root), backend_id=BID, db_path=self.db)
        (group,) = CAS.duplicates(self.db)
        self.assertEqual(group[0].path, str(oldest))
        self.assertEqual(group[0].mtime, 1_000_000.0)
        self.assertEqual([e.mtime for e in group], [1_000_000.0, 2_000_000.0, 3_000_000.0])


# --------------------------------------------------------------------------
# The plan: select all keeps the first of each fully selected group
# --------------------------------------------------------------------------


class PlanTest(unittest.TestCase):
    def test_happy_select_all_keeps_exactly_the_oldest_of_each_group(self) -> None:
        g1 = [_e("/a1", 200.0, "h1"), _e("/a2", 100.0, "h1"), _e("/a3", 300.0, "h1")]
        g2 = [_e("/b1", 50.0, "h2"), _e("/b2", 60.0, "h2")]
        plan = CAS.plan_deletion([*g1, *g2], [g1, g2])
        self.assertEqual(sorted(e.path for e in plan.deletable), ["/a1", "/a3", "/b2"])
        self.assertEqual(sorted(e.path for e in plan.auto_kept), ["/a2", "/b1"])
        self.assertEqual(plan.survivors, 2)
        self.assertEqual(plan.refused_groups, [])

    def test_happy_partial_selection_is_unchanged(self) -> None:
        group = [_e("/old", 1.0), _e("/mid", 2.0), _e("/new", 3.0)]
        # The user may deliberately remove the oldest copy and keep a newer one.
        plan = CAS.plan_deletion([group[0], group[1]], [group])
        self.assertEqual([e.path for e in plan.deletable], ["/old", "/mid"])
        self.assertEqual(plan.auto_kept, [])
        self.assertEqual(plan.survivors, 1)

    def test_sad_a_group_of_one_is_still_refused(self) -> None:
        plan = CAS.plan_deletion([_e("/only")], [[_e("/only")]])
        self.assertEqual(plan.deletable, [])
        self.assertEqual(plan.refused_groups, ["h1"])

    def test_edge_the_survivor_follows_the_rule_not_the_list_order(self) -> None:
        group = [_e("/z", None), _e("/y", 5.0)]
        plan = CAS.plan_deletion(list(group), [group])
        self.assertEqual([e.path for e in plan.auto_kept], ["/y"])
        self.assertEqual([e.path for e in plan.deletable], ["/z"])

    def test_edge_the_ui_module_uses_the_same_plan(self) -> None:
        from ui.cas_dialog import plan_deletion

        self.assertIs(plan_deletion, CAS.plan_deletion)


# --------------------------------------------------------------------------
# Real files: select all, delete, the oldest stays and the rest is restorable
# --------------------------------------------------------------------------


class SelectAllDeleteOnDiskTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.db = self.tmp / "cas.sqlite"
        self.root = self.tmp / "tree"
        self.root.mkdir()
        self.fs = LocalFS()
        h = mock.patch.object(LocalFS, "home", lambda _self: str(self.tmp))
        h.start()
        self.addCleanup(h.stop)

    def _write(self, rel: str, mtime: float, data: bytes) -> Path:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        os.utime(p, (mtime, mtime))
        return p

    def _index(self):
        CAS.rebuild(self.fs, str(self.root), backend_id=BID, db_path=self.db)
        return CAS.duplicates(self.db)

    def _delete_all(self, groups):
        everything = [e for g in groups for e in g]
        plan = CAS.plan_deletion(everything, groups)
        return plan, CAS.delete_duplicates(plan.deletable, groups, {BID: self.fs}, db_path=self.db)

    def test_happy_exactly_one_per_group_remains_and_it_is_the_oldest(self) -> None:
        a_old = self._write("x/a-old.txt", 1_000.0, b"alpha\n")
        a_new = self._write("a-new.txt", 9_000.0, b"alpha\n")
        a_mid = self._write("y/a-mid.txt", 5_000.0, b"alpha\n")
        b_old = self._write("b-old.txt", 2_000.0, b"beta\n")
        b_new = self._write("x/b-new.txt", 3_000.0, b"beta\n")
        unique = self._write("unique.txt", 4_000.0, b"gamma\n")
        _plan, outcome = self._delete_all(self._index())
        self.assertEqual(outcome.refused, [])
        self.assertEqual(outcome.failed, [])
        self.assertTrue(a_old.exists() and b_old.exists() and unique.exists())
        for gone in (a_new, a_mid, b_new):
            self.assertFalse(gone.exists(), gone)
        trashed = sorted(e.original_path for e in T.list_trash(self.fs))
        self.assertEqual(trashed, sorted(str(p) for p in (a_new, a_mid, b_new)))
        # Restorable: the trash keeps the bytes.
        entry = next(e for e in T.list_trash(self.fs) if e.original_path == str(a_new))
        T.restore(self.fs, entry.trash_id)
        self.assertEqual(a_new.read_bytes(), b"alpha\n")

    def test_sad_a_survivor_that_vanished_stops_its_group(self) -> None:
        old = self._write("old.txt", 1_000.0, b"alpha\n")
        new = self._write("new.txt", 2_000.0, b"alpha\n")
        groups = self._index()
        old.unlink()  # gone after indexing, before deleting
        _plan, outcome = self._delete_all(groups)
        self.assertEqual(outcome.removed, [])
        self.assertTrue(new.exists())
        self.assertIn("no other verified copy", " ".join(why for _e, why in outcome.refused))

    def test_sad_a_survivor_that_changed_stops_its_group(self) -> None:
        old = self._write("old.txt", 1_000.0, b"alpha\n")
        new = self._write("new.txt", 2_000.0, b"alpha\n")
        groups = self._index()
        old.write_bytes(b"edited\n")
        _plan, outcome = self._delete_all(groups)
        self.assertEqual(outcome.removed, [])
        self.assertEqual(new.read_bytes(), b"alpha\n")

    def test_edge_a_tie_keeps_the_shorter_path(self) -> None:
        short = self._write("s.txt", 1_000.0, b"alpha\n")
        longer = self._write("deep/er/s.txt", 1_000.0, b"alpha\n")
        _plan, outcome = self._delete_all(self._index())
        self.assertTrue(short.exists())
        self.assertFalse(longer.exists())
        self.assertEqual([e.path for e in outcome.removed], [str(longer)])


if __name__ == "__main__":
    unittest.main()
