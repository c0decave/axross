"""Deleting duplicates must never erase the last real copy of the content.

The Duplicate Finder works from an index, and an index is a claim about
the past. Two ways that claim turned into data loss, both reproduced
against a real tree before the fix:

* a symlink was indexed as a file, so ``real.txt`` and ``link.txt ->
  real.txt`` formed a "duplicate group" — deleting ``real.txt`` was
  approved with "1 copy will remain", and what remained was a dangling
  link;
* a survivor that changed or vanished after indexing still counted as a
  copy, because nothing was re-checked before deleting.

``cas.delete_duplicates`` re-verifies on the live backend, right before
it acts, that each file it removes still holds the indexed content and
that at least one *genuine* other copy survives. Removal goes to the
axross trash, so even a correct deletion stays reversible.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import cas as CAS  # noqa: E402
from core import trash as T  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

BID = "LocalFS:Local"


class _NoIdentityFS(LocalFS):
    """A backend that cannot tell whether two paths are one file — the
    situation of every remote protocol."""

    same_file = None


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.tree = self.tmp / "tree"
        self.tree.mkdir()
        self.db = self.tmp / "cas.sqlite"
        self.trash_root = str(self.tmp / "trash-root" / T.TRASH_DIRNAME)
        self.fs = LocalFS()

    def _write(self, rel: str, data: bytes = b"same content\n") -> Path:
        p = self.tree / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    def _rebuild(self, fs=None) -> list:
        CAS.rebuild(fs or self.fs, str(self.tree), backend_id=BID, db_path=self.db)
        return CAS.duplicates(self.db)

    def _entry(self, groups, path: Path):
        for group in groups:
            for e in group:
                if e.path == str(path):
                    return e
        raise AssertionError(f"{path} not indexed as a duplicate")

    def _delete(self, groups, *paths: Path, backends=None, **kw):
        candidates = [self._entry(groups, p) for p in paths]
        return CAS.delete_duplicates(
            candidates,
            groups,
            backends if backends is not None else {BID: self.fs},
            db_path=self.db,
            trash_root=self.trash_root,
            **kw,
        )


# --------------------------------------------------------------------------
# Happy path
# --------------------------------------------------------------------------


class HappyTest(_Base):
    def test_one_of_two_real_copies_goes_to_the_trash_and_the_other_stays(self) -> None:
        a, b = self._write("a.txt"), self._write("b.txt")
        out = self._delete(self._rebuild(), a)
        self.assertEqual([e.path for e in out.removed], [str(a)])
        self.assertEqual(out.refused, [])
        self.assertEqual(out.failed, [])
        self.assertFalse(a.exists())
        self.assertEqual(b.read_bytes(), b"same content\n")

    def test_the_removed_copy_is_restorable_from_the_axross_trash(self) -> None:
        a, _b = self._write("a.txt"), self._write("b.txt")
        self._delete(self._rebuild(), a)
        entries = T.list_trash(self.fs, root=self.trash_root)
        self.assertEqual([e.original_path for e in entries], [str(a)])
        T.restore(self.fs, entries[0].trash_id, root=self.trash_root)
        self.assertEqual(a.read_bytes(), b"same content\n")

    def test_the_index_forgets_the_removed_copy(self) -> None:
        a, _b = self._write("a.txt"), self._write("b.txt")
        self._delete(self._rebuild(), a)
        self.assertEqual(CAS.duplicates(self.db), [])
        self.assertEqual(
            [e.path for e in CAS.list_for_backend(self.db, BID)], [str(self.tree / "b.txt")]
        )

    def test_a_separate_copy_reached_through_a_symlinked_folder_still_counts(self) -> None:
        # Local can prove identity, so a genuine copy that merely sits
        # behind a symlinked directory is not refused.
        a = self._write("a.txt")
        other = self.tmp / "elsewhere"
        other.mkdir()
        (other / "b.txt").write_bytes(b"same content\n")
        (self.tree / "via").symlink_to(other)
        b_via = self.tree / "via" / "b.txt"
        for p in (a, b_via):
            CAS.upsert(self.db, BID, str(p), "sha256", _hash(self.fs, a), a.stat().st_size)
        out = self._delete(CAS.duplicates(self.db), a)
        self.assertEqual([e.path for e in out.removed], [str(a)])
        self.assertTrue((other / "b.txt").exists())


def _hash(fs, p: Path) -> str:
    return fs.checksum(str(p)).split(":", 1)[1]


# --------------------------------------------------------------------------
# Sad path — every way the last copy could have been lost
# --------------------------------------------------------------------------


class SadTest(_Base):
    def test_rebuild_does_not_index_symlinks(self) -> None:
        self._write("real.txt")
        (self.tree / "link.txt").symlink_to("real.txt")
        self.assertEqual(self._rebuild(), [])
        paths = [e.path for e in CAS.list_for_backend(self.db, BID)]
        self.assertEqual(paths, [str(self.tree / "real.txt")])

    def test_a_symlink_left_in_an_old_index_is_not_a_surviving_copy(self) -> None:
        real = self._write("real.txt")
        link = self.tree / "link.txt"
        link.symlink_to("real.txt")
        value = _hash(self.fs, real)
        for p in (real, link):  # what the index held before the walk fix
            CAS.upsert(self.db, BID, str(p), "sha256", value, real.stat().st_size)
        out = self._delete(CAS.duplicates(self.db), real)
        self.assertEqual(out.removed, [])
        self.assertEqual([e.path for e, _why in out.refused], [str(real)])
        self.assertIn("no other verified copy", out.refused[0][1])
        self.assertEqual(real.read_bytes(), b"same content\n")

    def test_a_hardlink_is_the_same_file_not_a_second_copy(self) -> None:
        a = self._write("a.txt")
        os.link(a, self.tree / "hard.txt")
        out = self._delete(self._rebuild(), a)
        self.assertEqual(out.removed, [])
        self.assertTrue(a.exists())

    def test_a_survivor_changed_since_indexing_does_not_count(self) -> None:
        a, b = self._write("a.txt"), self._write("b.txt")
        groups = self._rebuild()
        b.write_bytes(b"edited later\n")
        out = self._delete(groups, a)
        self.assertEqual(out.removed, [])
        self.assertTrue(a.exists())

    def test_a_survivor_deleted_since_indexing_does_not_count(self) -> None:
        a, b = self._write("a.txt"), self._write("b.txt")
        groups = self._rebuild()
        b.unlink()
        out = self._delete(groups, a)
        self.assertEqual(out.removed, [])
        self.assertTrue(a.exists())

    def test_a_candidate_changed_since_indexing_is_not_a_duplicate_any_more(self) -> None:
        a, b = self._write("a.txt"), self._write("b.txt")
        groups = self._rebuild()
        a.write_bytes(b"now unique\n")
        out = self._delete(groups, a)
        self.assertEqual(out.removed, [])
        self.assertIn("changed since", out.refused[0][1])
        self.assertEqual(a.read_bytes(), b"now unique\n")
        self.assertTrue(b.exists())

    def test_a_survivor_on_a_backend_that_is_not_connected_does_not_count(self) -> None:
        a = self._write("a.txt")
        self._rebuild()
        CAS.upsert(
            self.db, "SFTP:me@far", "/srv/a.txt", "sha256", _hash(self.fs, a), a.stat().st_size
        )
        out = self._delete(CAS.duplicates(self.db), a)
        self.assertEqual(out.removed, [])
        self.assertTrue(a.exists())

    def test_a_copy_inside_the_axross_trash_is_not_a_survivor(self) -> None:
        a = self._write("a.txt")
        trashed = self._write(f"{T.TRASH_DIRNAME}/0123abcd")
        value = _hash(self.fs, a)
        for p in (a, trashed):
            CAS.upsert(self.db, BID, str(p), "sha256", value, a.stat().st_size)
        out = self._delete(CAS.duplicates(self.db), a)
        self.assertEqual(out.removed, [])
        self.assertTrue(a.exists())

    def test_rebuild_skips_the_axross_trash(self) -> None:
        self._write("a.txt")
        self._write(f"{T.TRASH_DIRNAME}/0123abcd")
        self.assertEqual(self._rebuild(), [])

    def test_without_identity_a_survivor_behind_a_symlinked_folder_is_refused(self) -> None:
        # /tree/via -> /tree: "via/a.txt" IS "a.txt". A remote backend
        # cannot prove otherwise, so it must not count.
        a = self._write("a.txt")
        (self.tree / "via").symlink_to(self.tree)
        value = _hash(self.fs, a)
        for p in (a, self.tree / "via" / "a.txt"):
            CAS.upsert(self.db, BID, str(p), "sha256", value, a.stat().st_size)
        fs = _NoIdentityFS()
        out = self._delete(CAS.duplicates(self.db), a, backends={BID: fs})
        self.assertEqual(out.removed, [])
        self.assertTrue(a.exists())

    def _alias_through_folder_link(self):
        """``via -> .``: deleting ``via/a.txt`` deletes ``a.txt``."""
        a = self._write("a.txt")
        (self.tree / "via").symlink_to(".")
        alias = self.tree / "via" / "a.txt"
        for p in (a, alias):
            CAS.upsert(self.db, BID, str(p), "sha256", _hash(self.fs, a), a.stat().st_size)
        return a, alias

    def test_a_candidate_reached_through_a_symlinked_folder_is_refused_locally(self) -> None:
        a, alias = self._alias_through_folder_link()
        out = self._delete(CAS.duplicates(self.db), alias)
        self.assertEqual(out.removed, [])
        self.assertTrue(a.exists())

    def test_a_candidate_reached_through_a_symlinked_folder_is_refused_without_identity(
        self,
    ) -> None:
        a, alias = self._alias_through_folder_link()
        out = self._delete(CAS.duplicates(self.db), alias, backends={BID: _NoIdentityFS()})
        self.assertEqual(out.removed, [])
        self.assertTrue(a.exists())

    def test_a_trash_failure_keeps_the_file_and_its_index_row(self) -> None:
        a, _b = self._write("a.txt"), self._write("b.txt")
        groups = self._rebuild()
        with mock.patch.object(T, "trash", side_effect=OSError("disk full")):
            out = self._delete(groups, a)
        self.assertEqual(out.removed, [])
        self.assertEqual([(e.path, why) for e, why in out.failed], [(str(a), "disk full")])
        self.assertTrue(a.exists())
        self.assertEqual(len(CAS.duplicates(self.db)), 1)

    def test_every_copy_selected_removes_nothing(self) -> None:
        a, b = self._write("a.txt"), self._write("b.txt")
        out = self._delete(self._rebuild(), a, b)
        self.assertEqual(out.removed, [])
        self.assertTrue(a.exists() and b.exists())


# --------------------------------------------------------------------------
# Edge cases
# --------------------------------------------------------------------------


class EdgeTest(_Base):
    def test_two_candidates_one_verified_survivor_removes_both(self) -> None:
        a, b, c = self._write("a.txt"), self._write("b.txt"), self._write("c.txt")
        out = self._delete(self._rebuild(), a, b)
        self.assertEqual(sorted(e.path for e in out.removed), [str(a), str(b)])
        self.assertTrue(c.exists())

    def test_one_bad_survivor_does_not_hide_a_good_one(self) -> None:
        a, b, c = self._write("a.txt"), self._write("b.txt"), self._write("c.txt")
        groups = self._rebuild()
        b.unlink()
        out = self._delete(groups, a)
        self.assertEqual([e.path for e in out.removed], [str(a)])
        self.assertTrue(c.exists())

    def test_cancel_before_the_start_touches_nothing(self) -> None:
        a, _b = self._write("a.txt"), self._write("b.txt")
        out = self._delete(self._rebuild(), a, cancel=lambda: True)
        self.assertEqual(out.removed, [])
        self.assertTrue(a.exists())

    def test_progress_reports_each_file_handled(self) -> None:
        a, _b = self._write("a.txt"), self._write("b.txt")
        seen = []
        self._delete(self._rebuild(), a, progress=lambda done, ok, p: seen.append((done, ok, p)))
        self.assertEqual(seen, [(1, 1, str(a))])

    def test_empty_selection_is_a_no_op(self) -> None:
        self._write("a.txt"), self._write("b.txt")
        out = CAS.delete_duplicates([], self._rebuild(), {BID: self.fs}, db_path=self.db)
        self.assertEqual((out.removed, out.refused, out.failed), ([], [], []))


if __name__ == "__main__":
    unittest.main()
