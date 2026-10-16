"""Scripting API for the duplicate index: scans, duplicates, dedupe.

``axross.dedupe()`` is a dry run unless ``dry_run=False`` is passed: it
returns the plan (which copy stays, which go) and touches nothing. A real
run moves the copies to the axross trash through the same verified path as
the Duplicate Finder.
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
from core import scripting as S  # noqa: E402
from core import trash as T  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

BID = "LocalFS:Local"


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.db = self.tmp / "cas.sqlite"
        p = mock.patch.object(CAS, "_DEFAULT_DB", self.db)
        p.start()
        self.addCleanup(p.stop)
        h = mock.patch.object(LocalFS, "home", lambda _self: str(self.tmp))
        h.start()
        self.addCleanup(h.stop)
        self.fs = LocalFS()
        self.root = self.tmp / "tree"
        self.old = self._write("keep/old.txt", 1_000.0, b"alpha\n")
        self.new = self._write("new.txt", 5_000.0, b"alpha\n")
        self.other_old = self._write("b-old.txt", 2_000.0, b"beta\n")
        self.other_new = self._write("sub/b-new.txt", 3_000.0, b"beta\n")
        CAS.rebuild(self.fs, str(self.root), backend_id=BID)

    def _write(self, rel: str, mtime: float, data: bytes) -> Path:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        os.utime(p, (mtime, mtime))
        return p


class ListTest(_Base):
    def test_happy_scans_and_duplicates_are_listed(self) -> None:
        (scan,) = S.duplicate_scans()
        self.assertEqual((scan.root, scan.status), (str(self.root), "complete"))
        groups = S.duplicates()
        self.assertEqual(len(groups), 2)
        self.assertEqual({g[0].path for g in groups}, {str(self.old), str(self.other_old)})

    def test_happy_duplicates_of_one_scan_or_folder(self) -> None:
        (scan,) = S.duplicate_scans()
        self.assertEqual(len(S.duplicates(scan=scan.scan_id)), 2)
        self.assertEqual(S.duplicates(scan=scan.scan_id + 1), [])
        self.assertEqual(S.duplicates(folder=str(self.root / "keep")), [])  # one copy only

    def test_edge_scan_accepts_a_scan_record(self) -> None:
        (scan,) = S.duplicate_scans()
        self.assertEqual(len(S.duplicates(scan=scan)), 2)


class DedupeTest(_Base):
    def test_happy_the_default_is_a_dry_run_that_touches_nothing(self) -> None:
        result = S.dedupe(backends=[self.fs])
        self.assertTrue(result.dry_run)
        self.assertEqual(result.groups, 2)
        self.assertEqual({e.path for e in result.keep}, {str(self.old), str(self.other_old)})
        self.assertEqual({e.path for e in result.trash}, {str(self.new), str(self.other_new)})
        self.assertEqual(result.removed, [])
        for p in (self.old, self.new, self.other_old, self.other_new):
            self.assertTrue(p.exists(), p)
        self.assertEqual(T.list_trash(self.fs), [])
        self.assertIn("dry run", result.render().lower())

    def test_happy_a_real_run_moves_all_but_the_oldest_to_the_trash(self) -> None:
        result = S.dedupe(dry_run=False, backends=[self.fs])
        self.assertFalse(result.dry_run)
        self.assertEqual({e.path for e in result.removed}, {str(self.new), str(self.other_new)})
        self.assertTrue(self.old.exists() and self.other_old.exists())
        self.assertFalse(self.new.exists() or self.other_new.exists())
        trashed = {e.original_path for e in T.list_trash(self.fs)}
        self.assertEqual(trashed, {str(self.new), str(self.other_new)})
        self.assertEqual(S.duplicates(), [])  # the index forgot the trashed copies

    def test_sad_an_unknown_keep_rule_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            S.dedupe(keep="newest")

    def test_sad_a_backend_that_is_not_passed_is_refused_not_guessed(self) -> None:
        result = S.dedupe(dry_run=False, backends=[])
        self.assertEqual(result.removed, [])
        self.assertTrue(self.new.exists())
        self.assertTrue(all("not connected" in why for _e, why in result.refused))

    def test_sad_a_changed_survivor_stops_its_group(self) -> None:
        self.old.write_bytes(b"edited\n")
        result = S.dedupe(dry_run=False, backends=[self.fs])
        self.assertTrue(self.new.exists())
        self.assertEqual({e.path for e in result.removed}, {str(self.other_new)})

    def test_edge_dedupe_limited_to_a_folder(self) -> None:
        self._write("sub/b-copy.txt", 9_000.0, b"beta\n")
        CAS.rebuild(self.fs, str(self.root), backend_id=BID)
        result = S.dedupe(folder=str(self.root / "sub"), backends=[self.fs])
        self.assertEqual([e.path for e in result.trash], [str(self.root / "sub/b-copy.txt")])
        self.assertEqual([e.path for e in result.keep], [str(self.other_new)])

    def test_edge_the_default_backend_is_the_local_filesystem(self) -> None:
        result = S.dedupe(dry_run=False)
        self.assertEqual(len(result.removed), 2)


class PublicSurfaceTest(unittest.TestCase):
    def test_happy_the_new_verbs_are_public_documented_and_grouped(self) -> None:
        listed = {n for _g, names in S._HELP_GROUPS for n in names}
        for name in ("duplicate_scans", "duplicates", "dedupe"):
            self.assertIn(name, S.__all__)
            self.assertIn(name, listed)
            self.assertGreater(len((getattr(S, name).__doc__ or "").strip()), 40)

    def test_edge_the_checked_in_reference_matches_the_generator(self) -> None:
        ref = Path(__file__).resolve().parents[1] / "docs" / "SCRIPTING_REFERENCE.md"
        text = ref.read_text(encoding="utf-8")
        for name in ("duplicate_scans", "duplicates", "dedupe"):
            self.assertIn(S._render_function_block(name, getattr(S, name)), text)


if __name__ == "__main__":
    unittest.main()
