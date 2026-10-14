"""``list_trash`` takes the data objects from the listing it already has.

Before: one ``exists()`` per sidecar on top of the listing - one extra
round trip per trash entry on remote backends. A data object that the
listing shows as a plain entry exists; symlinks (whether exists() follows
them depends on the backend) and names not in the listing (case-
insensitive servers) still ask ``exists()``, so the result is the same
as before.
"""

from __future__ import annotations

import dataclasses
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import trash as T  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


class ListTrashTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.fs = LocalFS()
        self.ids = []
        for i in range(20):
            p = self.tmp / f"f{i}.txt"
            p.write_text("x" * i)
            self.ids.append(T.trash(self.fs, str(p), root=str(self.tmp)))
        self.trash_dir = Path(T._resolve_root(self.fs, str(self.tmp)))

    def listed(self):
        return T.list_trash(self.fs, root=str(self.tmp))

    def test_happy_no_exists_call_per_entry(self) -> None:
        with mock.patch.object(LocalFS, "exists", wraps=self.fs.exists) as ex:
            entries = self.listed()
        self.assertEqual(sorted(e.trash_id for e in entries), sorted(self.ids))
        self.assertEqual(ex.call_count, 1)  # the trash root itself

    def test_sad_a_sidecar_without_data_is_still_skipped(self) -> None:
        (self.trash_dir / self.ids[0]).unlink()
        self.assertNotIn(self.ids[0], [e.trash_id for e in self.listed()])
        self.assertEqual(len(self.listed()), 19)

    def test_edge_a_dangling_symlink_follows_the_backends_exists(self) -> None:
        # LocalFS.exists is lexists (link listed); a backend whose exists()
        # follows links skips it - both as before, since links still ask.
        data = self.trash_dir / self.ids[1]
        data.unlink()
        os.symlink(self.tmp / "gone", data)
        self.assertIn(self.ids[1], [e.trash_id for e in self.listed()])
        with mock.patch.object(LocalFS, "exists", side_effect=lambda p: os.path.exists(p)):
            self.assertNotIn(self.ids[1], [e.trash_id for e in self.listed()])

    def test_edge_a_symlink_to_an_existing_file_is_listed(self) -> None:
        data = self.trash_dir / self.ids[2]
        data.unlink()
        (self.tmp / "target").write_text("t")
        os.symlink(self.tmp / "target", data)
        self.assertIn(self.ids[2], [e.trash_id for e in self.listed()])

    def test_edge_a_name_missing_from_the_listing_falls_back_to_exists(self) -> None:
        # e.g. a case-insensitive server listing the name in another case
        real = self.fs.list_dir

        def listing(path):
            return [
                dataclasses.replace(it, name=it.name.upper()) if it.name == self.ids[3] else it
                for it in real(path)
            ]

        with mock.patch.object(LocalFS, "list_dir", side_effect=listing):
            self.assertIn(self.ids[3], [e.trash_id for e in self.listed()])


if __name__ == "__main__":
    unittest.main()
