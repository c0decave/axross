"""The offline metadata index is private to the user, like the CAS index.

Found in review: ``metadata_index._connect`` created the database through
``sqlite3.connect`` under the process umask (0644 with the usual 022) in a
directory made 0755. Each row holds a backend id ("SSHSession:alice@db01",
i.e. user and host) and the full remote path of an indexed file, so every
local account could read which servers the user indexed and what is on
them. ``core.cas`` already creates its index 0600 in a 0700 directory.
"""

from __future__ import annotations

import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import metadata_index as MI  # noqa: E402


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


class MetadataIndexPrivateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        old = os.umask(0o022)
        self.addCleanup(os.umask, old)
        self.db = self.tmp / "share" / "axross" / "metadata.sqlite"

    def test_happy_a_new_index_and_its_directory_are_private(self) -> None:
        MI.upsert(self.db, "SSHSession:alice@db01", "/srv/a", name="a", size=1, is_dir=False)
        self.assertEqual(_mode(self.db), 0o600)
        self.assertEqual(_mode(self.db.parent), 0o700)
        self.assertEqual([e.path for e in MI.search("a", db_path=self.db)], ["/srv/a"])

    def test_sad_an_index_left_world_readable_by_an_older_version_is_tightened(self) -> None:
        self.db.parent.mkdir(parents=True)
        MI.upsert(self.db, "b", "/x", name="x", size=1, is_dir=False)
        os.chmod(self.db, 0o644)
        MI.search("x", db_path=self.db)
        self.assertEqual(_mode(self.db), 0o600)

    def test_edge_an_existing_shared_parent_directory_is_left_alone(self) -> None:
        """Only directories the index creates are made 0700: the parent may
        be a directory the user shares on purpose."""
        self.db.parent.mkdir(parents=True)
        os.chmod(self.db.parent, 0o755)
        MI.upsert(self.db, "b", "/x", name="x", size=1, is_dir=False)
        self.assertEqual(_mode(self.db.parent), 0o755)
        self.assertEqual(_mode(self.db), 0o600)


if __name__ == "__main__":
    unittest.main()
