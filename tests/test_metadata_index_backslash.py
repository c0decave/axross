"""A backslash in a file name is an ordinary character on a POSIX file
system, and the offline index now keeps such files.

index_dir validated every name with the strict single-component rule,
which refuses a backslash everywhere, so ``a\\b.txt`` on a local Linux
folder never reached Find in Index. The backend's own name policy
(core.path_policy.BackendPathPolicy.literal_backslash: LocalFS on POSIX
only) decides now, as it does for listings. On every other backend a
backslash may be a separator on the server, and the entry stays out.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import metadata_index as MX  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from models.file_item import FileItem  # noqa: E402

POSIX = os.sep == "/"


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.db = self.tmp / "m.db"
        self.root = self.tmp / "data"
        self.root.mkdir()

    def names(self, backend_id: str = "t") -> set[str]:
        return {e.name for e in MX.iter_entries(db_path=self.db) if e.backend_id == backend_id}


class _RemoteLike:
    """A backend without literal_backslash_in_names (an SMB or unknown server)."""

    def __init__(self, names):
        self._names = names

    def separator(self) -> str:
        return "/"

    def join(self, *parts) -> str:
        return "/".join(p.rstrip("/") for p in parts)

    def list_dir(self, path):
        return [FileItem(name=n, size=1) for n in self._names] if path == "/r" else []


@unittest.skipUnless(POSIX, "a backslash is a separator on Windows")
class HappyTests(_Base):
    def test_happy_a_local_file_with_a_backslash_is_indexed(self) -> None:
        (self.root / "a\\b.txt").write_text("x")
        (self.root / "plain.txt").write_text("x")
        MX.index_dir(LocalFS(), str(self.root), backend_id="t", db_path=self.db)
        self.assertEqual(self.names(), {"a\\b.txt", "plain.txt"})
        self.assertEqual([e.name for e in MX.search("a\\b", db_path=self.db)], ["a\\b.txt"])

    def test_happy_reindex_keeps_it_and_drops_it_once_deleted(self) -> None:
        f = self.root / "x\\y.txt"
        f.write_text("x")
        self.assertEqual(MX.reindex_dir(LocalFS(), str(self.root), backend_id="t",
                                        db_path=self.db), (1, 0))
        f.unlink()
        self.assertEqual(MX.reindex_dir(LocalFS(), str(self.root), backend_id="t",
                                        db_path=self.db), (0, 1))


class SadTests(_Base):
    def test_sad_on_another_backend_a_backslash_name_stays_out(self) -> None:
        MX.index_dir(_RemoteLike(["a\\..\\evil", "ok.txt"]), "/r", backend_id="r", db_path=self.db)
        self.assertEqual(self.names("r"), {"ok.txt"})

    @unittest.skipUnless(POSIX, "POSIX file names")
    def test_sad_a_slash_or_dotdot_is_still_refused_locally(self) -> None:
        # Only the backslash rule moves; traversal and separators stay out.
        for bad in ("..", "a/b"):
            self.assertRaises(ValueError, MX._checked_row, "t", "/x/" + bad, name=bad, size=0,
                              is_dir=False, literal_backslash=True)


@unittest.skipUnless(POSIX, "POSIX file names")
class EdgeTests(_Base):
    def test_edge_a_name_that_is_only_backslashes(self) -> None:
        (self.root / "\\\\").write_text("x")
        MX.index_dir(LocalFS(), str(self.root), backend_id="t", db_path=self.db)
        self.assertEqual(self.names(), {"\\\\"})

    def test_edge_upsert_keeps_its_strict_default(self) -> None:
        # Callers without a backend (scripts, MCP rows) keep the old rule.
        with self.assertRaises(ValueError):
            MX.upsert(self.db, "t", "/x/a\\b", name="a\\b", size=0, is_dir=False)


if __name__ == "__main__":
    unittest.main()
