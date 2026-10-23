"""Indexing a folder again drops what is no longer there.

"Index Current Pane…" only ever added rows (index_dir is additive;
prune_missing was reachable through MCP only), so a file deleted after it
had been indexed stayed a hit in Find in Index for good. reindex_dir
removes the rows under the folder that a complete walk did not see - and
nothing when the walk was cancelled or capped, or under a folder whose
listing failed: those rows are unknown, not gone.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import metadata_index as MX  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "data"
        (self.root / "sub" / "deep").mkdir(parents=True)
        for rel in ("a.txt", "b.txt", "sub/c.txt", "sub/deep/d.txt"):
            (self.root / rel).write_text("x")
        self.db = self.tmp / "m.db"

    def reindex(self, root: Path | None = None, backend=None, **kw):
        return MX.reindex_dir(backend or LocalFS(), str(root or self.root), backend_id="t",
                              db_path=self.db, **kw)

    def paths(self, backend_id: str = "t") -> set[str]:
        return {e.path for e in MX.iter_entries(db_path=self.db) if e.backend_id == backend_id}

    def rel(self, *names: str) -> set[str]:
        return {str(self.root / n) for n in names}


ALL = ("a.txt", "b.txt", "sub", "sub/c.txt", "sub/deep", "sub/deep/d.txt")


# --- happy ----------------------------------------------------------------


class HappyTests(_Base):
    def test_happy_a_deleted_file_leaves_the_index(self) -> None:
        self.assertEqual(self.reindex(), (6, 0))
        (self.root / "b.txt").unlink()
        self.assertEqual(self.reindex(), (5, 1))
        self.assertEqual(self.paths(), self.rel(*[n for n in ALL if n != "b.txt"]))

    def test_happy_a_deleted_folder_takes_its_whole_subtree_along(self) -> None:
        self.reindex()
        shutil.rmtree(self.root / "sub")
        self.assertEqual(self.reindex(), (2, 4))
        self.assertEqual(self.paths(), self.rel("a.txt", "b.txt"))

    def test_happy_index_dir_stays_additive(self) -> None:
        # The MCP tool and scripts call index_dir; its contract is unchanged.
        MX.index_dir(LocalFS(), str(self.root), backend_id="t", db_path=self.db)
        (self.root / "a.txt").unlink()
        MX.index_dir(LocalFS(), str(self.root), backend_id="t", db_path=self.db)
        self.assertIn(str(self.root / "a.txt"), self.paths())


# --- sad ------------------------------------------------------------------


class SadTests(_Base):
    def test_sad_a_cancelled_walk_removes_nothing(self) -> None:
        self.reindex()
        (self.root / "a.txt").unlink()
        (self.root / "b.txt").unlink()
        calls = []
        self.reindex(cancel=lambda: len(calls) > 0, progress=lambda *a: calls.append(a))
        self.assertEqual(self.paths(), self.rel(*ALL))

    def test_sad_rows_under_a_folder_that_cannot_be_listed_stay(self) -> None:
        self.reindex()
        sub = str(self.root / "sub")
        real = LocalFS.list_dir

        def failing(fs, path):
            if path == sub:
                raise PermissionError(13, "Permission denied", path)
            return real(fs, path)

        with mock.patch.object(LocalFS, "list_dir", failing):
            indexed, removed = self.reindex()
        self.assertEqual(removed, 0)
        self.assertEqual(self.paths(), self.rel(*ALL))

    def test_sad_an_unlistable_root_removes_nothing(self) -> None:
        self.reindex()
        shutil.rmtree(self.root)
        self.assertEqual(self.reindex(), (0, 0))
        self.assertEqual(len(self.paths()), 6)


# --- edge -----------------------------------------------------------------


class EdgeTests(_Base):
    def test_edge_siblings_with_the_same_prefix_are_not_touched(self) -> None:
        # "/data-x" sorts before "/data/" and "/data0" after it: the range
        # must be exactly the folder's subtree.
        for sibling in ("data-x", "data0", "data_y", "datab"):
            (self.tmp / sibling).mkdir()
            (self.tmp / sibling / "f.txt").write_text("x")
            self.reindex(self.tmp / sibling)
        self.reindex()
        shutil.rmtree(self.root)
        self.root.mkdir()
        self.reindex()
        left = self.paths()
        for sibling in ("data-x", "data0", "data_y", "datab"):
            self.assertIn(str(self.tmp / sibling / "f.txt"), left)
        self.assertFalse(any(p.startswith(str(self.root) + "/") for p in left))

    def test_edge_other_backends_are_not_touched(self) -> None:
        MX.index_dir(LocalFS(), str(self.root), backend_id="other", db_path=self.db)
        self.reindex()
        shutil.rmtree(self.root / "sub")
        self.reindex()
        self.assertEqual(len(self.paths("other")), 6)

    def test_edge_the_entry_cap_removes_nothing(self) -> None:
        self.reindex()
        (self.root / "b.txt").unlink()
        with mock.patch.object(MX, "MAX_WALK_ENTRIES", 2):
            self.assertEqual(self.reindex()[1], 0)
        self.assertIn(str(self.root / "b.txt"), self.paths())

    def test_edge_below_the_depth_cap_rows_stay(self) -> None:
        self.reindex()
        (self.root / "sub" / "deep" / "d.txt").unlink()
        with mock.patch.object(MX, "MAX_WALK_DEPTH", 0):
            indexed, removed = self.reindex()
        self.assertIn(str(self.root / "sub" / "deep" / "d.txt"), self.paths())
        self.assertEqual(removed, 0)

    def test_edge_the_root_folder_slash_works(self) -> None:
        # "/" must not become an empty prefix that matches nothing.
        self.assertEqual(MX._subtree_bounds("/"), ("/", "0"))
        self.assertEqual(MX._subtree_bounds("/data/"), ("/data/", "/data0"))


# --- e2e: the dialog ----------------------------------------------------------


class DialogTests(_Base):
    @classmethod
    def setUpClass(cls) -> None:
        from PyQt6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication([])

    def test_e2e_index_current_pane_again_drops_a_deleted_file(self) -> None:
        from PyQt6.QtWidgets import QMessageBox

        from ui import metadata_search_dialog as M

        root = self.root

        class _Pane:
            backend = LocalFS()
            current_path = str(root)

        for p in (mock.patch.object(MX, "_DEFAULT_DB", self.db),
                  mock.patch.object(M.QMessageBox, "question",
                                    return_value=QMessageBox.StandardButton.Yes),
                  mock.patch.object(M.QMessageBox, "information")):
            p.start()
            self.addCleanup(p.stop)
        dlg = M.MetadataSearchDialog(_Pane())
        self.addCleanup(dlg.deleteLater)
        dlg.show()

        def run() -> str:
            M.QMessageBox.information.reset_mock()
            dlg._do_index_active()
            end = time.time() + 15
            while time.time() < end and not M.QMessageBox.information.called:
                self.app.processEvents()
                time.sleep(0.01)
            self.assertTrue(M.QMessageBox.information.called, "index never finished")
            return M.QMessageBox.information.call_args[0][2]

        run()
        (root / "a.txt").unlink()
        text = run()
        bid = M._backend_id_for(_Pane.backend)
        self.assertNotIn(str(root / "a.txt"), self.paths(bid))
        self.assertIn(str(root / "b.txt"), self.paths(bid))
        self.assertIn("Removed 1 that no longer exist", text)


if __name__ == "__main__":
    unittest.main()
