"""A long path does not widen the Duplicate Finder's window.

Found in review (round 2 of the 2026-11 reviews, UI shell): the details
line - a word-wrapped label - could not break a long path without
blanks, so its minimum width, and the window's, was the path's: a nested
path of 1,700 characters made the window 1,839 px wide, wider than a
1024 px screen.

(A bidi override or control in a path never reaches the list: the index
walk refuses such paths.)
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import cas as CAS  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

BID = "LocalFS:Local"


class DuplicateFinderLongPathTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        p = mock.patch.object(CAS, "_DEFAULT_DB", self.tmp / "cas.sqlite")
        p.start()
        self.addCleanup(p.stop)

    def _dialog(self, tree: Path):
        from ui.cas_dialog import CasDuplicatesDialog

        fs = LocalFS()
        CAS.rebuild(fs, str(tree), backend_id=BID)

        class _Pane:
            backend = fs
            current_path = str(tree)

        dlg = CasDuplicatesDialog(_Pane())
        self.addCleanup(dlg.deleteLater)
        return dlg

    def _rows(self, dlg):
        group = dlg._tree.topLevelItem(0)
        return [group.child(j) for j in range(group.childCount())]

    def test_happy_a_plain_name_is_shown_as_it_is(self) -> None:
        tree = self.tmp / "tree"
        tree.mkdir()
        for name in ("a.txt", "b.txt"):
            (tree / name).write_bytes(b"same\n")
        dlg = self._dialog(tree)
        self.assertEqual(sorted(r.text(0) for r in self._rows(dlg)), ["a.txt", "b.txt"])

    def test_edge_a_long_path_does_not_widen_the_window(self) -> None:
        tree = self.tmp / "tree"
        deep = tree
        for i in range(7):
            deep = deep / (("d" * 240) + str(i))
        deep.mkdir(parents=True)
        (deep / "a.bin").write_bytes(b"same\n")
        (tree / "b.bin").write_bytes(b"same\n")
        dlg = self._dialog(tree)
        dlg.resize(900, 500)
        dlg.show()
        row = next(r for r in self._rows(dlg) if r.text(0) == "a.bin")
        dlg._tree.setCurrentItem(row)
        self.app.processEvents()
        self.assertLess(dlg.minimumSizeHint().width(), 1024)
        self.assertEqual(dlg.width(), 900)
        self.assertIn(str(deep / "a.bin"), dlg._details.text())
