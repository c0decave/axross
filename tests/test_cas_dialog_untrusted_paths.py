"""The Duplicate Finder's details line shows a copy's path as text.

The details line under the list is where the user reads the full path of
the copy they are about to keep or remove. A path is the file's own
name, from any server the index covers: shown with Qt's rich-text guess,
a file named ``<b>…</b>`` or ``<img width=4000 …>`` restyled the line,
hid the real path or laid the dialog out thousands of pixels wide.
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
#: A file name that, as rich text, lays a label out huge.
WIDE = "<img width=4000 height=4000 src=x>"


class DetailsTest(unittest.TestCase):
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

    def test_sad_a_markup_file_name_is_shown_as_text(self) -> None:
        from PyQt6.QtCore import Qt

        from ui.cas_dialog import CasDuplicatesDialog

        (self.tmp / "tree").mkdir()
        evil = self.tmp / "tree" / WIDE
        evil.write_bytes(b"same content\n")
        (self.tmp / "tree" / "plain.txt").write_bytes(b"same content\n")
        fs = LocalFS()
        CAS.rebuild(fs, str(self.tmp / "tree"), backend_id=BID)

        class _Pane:
            backend = fs
            current_path = str(self.tmp / "tree")

        dlg = CasDuplicatesDialog(_Pane())
        self.addCleanup(dlg.deleteLater)
        tree = dlg._tree
        group = tree.topLevelItem(0)
        row = next(group.child(j) for j in range(group.childCount())
                   if group.child(j).text(0) == WIDE)
        tree.setCurrentItem(row)
        self.assertIn(WIDE, dlg._details.text())
        self.assertEqual(dlg._details.textFormat(), Qt.TextFormat.PlainText)
        self.assertLess(dlg._details.sizeHint().width(), 2000)

    def test_sad_a_markup_file_name_is_text_in_the_row_tooltip(self) -> None:
        """The row tooltip (name and folder columns) shows the same path:
        set as it is, Qt rendered it as rich text - an image 4000 pixels
        wide over the list instead of the path (0.15.59 fixed only the
        details line)."""
        from tests.markup_probe import BOLD_FILE as BOLD, shown, tooltip_width

        from ui.cas_dialog import COL_FOLDER, COL_NAME, CasDuplicatesDialog

        (self.tmp / "tree").mkdir()
        (self.tmp / "tree" / WIDE).write_bytes(b"same content\n")
        (self.tmp / "tree" / BOLD).write_bytes(b"same content\n")
        (self.tmp / "tree" / "a  b").write_bytes(b"same content\n")
        fs = LocalFS()
        CAS.rebuild(fs, str(self.tmp / "tree"), backend_id=BID)

        class _Pane:
            backend = fs
            current_path = str(self.tmp / "tree")

        dlg = CasDuplicatesDialog(_Pane())
        self.addCleanup(dlg.deleteLater)
        group = dlg._tree.topLevelItem(0)
        rows = {group.child(j).text(COL_NAME): group.child(j)
                for j in range(group.childCount())}
        for name in (WIDE, BOLD, "a  b"):
            for col in (COL_NAME, COL_FOLDER):
                tip = rows[name].toolTip(col)
                self.assertEqual(shown(tip), str(self.tmp / "tree" / name), (name, col))
        self.assertLess(tooltip_width(rows[WIDE].toolTip(COL_NAME)), 2000)
