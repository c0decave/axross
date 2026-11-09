"""The pane's item count counts the rows shown; hidden entries are named
apart (UX review round 7, M4).

It said "10 items" while 7 were shown, and a folder that looked empty said
"1 item" because of a hidden .part file. Now: "7 items (3 hidden)",
"0 items (1 hidden)", and with a filter "3 of 7 items".
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


class ItemCountTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def pump(self, seconds: float = 0.1) -> None:
        end = time.time() + seconds
        while time.time() < end:
            self.app.processEvents()
            time.sleep(0.01)

    def _pane(self, names: list[str]):
        from core.local_fs import LocalFS
        from ui.file_pane import FilePaneWidget

        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        for name in names:
            Path(d, name).write_text("x")
        pane = FilePaneWidget(LocalFS())
        self.addCleanup(pane.deleteLater)
        pane.set_show_hidden(False)
        pane.navigate(d)
        self.pump()
        return pane

    # --- happy --------------------------------------------------------------

    def test_happy_hidden_entries_are_counted_apart(self) -> None:
        pane = self._pane(["a.txt", "b.txt", "c.txt", ".x", ".y", ".z"])
        self.assertEqual(pane._status.text(), "3 items (3 hidden)")

    def test_happy_showing_hidden_entries_counts_them(self) -> None:
        pane = self._pane(["a.txt", ".x"])
        pane.set_show_hidden(True)
        self.pump()
        self.assertEqual(pane._status.text(), "2 items")

    # --- sad ----------------------------------------------------------------

    def test_sad_a_folder_with_only_a_hidden_part_file_counts_none_shown(self) -> None:
        pane = self._pane([".big.iso.part"])
        self.assertEqual(pane._status.text(), "0 items (1 hidden)")

    def test_sad_a_message_in_the_status_line_is_not_overwritten(self) -> None:
        pane = self._pane(["a.txt", ".x"])
        pane._status.setText("Copied 1 path to the clipboard")
        pane.set_show_hidden(True)
        self.pump()
        self.assertEqual(pane._status.text(), "Copied 1 path to the clipboard")

    # --- edge ---------------------------------------------------------------

    def test_edge_a_filter_says_how_many_of_how_many(self) -> None:
        pane = self._pane(["alpha.txt", "beta.txt", "gamma.txt", ".hidden"])
        pane._filter_edit.setText("alp")
        self.pump()
        self.assertEqual(pane._status.text(), "1 of 3 items (1 hidden)")
        pane._filter_edit.setText("")
        self.pump()
        self.assertEqual(pane._status.text(), "3 items (1 hidden)")

    def test_edge_german(self) -> None:
        from core import i18n

        i18n.install("de")
        self.addCleanup(i18n.install, "en")
        pane = self._pane(["a.txt", "b.txt", ".x"])
        self.assertEqual(pane._status.text(), "2 Elemente (1 versteckt)")
        pane._filter_edit.setText("a")
        self.pump()
        self.assertEqual(pane._status.text(), "1 von 2 Elementen (1 versteckt)")


if __name__ == "__main__":
    unittest.main()
