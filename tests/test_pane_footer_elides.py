"""The pane footer cuts a long message with "…" and keeps it whole in the
tooltip; the free space gives up its room first (UX review round 7, M2).

After Ctrl+C at 1024x600 the footer read "2 Pfade in die Zwische" and
"Frei: 249,0 MB / 274,5", cut mid-word with no way to read the rest; at
1280x800 the German "Strg+V …" instruction did not show at all.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

LONG = ("2 Pfade in die Zwischenablage kopiert – Einfügen (Strg+V) in einem Ordner "
        "kopiert die Dateien dorthin")


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def pump(self, seconds: float = 0.05) -> None:
        end = time.time() + seconds
        while time.time() < end:
            self.app.processEvents()
            time.sleep(0.01)


class ElidedLabelTest(_Base):
    def _label(self, text: str, width: int):
        from ui.elided_label import ElidedLabel

        label = ElidedLabel(text)
        self.addCleanup(label.deleteLater)
        label.resize(width, 20)
        label.show()
        self.pump()
        return label

    def test_happy_a_long_text_is_cut_with_an_ellipsis_and_whole_in_the_tooltip(self) -> None:
        label = self._label(LONG, 200)
        self.assertEqual(label.text(), LONG)
        self.assertTrue(label.shown_text().endswith("…"), label.shown_text())
        self.assertTrue(LONG.startswith(label.shown_text()[:-1]))
        self.assertEqual(label.toolTip(), LONG)

    def test_sad_a_text_that_fits_has_no_tooltip_of_its_own(self) -> None:
        label = self._label("10 items", 300)
        self.assertEqual(label.shown_text(), "10 items")
        self.assertEqual(label.toolTip(), "")

    def test_edge_the_short_form_comes_before_the_cut(self) -> None:
        from ui.elided_label import ElidedLabel

        label = ElidedLabel()
        self.addCleanup(label.deleteLater)
        label.set_texts("Free: 249.0 MB / 274.5 GB (99% used)", "Free: 249.0 MB")
        width = label.fontMetrics().horizontalAdvance("Free: 249.0 MB") + 6
        label.resize(width, 20)
        label.show()
        self.pump()
        self.assertEqual(label.shown_text(), "Free: 249.0 MB")
        label.resize(12, 20)
        self.pump()
        self.assertEqual(label.shown_text(), "")  # no "Fr…" stub


class PaneFooterTest(_Base):
    def _window(self, width: int):
        from PyQt6.QtWidgets import QMainWindow

        from core.local_fs import LocalFS
        from ui.file_pane import FilePaneWidget

        d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, d, True)
        win = QMainWindow()
        self.addCleanup(win.deleteLater)
        pane = FilePaneWidget(LocalFS())
        win.setCentralWidget(pane)
        pane.navigate(d)
        win.resize(width, 500)
        win.show()
        self.pump(0.2)
        pane._disk_label.set_texts("Free: 249.0 MB / 274.5 GB (99% used)", "Free: 249.0 MB")
        self.pump()
        return win, pane

    def test_happy_the_message_is_cut_with_an_ellipsis_not_mid_word(self) -> None:
        win, pane = self._window(330)
        pane._feedback(LONG)
        self.pump()
        self.assertEqual(pane._status.text(), LONG)
        self.assertTrue(pane._status.shown_text().endswith("…"))
        self.assertEqual(pane._status.toolTip(), LONG)
        # and whole in the window's status bar
        self.assertEqual(win.statusBar().currentMessage(), LONG)

    def test_sad_the_free_space_gives_way_before_the_message(self) -> None:
        win, pane = self._window(1200)
        text = "Copied 2 paths to the clipboard – Paste (Ctrl+V) copies them"
        pane._feedback(text)
        need = pane._status.fontMetrics().horizontalAdvance(text)
        seen_yield = False
        for width in range(1200, 300, -40):
            win.resize(width, 500)
            self.pump()
            message_whole = pane._status.shown_text() == text
            disk_whole = pane._disk_label.shown_text() == pane._disk_label.text()
            # never the message cut while the free space is shown whole
            self.assertFalse(not message_whole and disk_whole, width)
            if pane._status_row.message_room() >= need + 4:
                self.assertTrue(message_whole, width)
            seen_yield |= message_whole and not disk_whole
        self.assertTrue(seen_yield, "the free space never gave way")

    def test_edge_a_short_message_leaves_the_free_space_whole(self) -> None:
        win, pane = self._window(900)
        pane._feedback("3 items")
        self.pump()
        self.assertEqual(pane._status.shown_text(), "3 items")
        self.assertEqual(pane._disk_label.shown_text(), pane._disk_label.text())
        self.assertEqual(win.statusBar().currentMessage(), "")


if __name__ == "__main__":
    unittest.main()
