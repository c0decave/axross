""""View Hex" (read-only) does not change bytes, not even in memory.

Found in review (round 2): read-only only hid the Save button. Typing in
the hex or ASCII column still rewrote the bytes in the view, marked them
modified, reported "Modified (N bytes changed)" and asked to discard
changes on close - a viewer showing bytes the file does not contain.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


class HexReadOnlyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.path = self.tmp / "blob.bin"
        self.path.write_bytes(b"\x00\x01\x02\x03hello")

    def open(self, read_only: bool):
        from core.local_fs import LocalFS
        from ui.hex_editor import HexEditorDialog

        dlg = HexEditorDialog(LocalFS(), str(self.path), read_only=read_only)
        self.addCleanup(dlg.deleteLater)
        dlg.show()
        dlg._hex_widget.setFocus()
        return dlg

    def type(self, dlg, *keys) -> None:
        from PyQt6.QtTest import QTest

        for key in keys:
            if isinstance(key, str):
                QTest.keyClicks(dlg._hex_widget, key)
            else:
                QTest.keyClick(dlg._hex_widget, key)

    def test_happy_the_editor_still_edits(self) -> None:
        dlg = self.open(read_only=False)
        self.type(dlg, "FF")
        self.assertEqual(dlg._hex_widget.get_data()[:1], b"\xff")
        self.assertTrue(dlg._hex_widget.is_modified)

    def test_sad_typing_hex_digits_in_the_viewer_changes_nothing(self) -> None:
        dlg = self.open(read_only=True)
        self.type(dlg, "FFAB")
        self.assertEqual(dlg._hex_widget.get_data(), self.path.read_bytes())
        self.assertFalse(dlg._hex_widget.is_modified)
        self.assertNotIn("Modified", dlg._status_label.text())

    def test_sad_typing_in_the_ascii_column_of_the_viewer_changes_nothing(self) -> None:
        from PyQt6.QtCore import QPoint, Qt
        from PyQt6.QtTest import QTest

        dlg = self.open(read_only=True)
        hexw = dlg._hex_widget
        # A click in the ASCII column switches to ASCII editing.
        QTest.mouseClick(
            hexw, Qt.MouseButton.LeftButton, pos=QPoint(int(hexw._ascii_start) + 2, 2)
        )
        self.assertFalse(hexw._editing_hex)
        self.type(dlg, "zz")
        self.assertEqual(dlg._hex_widget.get_data(), self.path.read_bytes())
        self.assertFalse(dlg._hex_widget.is_modified)

    def test_edge_the_viewer_still_navigates_and_closes_without_asking(self) -> None:
        from PyQt6.QtCore import Qt

        dlg = self.open(read_only=True)
        self.type(dlg, "7", Qt.Key.Key_Right, Qt.Key.Key_Right, Qt.Key.Key_Right)
        self.assertEqual(dlg._hex_widget._cursor_pos, 1)
        with mock.patch("ui.hex_editor.QMessageBox.question") as question:
            dlg._on_close()
        question.assert_not_called()
        self.assertEqual(self.path.read_bytes(), b"\x00\x01\x02\x03hello")


if __name__ == "__main__":
    unittest.main()
