"""Text and hex editor: a [x] in the top-right corner next to the Close button."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


class EditorCloseButtonTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.file = Path(self._tmp.name) / "note.txt"
        self.file.write_text("hello\n", encoding="utf-8")

    def _text(self):
        from core.local_fs import LocalFS
        from ui.text_editor import TextEditorDialog

        dlg = TextEditorDialog(LocalFS(), str(self.file))
        self.addCleanup(dlg.deleteLater)
        return dlg

    def _hex(self):
        from core.local_fs import LocalFS
        from ui.hex_editor import HexEditorDialog

        dlg = HexEditorDialog(LocalFS(), str(self.file))
        self.addCleanup(dlg.deleteLater)
        return dlg

    def _corner(self, dlg):
        from PyQt6.QtWidgets import QToolButton

        return dlg.findChild(QToolButton, "axCloseCorner")

    def _both(self):
        return (("text", self._text), ("hex", self._hex))

    def test_there_is_a_close_button_in_the_top_right_corner(self) -> None:
        for kind, make in self._both():
            with self.subTest(kind):
                dlg = make()
                dlg.resize(800, 500)
                dlg.show()
                self.app.processEvents()
                btn = self._corner(dlg)
                self.assertIsNotNone(btn)
                pos = btn.mapTo(dlg, btn.rect().topLeft())
                self.assertGreater(pos.x(), dlg.width() * 0.8, "not on the right")
                self.assertLess(pos.y(), 60, "not at the top")
                self.assertTrue(btn.toolTip())
                self.assertFalse(btn.icon().isNull())

    def test_clicking_it_closes_a_clean_editor(self) -> None:
        for kind, make in self._both():
            with self.subTest(kind):
                dlg = make()
                dlg.show()
                self._corner(dlg).click()
                self.app.processEvents()
                self.assertFalse(dlg.isVisible())

    def test_unsaved_changes_still_ask_before_closing(self) -> None:
        dlg = self._text()
        dlg.show()
        dlg._editor.setPlainText("changed")
        with mock.patch("ui.text_editor.QMessageBox.question") as ask:
            ask.return_value = __import__(
                "PyQt6.QtWidgets", fromlist=["QMessageBox"]
            ).QMessageBox.StandardButton.No
            self._corner(dlg).click()
        ask.assert_called_once()
        self.assertTrue(dlg.isVisible())

    def test_hex_unsaved_changes_still_ask_before_closing(self) -> None:
        from PyQt6.QtWidgets import QMessageBox

        dlg = self._hex()
        dlg.show()
        dlg._hex_widget._modified_offsets.add(0)
        with mock.patch("ui.hex_editor.QMessageBox.question") as ask:
            ask.return_value = QMessageBox.StandardButton.No
            self._corner(dlg).click()
        ask.assert_called_once()
        self.assertTrue(dlg.isVisible())

    def test_discarding_changes_closes(self) -> None:
        from PyQt6.QtWidgets import QMessageBox

        dlg = self._text()
        dlg.show()
        dlg._editor.setPlainText("changed")
        with mock.patch("ui.text_editor.QMessageBox.question") as ask:
            ask.return_value = QMessageBox.StandardButton.Yes
            self._corner(dlg).click()
        self.assertFalse(dlg.isVisible())

    def test_escape_does_not_drop_unsaved_changes_silently(self) -> None:
        from PyQt6.QtWidgets import QMessageBox

        dlg = self._text()
        dlg.show()
        dlg._editor.setPlainText("changed")
        with mock.patch("ui.text_editor.QMessageBox.question") as ask:
            ask.return_value = QMessageBox.StandardButton.No
            dlg.reject()
        ask.assert_called_once()
        self.assertTrue(dlg.isVisible())

    def test_the_bottom_close_button_is_still_there(self) -> None:
        for kind, make in self._both():
            with self.subTest(kind):
                dlg = make()
                self.assertEqual(dlg._btn_close.text(), "Close")

    def test_read_only_viewer_has_the_corner_button_too(self) -> None:
        from core.local_fs import LocalFS
        from ui.text_editor import TextEditorDialog

        dlg = TextEditorDialog(LocalFS(), str(self.file), read_only=True)
        self.addCleanup(dlg.deleteLater)
        self.assertIsNotNone(self._corner(dlg))


if __name__ == "__main__":
    unittest.main()
