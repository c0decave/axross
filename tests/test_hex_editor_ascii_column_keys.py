"""Hex editor: only typed characters write bytes; control keys do not.

Reproduced 2026-10-17 in the ASCII column of the hex editor: Backspace,
Esc, Enter and Ctrl+C wrote 0x08, 0x1b, 0x0d and 0x03 into the data and
marked them modified, and Esc did not close the editor - every key with a
one-character text was taken as a byte to write.
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

DATA = b"ABCDEFGH"


class HexAsciiColumnKeysTest(unittest.TestCase):
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
        self.path.write_bytes(DATA)

    def open(self, ascii_column: bool = True):
        from PyQt6.QtCore import QPoint, Qt
        from PyQt6.QtTest import QTest

        from core.local_fs import LocalFS
        from ui.hex_editor import HexEditorDialog

        dlg = HexEditorDialog(LocalFS(), str(self.path), read_only=False)
        self.addCleanup(dlg.deleteLater)
        dlg.show()
        dlg._hex_widget.setFocus()
        if ascii_column:
            # A click in the ASCII column switches to ASCII editing.
            hexw = dlg._hex_widget
            QTest.mouseClick(
                hexw, Qt.MouseButton.LeftButton, pos=QPoint(int(hexw._ascii_start) + 2, 2)
            )
            self.assertFalse(hexw._editing_hex)
        return dlg

    def press(self, dlg, key, mods=None, text: str | None = None) -> None:
        """A key press as the platform delivers it, with its text."""
        from PyQt6.QtCore import QEvent, Qt
        from PyQt6.QtGui import QKeyEvent
        from PyQt6.QtWidgets import QApplication

        mods = Qt.KeyboardModifier.NoModifier if mods is None else mods
        event = QKeyEvent(QEvent.Type.KeyPress, key, mods, text or "")
        QApplication.sendEvent(dlg._hex_widget, event)

    # -- happy -----------------------------------------------------------------

    def test_happy_typed_characters_write_bytes(self) -> None:
        from PyQt6.QtCore import Qt

        dlg = self.open()
        self.press(dlg, Qt.Key.Key_H, Qt.KeyboardModifier.ShiftModifier, "H")
        self.press(dlg, Qt.Key.Key_I, text="i")
        self.press(dlg, Qt.Key.Key_Space, text=" ")
        self.press(dlg, Qt.Key.Key_Eacute, text="é")
        self.assertEqual(dlg._hex_widget.get_data(), b"Hi \xe9EFGH")
        self.assertEqual(sorted(dlg._hex_widget._modified_offsets), [0, 1, 2, 3])

    def test_happy_hex_digits_still_write_nibbles_also_from_the_keypad(self) -> None:
        from PyQt6.QtCore import Qt

        dlg = self.open(ascii_column=False)
        self.press(dlg, Qt.Key.Key_F, text="f")
        self.press(dlg, Qt.Key.Key_1, Qt.KeyboardModifier.KeypadModifier, "1")
        self.assertEqual(dlg._hex_widget.get_data()[:1], b"\xf1")

    # -- sad -------------------------------------------------------------------

    def test_sad_control_keys_in_the_ascii_column_write_nothing(self) -> None:
        from PyQt6.QtCore import Qt

        dlg = self.open()
        ctrl = Qt.KeyboardModifier.ControlModifier
        for key, mods, text in (
            (Qt.Key.Key_Backspace, None, "\x08"),
            (Qt.Key.Key_Return, None, "\r"),
            (Qt.Key.Key_Enter, Qt.KeyboardModifier.KeypadModifier, "\r"),
            (Qt.Key.Key_C, ctrl, "\x03"),
            (Qt.Key.Key_A, ctrl, "a"),  # some platforms give the letter
            (Qt.Key.Key_Delete, None, "\x7f"),
        ):
            self.press(dlg, key, mods, text)
        self.assertEqual(dlg._hex_widget.get_data(), DATA)
        self.assertFalse(dlg._hex_widget.is_modified)

    def test_sad_escape_in_the_ascii_column_closes_the_editor(self) -> None:
        from PyQt6.QtCore import Qt
        from PyQt6.QtWidgets import QDialog

        dlg = self.open()
        with mock.patch("ui.hex_editor.QMessageBox.question") as question:
            self.press(dlg, Qt.Key.Key_Escape, text="\x1b")
        question.assert_not_called()  # nothing was changed
        self.assertEqual(dlg._hex_widget.get_data(), DATA)
        self.assertFalse(dlg.isVisible())
        self.assertEqual(dlg.result(), QDialog.DialogCode.Rejected)

    # -- edge ------------------------------------------------------------------

    def test_edge_ctrl_with_a_hex_digit_writes_no_nibble(self) -> None:
        from PyQt6.QtCore import Qt

        dlg = self.open(ascii_column=False)
        self.press(dlg, Qt.Key.Key_B, Qt.KeyboardModifier.ControlModifier, "b")
        self.press(dlg, Qt.Key.Key_E, Qt.KeyboardModifier.ControlModifier, "\x05")
        self.assertEqual(dlg._hex_widget.get_data(), DATA)
        self.assertFalse(dlg._hex_widget.is_modified)

    def test_edge_altgr_characters_still_write(self) -> None:
        """Windows reports AltGr as Ctrl+Alt ("@" on a German keyboard),
        macOS' Option as Alt: the character they type is input."""
        from PyQt6.QtCore import Qt

        dlg = self.open()
        ctrl_alt = Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.AltModifier
        self.press(dlg, Qt.Key.Key_Q, ctrl_alt, "@")
        self.press(dlg, Qt.Key.Key_E, Qt.KeyboardModifier.AltModifier, "€")
        self.assertEqual(dlg._hex_widget.get_data()[:1], b"@")
        # "€" is not a Latin-1 character: no byte for it, nothing written.
        self.assertEqual(dlg._hex_widget.get_data()[1:], DATA[1:])

    def test_edge_escape_after_an_edit_asks_before_closing(self) -> None:
        from PyQt6.QtCore import Qt
        from PyQt6.QtWidgets import QMessageBox

        dlg = self.open()
        self.press(dlg, Qt.Key.Key_Z, text="z")
        with mock.patch(
            "ui.hex_editor.QMessageBox.question", return_value=QMessageBox.StandardButton.No
        ) as question:
            self.press(dlg, Qt.Key.Key_Escape, text="\x1b")
        question.assert_called_once()
        self.assertTrue(dlg.isVisible())
        self.assertEqual(dlg._hex_widget.get_data(), b"zBCDEFGH")


if __name__ == "__main__":
    unittest.main()
