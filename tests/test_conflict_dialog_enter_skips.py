"""Enter in the "File Already Exists" prompt skips the file.

Measured before: with one conflict, the focus landed on the first button
(Overwrite) and Qt made the focused "auto default" button the default, so
pressing Enter replaced the existing file.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


class ConflictDialogEnterTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def conflict(self, *, dest_is_dir=False):
        from core.transfer_conflicts import TransferConflict

        return TransferConflict(
            name="f.txt", source_path="/a/f.txt", dest_path="/b/f.txt", dest_dir="/b",
            source_is_dir=False, dest_is_dir=dest_is_dir,
            source_size=3, dest_size=4, source_mtime=2.0e9, dest_mtime=1.0e9,
        )

    def press(self, dialog, key):
        from PyQt6.QtTest import QTest
        from PyQt6.QtWidgets import QApplication

        dialog.show()
        dialog.activateWindow()
        for _ in range(5):
            QApplication.processEvents()
        target = QApplication.focusWidget() or dialog
        QTest.keyClick(target, key)
        for _ in range(5):
            QApplication.processEvents()
        return dialog.result_choice()

    def test_happy_return_skips_a_single_conflict(self) -> None:
        from PyQt6.QtCore import Qt

        from core.transfer_conflicts import ConflictAction
        from ui.transfer_conflict_dialog import TransferConflictDialog

        dialog = TransferConflictDialog(self.conflict(), remaining=0)
        try:
            self.assertEqual(self.press(dialog, Qt.Key.Key_Return), (ConflictAction.SKIP, False))
        finally:
            dialog.close()
            dialog.deleteLater()

    def test_sad_no_overwrite_button_is_default_or_auto_default(self) -> None:
        from core.transfer_conflicts import ConflictAction
        from ui.transfer_conflict_dialog import TransferConflictDialog

        dialog = TransferConflictDialog(self.conflict(), remaining=3)
        try:
            dialog.show()
            for _ in range(5):
                self.app.processEvents()
            for action in (ConflictAction.OVERWRITE, ConflictAction.OVERWRITE_IF_NEWER):
                self.assertFalse(dialog.buttons[action].isDefault())
                self.assertFalse(dialog.buttons[action].autoDefault())
            self.assertTrue(dialog.buttons[ConflictAction.SKIP].isDefault())
        finally:
            dialog.close()
            dialog.deleteLater()

    def test_edge_enter_skips_a_folder_against_a_file_too(self) -> None:
        from PyQt6.QtCore import Qt

        from core.transfer_conflicts import ConflictAction
        from ui.transfer_conflict_dialog import TransferConflictDialog

        dialog = TransferConflictDialog(self.conflict(dest_is_dir=True), remaining=2)
        try:
            self.assertEqual(self.press(dialog, Qt.Key.Key_Enter), (ConflictAction.SKIP, False))
        finally:
            dialog.close()
            dialog.deleteLater()

    def test_edge_remaining_count_reads_as_a_sentence(self) -> None:
        from ui.transfer_conflict_dialog import TransferConflictDialog

        one = TransferConflictDialog(self.conflict(), remaining=1)
        many = TransferConflictDialog(self.conflict(), remaining=4)
        try:
            self.assertNotIn("(s)", one.apply_all.text())
            self.assertIn("4", many.apply_all.text())
            self.assertNotIn("(s)", many.apply_all.text())
        finally:
            one.deleteLater()
            many.deleteLater()


if __name__ == "__main__":
    unittest.main()
