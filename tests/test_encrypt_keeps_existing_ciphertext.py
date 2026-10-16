"""Encrypt File asks before replacing an existing ``.axenc``.

Measured before: the pane's Encrypt action wrote ``<name>.axenc`` with
``atomic_write`` whether or not that file existed. An earlier ciphertext
of the same name -- possibly the only copy of an older version, under a
different passphrase -- was replaced without a word. Decrypt in the same
pane asks before overwriting, and ``axross.encrypt`` refuses unless
``overwrite=True``; Encrypt was the odd one out.
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


class EncryptExistingCiphertextTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from PyQt6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from core import encrypted_overlay as E
        from core.local_fs import LocalFS
        from ui import column_prefs as CP
        from ui.file_pane import FilePaneWidget

        self.E = E
        self.root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        (self.root / "notes.txt").write_text("new plaintext")
        self.cipher = self.root / ("notes.txt" + E.ENC_SUFFIX)
        p = mock.patch.object(CP, "DEFAULT_PATH", self.root / "cols.json")
        p.start()
        self.addCleanup(p.stop)
        self.fs = LocalFS()
        self.pane = FilePaneWidget(self.fs)
        self.addCleanup(self.pane.deleteLater)
        self.pane.navigate(str(self.root))
        end = 0
        while self.pane.is_loading and end < 3000:
            self.app.processEvents()
            end += 1

    def item(self, name: str):
        from models.file_item import FileItem

        return FileItem(name=name, size=0, is_dir=False)

    def encrypt(self, answer):
        from PyQt6.QtWidgets import QMessageBox

        with mock.patch(
            "PyQt6.QtWidgets.QInputDialog.getText", side_effect=[("pw", True), ("pw", True)]
        ), mock.patch(
            "ui.file_pane.QMessageBox.question",
            return_value=answer or QMessageBox.StandardButton.No,
        ) as question, mock.patch("ui.file_pane.QMessageBox.information"), mock.patch(
            "ui.file_pane.QMessageBox.critical"
        ) as critical:
            self.pane._encrypt_selected_file(self.item("notes.txt"))
        critical.assert_not_called()
        return question

    def test_happy_a_first_encryption_asks_nothing(self) -> None:
        question = self.encrypt(None)
        question.assert_not_called()
        self.assertEqual(self.E.read_encrypted(self.fs, str(self.cipher), "pw"), b"new plaintext")

    def test_sad_declining_keeps_the_existing_ciphertext(self) -> None:
        from PyQt6.QtWidgets import QMessageBox

        self.E.write_encrypted(self.fs, str(self.root / "notes.txt"), b"old version", "old-pw")
        question = self.encrypt(QMessageBox.StandardButton.No)
        question.assert_called_once()
        self.assertEqual(
            self.E.read_encrypted(self.fs, str(self.cipher), "old-pw"), b"old version"
        )

    def test_edge_confirming_replaces_it(self) -> None:
        from PyQt6.QtWidgets import QMessageBox

        self.E.write_encrypted(self.fs, str(self.root / "notes.txt"), b"old version", "old-pw")
        self.encrypt(QMessageBox.StandardButton.Yes)
        self.assertEqual(self.E.read_encrypted(self.fs, str(self.cipher), "pw"), b"new plaintext")


if __name__ == "__main__":
    unittest.main()
