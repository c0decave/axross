"""Exporting profiles leaves the chosen folder's permissions alone.

File > Export Profiles wrote through
``_write_private_text``, which chmods the target's PARENT to 0700 - meant
for ~/.config/axross. Exporting into a team share, the home folder or
~/public_html silently locked everybody else out of that folder. Only the
exported file itself is private (0600).
"""

from __future__ import annotations

import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def _mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


class WritePrivateTextTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_happy_a_foreign_folder_keeps_its_mode(self) -> None:
        from ui.main_window import _write_private_text

        shared = self.tmp / "shared"
        shared.mkdir()
        os.chmod(shared, 0o775)
        _write_private_text(shared / "profiles.json", "{}\n", private_dir=False)
        self.assertEqual(_mode(shared), 0o775)
        self.assertEqual(_mode(shared / "profiles.json"), 0o600)
        self.assertEqual((shared / "profiles.json").read_text(), "{}\n")

    def test_sad_a_missing_foreign_folder_is_not_created(self) -> None:
        from ui.main_window import _write_private_text

        with self.assertRaises(OSError):
            _write_private_text(self.tmp / "gone" / "profiles.json", "{}", private_dir=False)
        self.assertFalse((self.tmp / "gone").exists())

    def test_edge_the_own_config_folder_is_still_made_private(self) -> None:
        from ui.main_window import _write_private_text

        config = self.tmp / "config"
        config.mkdir()
        os.chmod(config, 0o755)
        _write_private_text(config / "recents.json", "[]")
        self.assertEqual(_mode(config), 0o700)


class ExportDialogTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def test_happy_export_through_the_menu_keeps_the_folder_mode(self) -> None:
        from ui import main_window as MW

        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        with mock.patch("pathlib.Path.home", return_value=tmp):
            win = MW.MainWindow()
        self.addCleanup(win.deleteLater)
        self.addCleanup(win.close)
        shared = tmp / "team"
        shared.mkdir()
        os.chmod(shared, 0o2775)
        target = shared / "profiles.json"
        with (
            mock.patch(
                "PyQt6.QtWidgets.QFileDialog.getSaveFileName", return_value=(str(target), "")
            ),
            mock.patch.object(MW.QMessageBox, "information"),
            mock.patch.object(MW.QMessageBox, "warning"),
        ):
            win._export_profiles_json()
        self.assertTrue(target.exists())
        self.assertEqual(_mode(shared), 0o2775)
        self.assertEqual(_mode(target), 0o600)


if __name__ == "__main__":
    unittest.main()
