"""Every viewer / dialog that has its own Close button also gets the [x]
in its top-right corner."""

from __future__ import annotations

import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(__file__).resolve().parent.parent
MODULES = (
    "cas_dialog",
    "checksum_dialog",
    "metadata_search_dialog",
    "scheduler_dialog",
    "trash_browser",
    "image_viewer",
    "elevated_viewer",
    "snapshot_browser_dialog",
    "compare_dialog",
    "disk_usage_dialog",
    "properties_dialog",
)


class SourceGuardTest(unittest.TestCase):
    def test_every_close_button_dialog_installs_the_corner(self) -> None:
        for mod in MODULES:
            src = (ROOT / "ui" / f"{mod}.py").read_text(encoding="utf-8")
            self.assertRegex(src, r"add_close_corner\(", mod)

    def test_main_window_text_dialogs_install_it_too(self) -> None:
        src = (ROOT / "ui" / "main_window.py").read_text(encoding="utf-8")
        self.assertGreaterEqual(len(re.findall(r"add_close_corner\(", src)), 3)


class _Qt(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])


class HelperTest(_Qt):
    def _dialog(self):
        from PyQt6.QtWidgets import QDialog, QLabel, QVBoxLayout

        dlg = QDialog()
        lay = QVBoxLayout(dlg)
        lay.addWidget(QLabel("content"))
        self.addCleanup(dlg.deleteLater)
        return dlg

    def _corner(self, dlg):
        from PyQt6.QtWidgets import QToolButton

        return dlg.findChildren(QToolButton, "axCloseCorner")

    def test_the_button_sits_at_the_top_right(self) -> None:
        from ui.close_corner import add_close_corner

        dlg = self._dialog()
        btn = add_close_corner(dlg)
        dlg.resize(500, 300)
        dlg.show()
        self.app.processEvents()
        pos = btn.mapTo(dlg, btn.rect().topLeft())
        self.assertGreater(pos.x(), dlg.width() * 0.8)
        self.assertLess(pos.y(), 40)
        self.assertFalse(btn.icon().isNull())

    def test_it_sits_above_the_existing_content(self) -> None:
        from PyQt6.QtWidgets import QLabel

        from ui.close_corner import add_close_corner

        dlg = self._dialog()
        btn = add_close_corner(dlg)
        dlg.show()
        self.app.processEvents()
        label = dlg.findChild(QLabel)
        self.assertLess(
            btn.mapTo(dlg, btn.rect().bottomLeft()).y(),
            label.mapTo(dlg, label.rect().topLeft()).y() + 1,
        )

    def test_clicking_it_rejects_the_dialog(self) -> None:
        from PyQt6.QtWidgets import QDialog

        from ui.close_corner import add_close_corner

        dlg = self._dialog()
        btn = add_close_corner(dlg)
        dlg.show()
        btn.click()
        self.assertFalse(dlg.isVisible())
        self.assertEqual(dlg.result(), QDialog.DialogCode.Rejected)

    def test_it_goes_through_a_custom_reject(self) -> None:
        from ui.close_corner import add_close_corner

        dlg = self._dialog()
        seen = []
        dlg.reject = lambda: seen.append(1)
        btn = add_close_corner(dlg)
        btn.click()
        self.assertEqual(seen, [1])

    def test_installing_twice_adds_only_one_button(self) -> None:
        from ui.close_corner import add_close_corner

        dlg = self._dialog()
        first = add_close_corner(dlg)
        second = add_close_corner(dlg)
        self.assertIs(first, second)
        self.assertEqual(len(self._corner(dlg)), 1)

    def test_a_dialog_without_a_vertical_layout_is_left_alone(self) -> None:
        from PyQt6.QtWidgets import QDialog, QHBoxLayout

        from ui.close_corner import add_close_corner

        dlg = QDialog()
        QHBoxLayout(dlg)
        self.addCleanup(dlg.deleteLater)
        self.assertIsNone(add_close_corner(dlg))
        self.assertEqual(len(self._corner(dlg)), 0)

    def test_a_dialog_without_any_layout_is_left_alone(self) -> None:
        from PyQt6.QtWidgets import QDialog

        from ui.close_corner import add_close_corner

        dlg = QDialog()
        self.addCleanup(dlg.deleteLater)
        self.assertIsNone(add_close_corner(dlg))


class RealDialogTest(_Qt):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        for target, name in (
            ("core.cas._DEFAULT_DB", "cas.db"),
            ("core.metadata_index._DEFAULT_DB", "meta.db"),
        ):
            p = mock.patch(target, Path(self.tmp) / name)
            p.start()
            self.addCleanup(p.stop)

    def _corner(self, dlg):
        from PyQt6.QtWidgets import QToolButton

        return dlg.findChild(QToolButton, "axCloseCorner")

    def test_duplicate_finder_has_it_and_it_stops_a_running_scan(self) -> None:
        import threading
        import time

        from core import cas as CAS
        from core.local_fs import LocalFS
        from ui.cas_dialog import CasDuplicatesDialog

        tree = Path(self.tmp) / "tree"
        tree.mkdir()
        for i in range(40):
            (tree / f"f{i}.txt").write_text(str(i))
        hashed = []
        gate = threading.Event()
        real = LocalFS.checksum

        def slow(fs, path, algorithm="sha256"):
            hashed.append(path)
            gate.wait(timeout=0.04)
            return real(fs, path, algorithm)

        class _Pane:
            backend = LocalFS()
            current_path = str(tree)

        with (
            mock.patch.object(LocalFS, "checksum", slow),
            mock.patch("ui.cas_dialog.QMessageBox.question") as ask,
        ):
            from PyQt6.QtWidgets import QMessageBox

            ask.return_value = QMessageBox.StandardButton.Yes
            dlg = CasDuplicatesDialog(_Pane())
            self.addCleanup(dlg.deleteLater)
            dlg.show()
            self.assertIsNotNone(self._corner(dlg))
            dlg._do_rebuild_active()
            end = time.time() + 5
            while len(hashed) < 3 and time.time() < end:
                self.app.processEvents()
                time.sleep(0.01)
            self._corner(dlg).click()
            self.assertFalse(dlg.isVisible())
            time.sleep(0.3)
        self.assertLess(len(hashed), 40)
        _ = CAS

    def test_find_in_index_has_it(self) -> None:
        from ui.metadata_search_dialog import MetadataSearchDialog

        dlg = MetadataSearchDialog(None)
        self.addCleanup(dlg.deleteLater)
        self.assertIsNotNone(self._corner(dlg))

    def test_the_versions_dialog_has_it(self) -> None:
        from core.local_fs import LocalFS
        from ui.snapshot_browser_dialog import SnapshotBrowserDialog

        with mock.patch("core.snapshot_browser.browse", lambda b, p: []):
            dlg = SnapshotBrowserDialog(LocalFS(), "/tmp/x")
        self.addCleanup(dlg.deleteLater)
        self.assertIsNotNone(self._corner(dlg))


if __name__ == "__main__":
    unittest.main()
