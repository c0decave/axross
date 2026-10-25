"""Every viewer / dialog that has its own Close button also gets the [x]
in its top-right corner."""

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

ROOT = Path(__file__).resolve().parent.parent
MODULES = (
    "cas_dialog",
    "cas_history_dialog",
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
    "media_viewer",
    "dir_size_dialog",
    "archive_pane",
    "third_party_dialog",
)


class SourceGuardTest(unittest.TestCase):
    def test_every_close_button_dialog_installs_the_corner(self) -> None:
        for mod in MODULES:
            src = (ROOT / "ui" / f"{mod}.py").read_text(encoding="utf-8")
            self.assertRegex(src, r"add_close_corner\(", mod)

    def test_main_window_text_dialogs_install_it_too(self) -> None:
        """Every function of main_window.py that builds a QDialog installs the
        corner. Counted per function: a count over the file ("at least 3")
        fell when two text windows came to share _show_text_dialog."""
        import ast

        src = (ROOT / "ui" / "main_window.py").read_text(encoding="utf-8")
        builders, missing = [], []
        for node in ast.walk(ast.parse(src)):
            if not isinstance(node, ast.FunctionDef):
                continue
            calls = {
                c.func.id if isinstance(c.func, ast.Name) else getattr(c.func, "attr", "")
                for c in ast.walk(node) if isinstance(c, ast.Call)
            }
            if "QDialog" in calls:
                builders.append(node.name)
                if "add_close_corner" not in calls:
                    missing.append(node.name)
        self.assertTrue(builders)  # the scan found the text dialogs
        self.assertEqual(missing, [])


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

    def test_a_dialog_without_a_vertical_layout_gets_it_over_the_corner(self) -> None:
        # It used to be left without one; on a window manager without title
        # buttons such a dialog had no visible close control at all.
        from PyQt6.QtWidgets import QDialog, QHBoxLayout, QLabel

        from ui.close_corner import add_close_corner

        dlg = QDialog()
        QHBoxLayout(dlg).addWidget(QLabel("content"))
        self.addCleanup(dlg.deleteLater)
        btn = add_close_corner(dlg)
        self.assertIsNotNone(btn)
        for width in (500, 820):
            dlg.resize(width, 300)
            dlg.show()
            self.app.processEvents()
            pos = btn.mapTo(dlg, btn.rect().topLeft())
            self.assertGreater(pos.x(), width * 0.8, width)
            self.assertLess(pos.y(), 40)
        self.assertEqual(len(self._corner(dlg)), 1)

    def test_a_dialog_without_any_layout_gets_it_over_the_corner(self) -> None:
        from PyQt6.QtWidgets import QDialog

        from ui.close_corner import add_close_corner

        dlg = QDialog()
        self.addCleanup(dlg.deleteLater)
        btn = add_close_corner(dlg)
        dlg.resize(400, 200)
        dlg.show()
        self.app.processEvents()
        self.assertGreater(btn.mapTo(dlg, btn.rect().topLeft()).x(), 400 * 0.8)
        btn.click()
        self.assertEqual(dlg.result(), QDialog.DialogCode.Rejected)


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


_QT_PROMPTS = {"QMessageBox", "QInputDialog", "QProgressDialog", "QFileDialog", "QColorDialog"}


def _dialogs_and_corners(path: Path) -> tuple[int, int]:
    """(QDialog subclasses + bare ``QDialog(...)`` windows, add_close_corner calls)."""
    import ast

    tree = ast.parse(path.read_text(encoding="utf-8"))
    dialogs = corners = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            bases = {ast.unparse(b).split(".")[-1] for b in node.bases}
            if "QDialog" in bases:
                dialogs += 1
        elif isinstance(node, ast.Call):
            name = ast.unparse(node.func).split(".")[-1]
            if name == "QDialog":
                dialogs += 1
            elif name in ("add_close_corner", "make_close_corner"):
                corners += 1
    return dialogs, corners


class EveryDialogHasTheCornerTest(_Qt):
    """Every window the application opens as a QDialog - viewers, managers,
    editors, settings, the ad-hoc ones in main_window and the bundled
    extensions' - has the [x]. Found missing in 17 places (2026-10-16):
    Scripting Guide, Shortcuts, Extensions, Connection, Network Proxy, Pack,
    Permissions, Batch Rename, Bookmark and Group Edit, Create XLink, LLM and
    Metadata Settings, Transfer Conflict, Paste SSH Config, the entropy
    heatmap. Qt's own prompts (QMessageBox, QInputDialog, ...) keep their
    buttons."""

    def test_sad_no_module_opens_a_dialog_without_the_corner(self) -> None:
        missing = []
        for path in sorted(
            [*(ROOT / "ui").glob("*.py"), *(ROOT / "resources" / "extensions").glob("*.py")]
        ):
            if path.name == "close_corner.py":
                continue
            dialogs, corners = _dialogs_and_corners(path)
            if corners < dialogs:
                missing.append(
                    f"{path.relative_to(ROOT)}: {dialogs} dialog(s), {corners} corner(s)"
                )
        self.assertEqual(missing, [])

    def test_happy_the_viewer_dialogs_have_it_once_built(self) -> None:
        from PyQt6.QtWidgets import QToolButton

        from ui.scripting_guide import ScriptingGuideDialog
        from ui.shortcuts_dialog import ShortcutsDialog

        for dlg in (ShortcutsDialog(), ScriptingGuideDialog()):
            self.addCleanup(dlg.deleteLater)
            found = dlg.findChildren(QToolButton, "axCloseCorner")
            self.assertEqual(len(found), 1, type(dlg).__name__)

    def test_edge_the_counter_sees_classes_bare_dialogs_and_calls(self) -> None:
        import tempfile

        src = (
            "class A(QDialog):\n    pass\n"
            "class B(QtWidgets.QDialog):\n    pass\n"
            "class C(QMessageBox):\n    pass\n"
            "d = QDialog(parent)\n"
            "add_close_corner(d)\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as fh:
            fh.write(src)
        self.addCleanup(lambda: Path(fh.name).unlink())
        self.assertEqual(_dialogs_and_corners(Path(fh.name)), (3, 1))
