"""Configurable maximum size for opening files in the viewers / editors."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import open_limits as OL  # noqa: E402

MIB = 1024 * 1024


class _Settings(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "settings.json"
        patcher = mock.patch.object(OL, "SETTINGS_PATH", self.path)
        patcher.start()
        self.addCleanup(patcher.stop)


class SettingTest(_Settings):
    def test_default_is_at_least_32_mib(self) -> None:
        self.assertGreaterEqual(OL.DEFAULT_MAX_OPEN_MB, 32)
        self.assertEqual(OL.max_open_bytes(), OL.DEFAULT_MAX_OPEN_MB * MIB)

    def test_set_persists_and_is_read_back(self) -> None:
        OL.set_max_open_mb(64)
        self.assertEqual(OL.max_open_mb(), 64)
        self.assertEqual(OL.max_open_bytes(), 64 * MIB)
        self.assertEqual(json.loads(self.path.read_text())["max_open_mb"], 64)

    def test_other_settings_keys_survive_a_write(self) -> None:
        self.path.write_text(json.dumps({"keep": "me"}), encoding="utf-8")
        OL.set_max_open_mb(48)
        self.assertEqual(json.loads(self.path.read_text())["keep"], "me")

    def test_out_of_range_values_are_rejected(self) -> None:
        for bad in (0, -5, OL.MAX_MAX_OPEN_MB + 1):
            with self.assertRaises(ValueError):
                OL.set_max_open_mb(bad)
        self.assertEqual(OL.max_open_mb(), OL.DEFAULT_MAX_OPEN_MB)

    def test_non_numbers_are_rejected(self) -> None:
        for bad in ("many", None, 3.5, True):
            with self.assertRaises((ValueError, TypeError)):
                OL.set_max_open_mb(bad)

    def test_hostile_or_broken_files_fall_back_to_the_default(self) -> None:
        for raw in (
            "not json",
            "[]",
            '{"max_open_mb": "9"}',
            '{"max_open_mb": -1}',
            '{"max_open_mb": 99999999}',
            '{"max_open_mb": true}',
            '{"max_open_mb": 1.5}',
        ):
            self.path.write_text(raw, encoding="utf-8")
            self.assertEqual(OL.max_open_mb(), OL.DEFAULT_MAX_OPEN_MB, raw)

    def test_missing_file_gives_the_default(self) -> None:
        self.assertEqual(OL.max_open_mb(), OL.DEFAULT_MAX_OPEN_MB)

    def test_settings_file_is_private(self) -> None:
        OL.set_max_open_mb(40)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_lower_limits_are_allowed(self) -> None:
        OL.set_max_open_mb(1)
        self.assertEqual(OL.max_open_bytes(), MIB)


class _QtCase(_Settings):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def _file(self, size: int, name: str = "big.txt") -> Path:
        p = Path(self._tmp.name) / name
        with open(p, "wb") as f:
            f.truncate(size)
            f.seek(0)
            f.write(b"hello\n")
        return p


class EditorLimitTest(_QtCase):
    def test_text_editor_opens_files_over_the_old_limits(self) -> None:
        from core.local_fs import LocalFS
        from ui.text_editor import TextEditorDialog

        p = self._file(5 * MIB)
        with mock.patch("ui.text_editor.QMessageBox.warning") as warn:
            dlg = TextEditorDialog(LocalFS(), str(p))
            self.addCleanup(dlg.deleteLater)
        warn.assert_not_called()
        self.assertTrue(dlg._editor.toPlainText().startswith("hello"))

    def test_text_editor_refuses_beyond_the_limit_and_names_it(self) -> None:
        from core.local_fs import LocalFS
        from ui.text_editor import TextEditorDialog

        OL.set_max_open_mb(2)
        p = self._file(3 * MIB)
        with mock.patch("ui.text_editor.QMessageBox.warning") as warn:
            dlg = TextEditorDialog(LocalFS(), str(p))
            self.addCleanup(dlg.deleteLater)
        warn.assert_called_once()
        self.assertIn("2 MB", warn.call_args[0][2])

    def test_a_raised_limit_takes_effect_without_restart(self) -> None:
        from core.local_fs import LocalFS
        from ui.text_editor import TextEditorDialog

        OL.set_max_open_mb(2)
        p = self._file(3 * MIB)
        OL.set_max_open_mb(8)
        with mock.patch("ui.text_editor.QMessageBox.warning") as warn:
            dlg = TextEditorDialog(LocalFS(), str(p))
            self.addCleanup(dlg.deleteLater)
        warn.assert_not_called()

    def test_read_capped_follows_the_setting(self) -> None:
        import io

        from ui import hex_editor as HE
        from ui import text_editor as TE

        OL.set_max_open_mb(1)
        blob = b"x" * (MIB + 1)
        with self.assertRaises(TE.EditorReadLimitError):
            TE._read_capped(io.BytesIO(blob))
        with self.assertRaises(HE.HexEditorReadLimitError):
            HE._read_capped(io.BytesIO(blob))
        OL.set_max_open_mb(2)
        self.assertEqual(len(TE._read_capped(io.BytesIO(blob))), MIB + 1)
        self.assertEqual(len(HE._read_capped(io.BytesIO(blob))), MIB + 1)

    def test_hex_editor_opens_20_mib_and_refuses_over_the_limit(self) -> None:
        from core.local_fs import LocalFS
        from ui.hex_editor import HexEditorDialog

        p = self._file(20 * MIB, "blob.bin")
        with mock.patch("ui.hex_editor.QMessageBox.warning") as warn:
            dlg = HexEditorDialog(LocalFS(), str(p))
            self.addCleanup(dlg.deleteLater)
        warn.assert_not_called()
        OL.set_max_open_mb(10)
        with mock.patch("ui.hex_editor.QMessageBox.warning") as warn:
            dlg2 = HexEditorDialog(LocalFS(), str(p))
            self.addCleanup(dlg2.deleteLater)
        warn.assert_called_once()
        self.assertIn("10 MB", warn.call_args[0][2])

    def test_elevated_viewer_renders_text_up_to_the_limit(self) -> None:
        from ui import elevated_viewer as EV

        data = b"line\n" * (5 * MIB // 5)
        self.assertTrue(EV._is_text_renderable(data))
        OL.set_max_open_mb(2)
        self.assertFalse(EV._is_text_renderable(data))


class PaneDecisionTest(_QtCase):
    def _pane(self):
        from core.local_fs import LocalFS
        from ui import column_prefs as CP
        from ui.file_pane import FilePaneWidget

        patcher = mock.patch.object(CP, "DEFAULT_PATH", Path(self._tmp.name) / "cols.json")
        patcher.start()
        self.addCleanup(patcher.stop)
        pane = FilePaneWidget(LocalFS())
        self.addCleanup(pane.deleteLater)
        return pane

    def test_editable_gate_follows_the_setting(self) -> None:
        pane = self._pane()
        self.assertTrue(pane._is_editable_file("a.txt", 20 * MIB))
        self.assertTrue(pane._is_editable_file("a.unknownext", 20 * MIB))
        self.assertFalse(pane._is_editable_file("a.txt", 40 * MIB))
        OL.set_max_open_mb(64)
        self.assertTrue(pane._is_editable_file("a.txt", 40 * MIB))
        OL.set_max_open_mb(1)
        self.assertFalse(pane._is_editable_file("a.txt", 2 * MIB))

    def test_double_click_on_an_oversized_file_explains_instead_of_doing_nothing(self) -> None:
        pane = self._pane()
        big = self._file(40 * MIB, "huge.log")
        pane.navigate(str(big.parent))
        proxy = pane._proxy
        row = next(
            r for r in range(proxy.rowCount()) if proxy.data(proxy.index(r, 0)) == "huge.log"
        )
        with mock.patch("ui.file_pane.QMessageBox.information") as info:
            pane._on_double_click(proxy.index(row, 0))
        info.assert_called_once()
        text = info.call_args[0][2]
        self.assertIn("32 MB", text)
        self.assertIn("huge.log", text)


class MenuTest(_QtCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls._home = tempfile.mkdtemp()
        cls._patch = mock.patch("pathlib.Path.home", return_value=Path(cls._home))
        cls._patch.start()
        from ui.main_window import MainWindow

        cls.win = MainWindow()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.win.deleteLater()
        cls._patch.stop()
        __import__("shutil").rmtree(cls._home, ignore_errors=True)

    def _action(self):
        from PyQt6.QtGui import QAction

        for a in self.win.findChildren(QAction):
            if "Open Size Limit" in a.text().replace("&", ""):
                return a
        return None

    def test_view_menu_has_the_entry(self) -> None:
        self.assertIsNotNone(self._action())

    def test_choosing_a_value_stores_it(self) -> None:
        with mock.patch("ui.main_window.QInputDialog.getInt", return_value=(96, True)) as ask:
            self._action().trigger()
        self.assertEqual(OL.max_open_mb(), 96)
        args = ask.call_args
        self.assertEqual(args[0][3], OL.DEFAULT_MAX_OPEN_MB)  # pre-filled with the current value
        self.assertEqual(args[0][4], OL.MIN_MAX_OPEN_MB)
        self.assertEqual(args[0][5], OL.MAX_MAX_OPEN_MB)

    def test_cancel_changes_nothing(self) -> None:
        with mock.patch("ui.main_window.QInputDialog.getInt", return_value=(500, False)):
            self._action().trigger()
        self.assertEqual(OL.max_open_mb(), OL.DEFAULT_MAX_OPEN_MB)


if __name__ == "__main__":
    unittest.main()
