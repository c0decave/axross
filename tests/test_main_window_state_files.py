"""The window's own state files (session.json, recents.json) never stop it.

Found in review: ``_read_json_file`` decodes the bytes as UTF-8 and the
callers caught only ``json.JSONDecodeError``. A session.json or
recents.json holding a non-UTF-8 byte raised UnicodeDecodeError out of
``MainWindow()``, so axross did not start at all until the user found and
deleted the file. "Restore Last Session" raised the same way, and a
session tree of the wrong shape failed half-way, after every open pane had
already been closed.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


class _WindowStateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from ui import main_window as MW

        self.MW = MW
        self.home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        self.session = self.home / "session.json"
        self.recents = self.home / "recents.json"
        for name, value in (("_SESSION_FILE", self.session), ("_RECENTS_FILE", self.recents)):
            patcher = mock.patch.object(MW.MainWindow, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.win = None

    def tearDown(self) -> None:
        if self.win is not None:
            from PyQt6.QtGui import QCloseEvent

            self.win.closeEvent(QCloseEvent())
            self.win.deleteLater()

    def make_window(self):
        with mock.patch("pathlib.Path.home", return_value=self.home):
            self.win = self.MW.MainWindow()
        return self.win


class StartupTest(_WindowStateTest):
    def test_happy_readable_files_are_used(self) -> None:
        self.recents.write_text(json.dumps(["prod", "lab"]))
        self.session.write_text(json.dumps({"window": {"compact": False}}))
        win = self.make_window()
        self.assertEqual(win._recent_profiles, ["prod", "lab"])

    def test_sad_a_non_utf8_recents_file_does_not_stop_the_window(self) -> None:
        self.recents.write_bytes(b'["\xff"]')
        win = self.make_window()
        self.assertEqual(win._recent_profiles, [])

    def test_sad_a_non_utf8_session_file_does_not_stop_the_window(self) -> None:
        self.session.write_bytes(b'{"window": {"ui_theme": "\xff"}}')
        win = self.make_window()
        self.assertTrue(win._panes)

    def test_edge_wrong_json_shapes_do_not_stop_the_window(self) -> None:
        self.recents.write_text(json.dumps({"not": "a list"}))
        self.session.write_text(json.dumps([1, 2]))
        win = self.make_window()
        self.assertEqual(win._recent_profiles, [])


class RestoreTest(_WindowStateTest):
    def restore(self) -> list[str]:
        with mock.patch.object(self.MW.QMessageBox, "information") as info:
            self.win._restore_session()
        self.app.processEvents()
        return [str(c.args[2]) for c in info.call_args_list]

    def test_happy_a_saved_session_is_restored(self) -> None:
        from PyQt6.QtCore import Qt

        win = self.make_window()
        win._split_pane(Qt.Orientation.Horizontal)
        win._save_session()
        self.assertEqual(self.restore(), [])
        self.assertEqual(len(win._panes), 2)

    def test_sad_a_non_utf8_session_is_reported_and_keeps_the_panes(self) -> None:
        from PyQt6.QtCore import Qt

        win = self.make_window()
        win._split_pane(Qt.Orientation.Horizontal)
        panes = list(win._panes)
        self.session.write_bytes(b'{"splitter": "\xff"}')
        messages = self.restore()
        self.assertEqual(len(messages), 1)
        self.assertEqual(win._panes, panes)

    def test_sad_a_session_of_the_wrong_shape_keeps_the_open_panes(self) -> None:
        from PyQt6.QtCore import Qt

        win = self.make_window()
        win._split_pane(Qt.Orientation.Horizontal)
        panes = list(win._panes)
        bad_pane = {"type": "pane", "local": True, "path": "/"}
        for data in (
            [1],
            {"splitter": [1]},
            {"splitter": {"type": "splitter", "children": [bad_pane, "x"]}},
            {"splitter": {"type": "splitter", "children": "abc"}},
            {"splitter": {"type": "splitter", "children": [{"type": "pane", "path": 5}]}},
            {"splitter": {"type": "splitter", "children": [bad_pane]}, "window": []},
        ):
            with self.subTest(data=data):
                self.session.write_text(json.dumps(data))
                messages = self.restore()
                self.assertEqual(len(messages), 1, messages)
                self.assertEqual(win._panes, panes)

    def test_edge_a_session_nested_beyond_any_real_layout_is_refused(self) -> None:
        """Deeper than the interpreter's recursion limit: restoring it raised
        RecursionError after the open panes were gone."""
        win = self.make_window()
        panes = list(win._panes)
        tree: dict = {"type": "pane", "local": True, "path": "/"}
        for _ in range(5000):
            tree = {"type": "splitter", "children": [tree]}
        self.session.write_text(json.dumps({"splitter": tree}))
        self.assertEqual(len(self.restore()), 1)
        self.assertEqual(win._panes, panes)


class SessionSaveTest(_WindowStateTest):
    """session.json is shared with core.i18n, which stores the language the
    user picked in window.language. Closing the window rewrote the file
    from scratch and dropped it, so the pick never survived the restart it
    asks for."""

    def close(self) -> None:
        from PyQt6.QtGui import QCloseEvent

        self.win.closeEvent(QCloseEvent())
        self.win.deleteLater()
        self.win = None

    def test_happy_the_picked_language_survives_closing_the_window(self) -> None:
        from core.i18n import store_language, stored_language

        self.make_window()
        store_language("de", self.session)
        self.close()
        self.assertEqual(stored_language(self.session), "de")
        data = json.loads(self.session.read_text())
        self.assertIn("children", data["splitter"])
        self.assertIn("ui_theme", data["window"])

    def test_sad_an_unreadable_session_file_is_still_replaced_on_close(self) -> None:
        self.session.write_bytes(b'{"window": {"language": "de"')
        self.make_window()
        self.close()
        data = json.loads(self.session.read_text())
        self.assertIn("splitter", data)
        self.assertNotIn("language", data["window"])

    def test_edge_the_window_keys_are_its_own_not_the_old_files(self) -> None:
        self.session.write_text(
            json.dumps(
                {
                    "splitter": {"type": "splitter", "children": [{"type": "pane", "x": 1}]},
                    "window": {"language": "sv", "compact": True, "width": 1},
                    "theme": "old",
                }
            )
        )
        self.make_window()
        self.close()
        data = json.loads(self.session.read_text())
        self.assertEqual(data["window"]["language"], "sv")
        self.assertFalse(data["window"]["compact"])
        self.assertGreater(data["window"]["width"], 1)
        self.assertNotIn({"type": "pane", "x": 1}, data["splitter"]["children"])


class ProfileImportTest(_WindowStateTest):
    def import_file(self, content: bytes):
        path = self.home / "import.json"
        path.write_bytes(content)
        from PyQt6.QtWidgets import QFileDialog

        with mock.patch.object(QFileDialog, "getOpenFileName", return_value=(str(path), "")), \
                mock.patch.object(self.MW.QMessageBox, "warning") as warning, \
                mock.patch.object(self.MW.QMessageBox, "information"):
            self.win._import_profiles_json()
        return warning

    def test_sad_a_non_utf8_import_file_is_reported(self) -> None:
        self.make_window()
        warning = self.import_file(b'{"x": "\xff"}')
        warning.assert_called_once()
        self.assertIn("Cannot read file", warning.call_args.args[2])

    def test_edge_a_non_object_import_file_is_reported(self) -> None:
        self.make_window()
        warning = self.import_file(b"[1]")
        warning.assert_called_once()


if __name__ == "__main__":
    unittest.main()
