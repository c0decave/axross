"""Dialogs the main window opens are freed once they are closed.

Each of these dialogs is created with the main window as parent. Without
an explicit delete it stays a child of the window until the application
exits, so every open added one more hidden QDialog (with its widgets and
whatever it captured: profile manager, backends, panes).
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

_OPENS = 3


def _reject_at_once(dialog) -> int:
    """Stand-in for a modal exec(): the user closes the dialog at once."""
    dialog.reject()
    return int(dialog.result())


class MainWindowDialogsFreedTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from ui import column_prefs as CP
        from ui import main_window as MW

        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        p = mock.patch.object(CP, "DEFAULT_PATH", self.tmp / "cols.json")
        p.start()
        self.addCleanup(p.stop)
        home = self.tmp / "home"
        home.mkdir()
        with mock.patch("pathlib.Path.home", return_value=home):
            self.win = MW.MainWindow()
        self.addCleanup(self.win.deleteLater)
        self.addCleanup(self.win.close)
        self.win._reconnect_timer.stop()
        for pane in list(self.win._panes)[1:]:
            self.win._close_pane(pane)
        self.errors: list[BaseException] = []
        hook = mock.patch.object(sys, "excepthook", lambda t, e, tb: self.errors.append(e))
        hook.start()
        self.addCleanup(hook.stop)

    def flush_deletes(self) -> None:
        from PyQt6.QtCore import QCoreApplication, QEvent

        end = time.time() + 0.3
        while time.time() < end:
            self.app.processEvents()
            QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
            time.sleep(0.01)

    def dialogs(self, cls=None) -> list:
        from PyQt6.QtWidgets import QDialog

        return self.win.findChildren(cls or QDialog)

    def _assert_no_growth(self, dialog_cls, opener) -> None:
        self.flush_deletes()
        before = len(self.dialogs(dialog_cls))
        with mock.patch.object(dialog_cls, "exec", _reject_at_once):
            for _ in range(_OPENS):
                opener()
                self.flush_deletes()
        self.assertEqual(len(self.dialogs(dialog_cls)), before)
        self.assertEqual(self.errors, [])

    # -- happy: each modal dialog is gone after it was closed ---------------
    def test_happy_connection_dialog_is_freed(self) -> None:
        from ui.connection_dialog import ConnectionDialog

        self._assert_no_growth(ConnectionDialog, self.win._on_connect)

    def test_happy_settings_dialog_is_freed(self) -> None:
        from ui.settings_dialog import SettingsDialog

        for opener in (
            self.win._show_network_proxy,
            self.win._show_llm_profiles,
            self.win._show_agent_settings,
            self.win._show_metadata_settings,
            self.win._show_extensions_dialog,
            self.win.open_settings,
        ):
            with self.subTest(opener=opener.__name__):
                self._assert_no_growth(SettingsDialog, opener)

    def test_happy_disk_usage_dialog_is_freed(self) -> None:
        from ui.disk_usage_dialog import DiskUsageDialog

        self._assert_no_growth(DiskUsageDialog, self.win._open_disk_usage)

    # -- compare: modeless --------------------------------------------------
    def _two_panes(self):
        left_dir, right_dir = self.tmp / "left", self.tmp / "right"
        left_dir.mkdir()
        right_dir.mkdir()
        (left_dir / "a.txt").write_text("L")
        left = self.win._panes[0]
        left.navigate(str(left_dir))
        right = self.win._add_pane_to_splitter(self.win._root_splitter, type(left.backend)())
        right.navigate(str(right_dir))
        self.win._set_active_pane(left)
        self.win._target_pane = right
        return left, right

    def _open_compare(self):
        from ui.compare_dialog import CompareDialog

        before = set(self.dialogs(CompareDialog))
        self.win._open_compare_panes()
        (dlg,) = set(self.dialogs(CompareDialog)) - before
        dlg.wait_for_compare()
        return dlg

    def test_happy_closed_compare_windows_are_freed(self) -> None:
        from ui.compare_dialog import CompareDialog

        self._two_panes()
        for _ in range(_OPENS):
            self._open_compare().close()
            self.flush_deletes()
        self.assertEqual(self.dialogs(CompareDialog), [])
        self.assertEqual(self.win._compare_dialogs, [])
        self.assertEqual(self.errors, [])

    def test_sad_compare_window_closed_by_closing_its_pane_is_freed(self) -> None:
        from ui.compare_dialog import CompareDialog

        left, right = self._two_panes()
        self._open_compare()
        self.win._close_pane(right)
        self.flush_deletes()
        self.assertEqual(self.dialogs(CompareDialog), [])
        self.assertEqual(self.errors, [])

    def test_edge_an_open_compare_window_is_kept(self) -> None:
        from ui.compare_dialog import CompareDialog

        self._two_panes()
        first = self._open_compare()
        self._open_compare().close()
        self.flush_deletes()
        self.assertEqual(self.dialogs(CompareDialog), [first])
        self.assertTrue(first.isVisible())
        first.close()


if __name__ == "__main__":
    unittest.main()
