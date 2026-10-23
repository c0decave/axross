"""The modeless Compare window does not act on a pane that was closed.

Found in review (round 2): the window is modeless and its signals were
bound to the two panes it compared. Closing one of them left the window
open; Delete then removed the files through the closed pane's connection
(released by the close) and called ``refresh_after_change`` on the deleted
widget, which raised ``RuntimeError: wrapped C/C++ object ... has been
deleted``. Reveal raised the same way, and Copy queued a transfer into the
closed pane's folder.
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


class CompareClosedPaneTest(unittest.TestCase):
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
        self.left_dir = self.tmp / "left"
        self.right_dir = self.tmp / "right"
        self.left_dir.mkdir()
        self.right_dir.mkdir()
        (self.left_dir / "only_left.txt").write_text("L")
        (self.right_dir / "only_right.txt").write_text("R")
        self.left = self.win._panes[0]
        self.left.navigate(str(self.left_dir))
        self.right = self.win._add_pane_to_splitter(
            self.win._root_splitter, type(self.left.backend)()
        )
        self.right.navigate(str(self.right_dir))
        self.win._set_active_pane(self.left)
        self.win._target_pane = self.right
        # Unhandled exceptions in Qt slots go to sys.excepthook.
        self.errors: list[BaseException] = []
        hook = mock.patch.object(sys, "excepthook", lambda t, e, tb: self.errors.append(e))
        hook.start()
        self.addCleanup(hook.stop)

    def open_compare(self):
        from ui.compare_dialog import CompareDialog

        before = set(self.win.findChildren(CompareDialog))
        self.win._open_compare_panes()
        (dlg,) = set(self.win.findChildren(CompareDialog)) - before
        dlg.wait_for_compare()
        return dlg

    def settle(self, seconds: float = 0.2) -> None:
        end = time.time() + seconds
        while time.time() < end:
            self.app.processEvents()
            time.sleep(0.01)

    def close_left(self) -> None:
        from PyQt6.QtCore import QCoreApplication, QEvent

        self.win._close_pane(self.left)
        # The running app's event loop deletes the pane; a test has to
        # deliver the deferred delete itself.
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
        self.settle()

    def test_happy_delete_with_both_panes_open_removes_the_one_sided_file(self) -> None:
        dlg = self.open_compare()
        dlg.delete_requested.emit("left", [str(self.left_dir / "only_left.txt")])
        # The pane deletes in the background (its removal job).
        end = time.time() + 10
        while self.left.removal_running and time.time() < end:
            self.settle(0.02)
        self.settle()
        self.assertEqual(self.errors, [])
        self.assertFalse((self.left_dir / "only_left.txt").exists())
        dlg.close()

    def test_sad_closing_a_compared_pane_closes_the_compare_window(self) -> None:
        from PyQt6 import sip

        dlg = self.open_compare()
        self.assertTrue(dlg.isVisible())
        self.close_left()
        self.assertTrue(sip.isdeleted(dlg) or not dlg.isVisible())

    def test_sad_a_late_delete_for_a_closed_pane_does_nothing(self) -> None:
        left = self.left
        self.close_left()
        with mock.patch("ui.main_window.QMessageBox.warning"), mock.patch(
            "ui.main_window.QMessageBox.information"
        ):
            try:
                self.win._delete_compared(left, [str(self.left_dir / "only_left.txt")])
            except RuntimeError as exc:  # the defect: a deleted widget
                self.errors.append(exc)
        self.assertEqual(self.errors, [])
        self.assertTrue((self.left_dir / "only_left.txt").exists())

    def test_edge_reveal_copy_and_sync_for_a_closed_pane_do_nothing(self) -> None:
        left, right = self.left, self.right
        self.close_left()
        src = str(self.left_dir / "only_left.txt")
        with mock.patch("ui.main_window.QMessageBox.warning"), mock.patch(
            "ui.main_window.QMessageBox.information"
        ):
            for call in (
                lambda: self.win._reveal_compared(left, src),
                lambda: self.win._copy_compared(left, right, "to_right", [src]),
                lambda: self.win._copy_compared(left, right, "to_left",
                                                [str(self.right_dir / "only_right.txt")]),
                lambda: self.win._apply_sync(left, right, [
                    {"kind": "mkdir", "direction": "to_left",
                     "dest": str(self.left_dir / "newdir"), "source": ""},
                ]),
            ):
                try:
                    call()
                except RuntimeError as exc:
                    self.errors.append(exc)
        self.settle(0.5)
        self.assertEqual(self.errors, [])
        self.assertFalse((self.right_dir / "only_left.txt").exists())
        self.assertFalse((self.left_dir / "only_right.txt").exists())
        self.assertFalse((self.left_dir / "newdir").exists())


if __name__ == "__main__":
    unittest.main()
