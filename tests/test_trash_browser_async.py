"""Show Trash: Restore, Delete Permanently and Empty Trash run off the GUI
thread - the same hang the pane's Delete had (a large trashed folder on a
slow share froze the window)."""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QTimer  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core import trash as T  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


def _settle(app, dlg, seconds: float = 10.0) -> None:
    end = time.monotonic() + seconds
    while dlg.busy and time.monotonic() < end:
        app.processEvents()
        time.sleep(0.01)
    app.processEvents()
    assert not dlg.busy, "the trash job did not end"


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.fs = LocalFS()
        self.fs.home = lambda: str(self.root)
        self.box = mock.patch("ui.trash_browser.QMessageBox")
        self.MBox = self.box.start()
        self.addCleanup(self.box.stop)
        self.MBox.StandardButton = QMessageBox.StandardButton
        self.MBox.question.return_value = QMessageBox.StandardButton.Yes

    def _trash(self, name: str, folder: bool = False) -> Path:
        p = self.root / name
        if folder:
            p.mkdir()
            (p / "inner.txt").write_bytes(b"i")
        else:
            p.write_bytes(b"x")
        T.trash(self.fs, str(p))
        return p

    def _dialog(self):
        from ui.trash_browser import TrashBrowserDialog

        dlg = TrashBrowserDialog(self.fs)
        self.addCleanup(dlg.close)
        return dlg


class TrashBrowserAsyncTest(_Base):
    def test_happy_the_gui_runs_while_delete_permanently_works(self) -> None:
        self._trash("big", folder=True)
        dlg = self._dialog()
        dlg._table.selectRow(0)
        gate = threading.Event()
        real_remove = self.fs.remove

        def slow_remove(path, recursive=False):
            gate.wait(5)
            return real_remove(path, recursive=recursive)

        ticks = []
        timer = QTimer()
        timer.timeout.connect(lambda: ticks.append(1))
        timer.start(10)
        with mock.patch.object(self.fs, "remove", side_effect=slow_remove):
            started = time.monotonic()
            dlg._do_delete_permanent()
            self.assertLess(time.monotonic() - started, 1.0, "the click blocked")
            self.assertTrue(dlg.busy)
            self.assertFalse(dlg._delete_btn.isEnabled())
            end = time.monotonic() + 0.3
            while time.monotonic() < end:
                self.app.processEvents()
                time.sleep(0.01)
            self.assertTrue(ticks, "the event loop did not run during the delete")
            gate.set()
            _settle(self.app, dlg)
        timer.stop()
        self.assertEqual(T.list_trash(self.fs), [])
        self.assertEqual(dlg._table.rowCount(), 0)
        self.assertTrue(dlg._delete_btn.isEnabled())

    def test_happy_empty_trash_in_the_background(self) -> None:
        for n in range(3):
            self._trash(f"f{n}.txt")
        dlg = self._dialog()
        dlg._do_empty()
        _settle(self.app, dlg)
        self.assertEqual(T.list_trash(self.fs), [])
        self.assertEqual(dlg._table.rowCount(), 0)
        self.MBox.information.assert_called()

    def test_happy_restore_in_the_background(self) -> None:
        p = self._trash("back.txt")
        dlg = self._dialog()
        dlg._table.selectRow(0)
        dlg._do_restore()
        _settle(self.app, dlg)
        self.assertEqual(p.read_bytes(), b"x")

    def test_sad_errors_are_reported_after_the_job(self) -> None:
        self._trash("e.txt")
        dlg = self._dialog()
        dlg._table.selectRow(0)
        with mock.patch.object(self.fs, "remove", side_effect=OSError("denied")):
            dlg._do_delete_permanent()
            _settle(self.app, dlg)
        self.MBox.warning.assert_called()
        self.assertIn("denied", self.MBox.warning.call_args[0][2])

    def test_edge_a_second_action_while_one_runs_is_refused(self) -> None:
        self._trash("a.txt")
        dlg = self._dialog()
        dlg._table.selectRow(0)
        gate = threading.Event()
        real_remove = self.fs.remove
        calls = []

        def slow_remove(path, recursive=False):
            calls.append(path)
            gate.wait(5)
            return real_remove(path, recursive=recursive)

        with mock.patch.object(self.fs, "remove", side_effect=slow_remove):
            dlg._do_delete_permanent()
            dlg._do_empty()  # refused: one job at a time
            gate.set()
            _settle(self.app, dlg)
        self.assertEqual(self.MBox.question.call_count, 1)

    def test_edge_closing_the_dialog_while_it_works_does_not_crash(self) -> None:
        self._trash("c", folder=True)
        dlg = self._dialog()
        dlg._table.selectRow(0)
        gate = threading.Event()
        real_remove = self.fs.remove

        def slow_remove(path, recursive=False):
            gate.wait(5)
            return real_remove(path, recursive=recursive)

        with mock.patch.object(self.fs, "remove", side_effect=slow_remove):
            dlg._do_delete_permanent()
            dlg.reject()
            gate.set()
            end = time.monotonic() + 1
            while time.monotonic() < end:
                self.app.processEvents()
                time.sleep(0.01)
        self.MBox.warning.assert_not_called()


if __name__ == "__main__":
    unittest.main()
