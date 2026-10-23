"""Show Trash: Restore, Delete Permanently and Empty Trash run off the GUI
thread - the same hang the pane's Delete had (a large trashed folder on a
slow share froze the window).

The listing too: ``core.trash.list_trash`` (one listing plus one ``.meta``
read per entry) ran on the GUI thread when the window opened and after every
action, so a big trash on a slow share froze the window before it showed.
It now loads on its own background job; a newer load supersedes an older
one, whose result is dropped."""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt, QTimer  # noqa: E402
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
        _settle(self.app, dlg)  # the listing loads in the background
        return dlg

    def _entry(self, original: str, trash_id: str):
        return T.TrashEntry(
            trash_id=trash_id,
            original_path=original,
            trashed_at=datetime(2026, 10, 22, 12, 0, 0),
            size=1,
        )

    def _gated_list(self, results):
        """A list_trash stand-in: call N waits for gates[N] (when there is
        one) and returns results[N]."""
        gates = {i: threading.Event() for i in range(len(results))}
        entered = {i: threading.Event() for i in range(len(results))}
        calls = []

        def list_trash(backend, root=None):
            n = len(calls)
            calls.append(n)
            entered[n].set()
            gates[n].wait(10)
            result = results[n]
            if isinstance(result, BaseException):
                raise result
            return result

        return list_trash, gates, entered, calls

    def _wait(self, cond, seconds: float = 10.0) -> bool:
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self.app.processEvents()
            if cond():
                return True
            time.sleep(0.01)
        return cond()


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


class TrashListingAsyncTest(_Base):
    """Item 20: the listing itself does not block the GUI thread."""

    def _open(self):
        from ui.trash_browser import TrashBrowserDialog

        dlg = TrashBrowserDialog(self.fs)
        self.addCleanup(dlg.close)
        return dlg

    def test_happy_the_gui_runs_while_list_trash_blocks(self) -> None:
        entries = [self._entry("/w/a.txt", "id-a"), self._entry("/w/b.txt", "id-b")]
        fake, gates, entered, _calls = self._gated_list([entries])
        with mock.patch.object(T, "list_trash", side_effect=fake):
            started = time.monotonic()
            dlg = self._open()
            self.assertLess(time.monotonic() - started, 1.0, "opening the window blocked")
            self.assertTrue(entered[0].wait(5))
            # list_trash is blocked in the worker; the event loop still runs.
            fired: list[int] = []
            QTimer.singleShot(20, lambda: fired.append(1))
            self.assertTrue(self._wait(lambda: fired, 2.0), "the event loop did not run")
            self.assertTrue(dlg.loading)
            self.assertTrue(dlg.busy)
            self.assertIn("Loading", dlg._info.text())
            for button in (dlg._restore_btn, dlg._delete_btn, dlg._empty_btn):
                self.assertFalse(button.isEnabled())
            gates[0].set()
            self.assertTrue(self._wait(lambda: not dlg.loading))
        self.assertEqual(dlg._table.rowCount(), 2)
        self.assertEqual(dlg._table.item(0, 0).text(), "/w/a.txt")
        self.assertIn("2 entries", dlg._info.text())
        for button in (dlg._restore_btn, dlg._delete_btn, dlg._empty_btn):
            self.assertTrue(button.isEnabled())

    def test_happy_the_reload_after_an_action_runs_in_the_background(self) -> None:
        self._trash("gone.txt")
        dlg = self._open()
        _settle(self.app, dlg)
        dlg._table.selectRow(0)
        fake, gates, entered, _calls = self._gated_list([[]])
        with mock.patch.object(T, "list_trash", side_effect=fake):
            dlg._do_delete_permanent()
            self.assertTrue(self._wait(entered[0].is_set), "no reload after the action")
            fired: list[int] = []
            QTimer.singleShot(20, lambda: fired.append(1))
            self.assertTrue(self._wait(lambda: fired, 2.0))
            self.assertTrue(dlg.loading)
            gates[0].set()
            _settle(self.app, dlg)
        self.assertEqual(dlg._table.rowCount(), 0)

    def test_sad_a_failing_listing_is_reported_after_the_load(self) -> None:
        fake, gates, _entered, _calls = self._gated_list([OSError("share gone")])
        with mock.patch.object(T, "list_trash", side_effect=fake):
            dlg = self._open()
            self.MBox.warning.assert_not_called()  # not yet: still loading
            gates[0].set()
            _settle(self.app, dlg)
        self.MBox.warning.assert_called_once()
        self.assertIn("share gone", self.MBox.warning.call_args[0][2])
        self.assertEqual(dlg._table.rowCount(), 0)
        self.assertTrue(dlg._empty_btn.isEnabled())

    def test_sad_an_unexpected_error_in_the_listing_is_reported_not_raised(self) -> None:
        fake, gates, _entered, _calls = self._gated_list([ValueError("garbled meta")])
        gates[0].set()
        with mock.patch.object(T, "list_trash", side_effect=fake):
            dlg = self._open()
            _settle(self.app, dlg)
        self.MBox.warning.assert_called_once()
        self.assertIn("garbled meta", self.MBox.warning.call_args[0][2])

    def test_edge_a_stale_listing_never_overwrites_a_newer_one(self) -> None:
        old = [self._entry("/w/old.txt", "id-old")]
        new = [self._entry("/w/new.txt", "id-new")]
        fake, gates, entered, calls = self._gated_list([old, new])
        with mock.patch.object(T, "list_trash", side_effect=fake):
            dlg = self._open()
            self.assertTrue(entered[0].wait(5))
            dlg._reload()  # a newer load while the first one is blocked
            gates[1].set()
            self.assertTrue(self._wait(lambda: dlg._table.rowCount() == 1))
            self.assertFalse(dlg.loading)
            gates[0].set()  # the old load ends last ...
            end = time.monotonic() + 0.5
            while time.monotonic() < end:
                self.app.processEvents()
                time.sleep(0.01)
        # ... and its result is dropped.
        self.assertEqual(calls, [0, 1])
        self.assertEqual(dlg._table.item(0, 0).text(), "/w/new.txt")
        self.assertFalse(dlg.loading)

    def test_edge_closing_the_window_while_it_loads_does_not_crash(self) -> None:
        fake, gates, entered, _calls = self._gated_list([OSError("late")])
        with mock.patch.object(T, "list_trash", side_effect=fake):
            dlg = self._open()
            self.assertTrue(entered[0].wait(5))
            dlg.reject()
            gates[0].set()
            end = time.monotonic() + 0.5
            while time.monotonic() < end:
                self.app.processEvents()
                time.sleep(0.01)
        self.MBox.warning.assert_not_called()  # nothing reported to a closed window

    def test_edge_an_action_is_refused_while_the_listing_loads(self) -> None:
        fake, gates, entered, _calls = self._gated_list([[]])
        with mock.patch.object(T, "list_trash", side_effect=fake):
            dlg = self._open()
            self.assertTrue(entered[0].wait(5))
            dlg._do_empty()
            self.MBox.question.assert_not_called()
            gates[0].set()
            _settle(self.app, dlg)

    def test_e2e_open_from_the_pane_menu_with_a_slow_listing(self) -> None:
        """The pane's Show Trash… opens the window at once; rows arrive later."""
        from PyQt6.QtTest import QTest

        from ui.file_pane import FilePaneWidget

        self._trash("one.txt")
        pane = FilePaneWidget(self.fs)
        self.addCleanup(pane.deleteLater)
        pane.navigate(str(self.root))
        real = T.list_trash
        gate = threading.Event()

        def slow(backend, root=None):
            gate.wait(10)
            return real(backend, root)

        with mock.patch.object(T, "list_trash", side_effect=slow):
            started = time.monotonic()
            pane._show_trash_browser()
            self.assertLess(time.monotonic() - started, 1.0)
            from ui.trash_browser import TrashBrowserDialog

            dlg = pane.findChild(TrashBrowserDialog)
            self.assertIsNotNone(dlg)
            self.addCleanup(dlg.close)
            self.assertTrue(dlg.loading)
            gate.set()
            _settle(self.app, dlg)
        self.assertEqual(dlg._table.rowCount(), 1)
        dlg._table.selectRow(0)
        QTest.mouseClick(dlg._restore_btn, Qt.MouseButton.LeftButton)
        _settle(self.app, dlg)
        self.assertTrue((self.root / "one.txt").exists())
        self.assertEqual(dlg._table.rowCount(), 0)


if __name__ == "__main__":
    unittest.main()
