"""Delete and Move to Trash run off the GUI thread; hidden entries get a second OK.

Before: ``FilePaneWidget._delete_selected`` walked the whole selection
(``preview_delete``) and then called ``backend.remove(path, recursive=...)``
on the GUI thread, so deleting a large folder - for example on an SMB share
mounted by the kernel and opened as a local path - froze the application
until the last entry was gone. ``_trash_selected`` did the same.

Now both run on a ScanJob (the Calculate Size pattern): the check before
the confirmation and the removal itself are background jobs, the status
line shows the progress with a Cancel button, Cancel stops between
entries, errors are reported per entry, the listing is reloaded at the
end, and a pane closed meanwhile drops the job without crashing.

Item 31: a folder selected for deletion that holds hidden entries needs a
second, explicit OK that names the count and some of them; its default
button is No.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from tests.test_pane_async_navigation import SlowFS  # noqa: E402


class GatedRemoveFS(SlowFS):
    """SlowFS whose remove() of chosen paths blocks until released, and
    whose remove() of other chosen paths fails."""

    def __init__(self) -> None:
        super().__init__()
        self.remove_gates: dict[str, threading.Event] = {}
        self.remove_fail: dict[str, Exception] = {}
        self.removed: list[str] = []
        self.entered: dict[str, threading.Event] = {}

    def hold_remove(self, path: str) -> threading.Event:
        ev = threading.Event()
        self.remove_gates[path] = ev
        self.entered[path] = threading.Event()
        return ev

    def remove(self, path: str, recursive: bool = False) -> None:
        if path in self.entered:
            self.entered[path].set()
        gate = self.remove_gates.get(path)
        if gate is not None:
            gate.wait(timeout=10)
        if path in self.remove_fail:
            raise self.remove_fail[path]
        super().remove(path, recursive=recursive)
        self.removed.append(path)


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from ui import column_prefs as CP

        self.root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        for name in ("a.txt", "b.txt", "c.txt"):
            (self.root / name).write_text(name)
        (self.root / "plain").mkdir()
        (self.root / "plain" / "x.txt").write_text("x")
        (self.root / "dotted").mkdir()
        (self.root / "dotted" / "y.txt").write_text("y")
        (self.root / "dotted" / ".env").write_text("secret")
        (self.root / "dotted" / ".git").mkdir()
        (self.root / "dotted" / ".git" / "HEAD").write_text("ref")
        p = mock.patch.object(CP, "DEFAULT_PATH", self.root / "cols.json")
        p.start()
        self.addCleanup(p.stop)
        self.fs = GatedRemoveFS()
        self.pane = self.make_pane(self.fs)

    def make_pane(self, fs):
        from ui.file_pane import FilePaneWidget

        pane = FilePaneWidget(fs)
        self.addCleanup(pane.deleteLater)
        pane.resize(800, 500)
        pane.show()
        pane.navigate(str(self.root))
        self.app.processEvents()
        return pane

    def wait(self, predicate, timeout=5.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            self.app.processEvents()
            if predicate():
                return True
            time.sleep(0.005)
        return False

    def select(self, *names: str, pane=None) -> None:
        from PyQt6.QtCore import QItemSelectionModel

        pane = pane or self.pane
        m = pane._proxy
        sel = pane._table.selectionModel()
        sel.clearSelection()
        for r in range(m.rowCount()):
            if m.data(m.index(r, 0)) in names:
                sel.select(
                    m.index(r, 0),
                    QItemSelectionModel.SelectionFlag.Select
                    | QItemSelectionModel.SelectionFlag.Rows,
                )
        pane._table.setFocus()

    def names(self, pane=None) -> set[str]:
        m = (pane or self.pane)._proxy
        return {m.data(m.index(r, 0)) for r in range(m.rowCount())}

    def question(self, answer=None):
        from PyQt6.QtWidgets import QMessageBox

        answer = answer or QMessageBox.StandardButton.Yes
        return mock.patch("ui.file_pane.QMessageBox.question", return_value=answer)

    def warning(self, answer=None):
        from PyQt6.QtWidgets import QMessageBox

        answer = answer or QMessageBox.StandardButton.Yes
        return mock.patch("ui.file_pane.QMessageBox.warning", return_value=answer)

    def idle(self, pane=None) -> bool:
        pane = pane or self.pane
        return self.wait(lambda: not pane.removal_running and not pane.is_loading)


class DeleteInBackgroundTest(_Base):
    def test_happy_the_gui_thread_runs_while_a_slow_remove_is_in_progress(self) -> None:
        from PyQt6.QtCore import QTimer

        target = str(self.root / "a.txt")
        gate = self.fs.hold_remove(target)
        self.select("a.txt")
        with self.question() as question, self.warning() as warning:
            start = time.time()
            self.pane._delete_selected()
            self.assertLess(time.time() - start, 0.5)
            self.assertTrue(self.wait(lambda: self.fs.entered[target].is_set()))
            # remove() is blocked in the worker; the event loop still runs.
            fired: list[int] = []
            QTimer.singleShot(20, lambda: fired.append(1))
            self.assertTrue(self.wait(lambda: fired, timeout=2.0))
            self.assertTrue(self.pane.removal_running)
            self.assertTrue(self.pane._cancel_delete_btn.isVisible())
            self.assertTrue(self.pane._progress_bar.isVisible())
            self.assertIn("Deleting", self.pane._status.text())
            gate.set()
            self.assertTrue(self.idle())
        question.assert_called_once()
        warning.assert_not_called()
        self.assertFalse((self.root / "a.txt").exists())
        self.assertNotIn("a.txt", self.names())  # the listing was reloaded
        self.assertFalse(self.pane._cancel_delete_btn.isVisible())
        self.assertIn("Deleted 1", self.pane._status.text())

    def test_happy_the_check_before_the_question_runs_in_the_background(self) -> None:
        gate = self.fs.hold(str(self.root / "plain"))
        self.select("plain")
        with self.question() as question, self.warning():
            start = time.time()
            self.pane._delete_selected()
            self.assertLess(time.time() - start, 0.5)
            self.app.processEvents()
            question.assert_not_called()  # the walk is still blocked
            self.assertTrue(self.pane.removal_running)
            self.assertTrue(self.pane._cancel_delete_btn.isVisible())
            gate.set()
            self.assertTrue(self.idle())
        question.assert_called_once()
        self.assertIn("1 file(s), 1 dir(s)", question.call_args[0][2])
        self.assertFalse((self.root / "plain").exists())

    def test_sad_cancel_stops_between_entries_and_keeps_the_rest(self) -> None:
        first = str(self.root / "a.txt")
        gate = self.fs.hold_remove(first)
        self.select("a.txt", "b.txt", "c.txt")
        with self.question(), self.warning() as warning:
            self.pane._delete_selected()
            self.assertTrue(self.wait(lambda: self.fs.entered[first].is_set()))
            self.pane._cancel_delete_btn.click()
            gate.set()
            self.assertTrue(self.idle())
        warning.assert_not_called()
        # The entry in progress finished; the others were never touched.
        self.assertEqual(self.fs.removed, [first])
        self.assertTrue((self.root / "b.txt").exists())
        self.assertTrue((self.root / "c.txt").exists())
        self.assertNotIn("a.txt", self.names())
        status = self.pane._status.text()
        self.assertIn("cancelled", status.lower())
        self.assertIn("1 of 3", status)

    def test_sad_cancel_during_the_check_asks_nothing_and_deletes_nothing(self) -> None:
        gate = self.fs.hold(str(self.root / "plain"))
        self.select("plain")
        with self.question() as question, self.warning():
            self.pane._delete_selected()
            self.app.processEvents()
            self.pane._cancel_delete_btn.click()
            gate.set()
            self.assertTrue(self.idle())
        question.assert_not_called()
        self.assertTrue((self.root / "plain" / "x.txt").exists())
        self.assertIn("nothing was deleted", self.pane._status.text().lower())

    def test_sad_an_error_per_entry_is_reported_and_the_others_still_go(self) -> None:
        bad = str(self.root / "b.txt")
        self.fs.remove_fail[bad] = PermissionError(13, "Permission denied")
        self.select("a.txt", "b.txt", "c.txt")
        with self.question(), self.warning() as warning:
            self.pane._delete_selected()
            self.assertTrue(self.idle())
        warning.assert_called_once()
        text = warning.call_args[0][2]
        self.assertIn("b.txt", text)
        self.assertIn("Permission denied", text)
        self.assertFalse((self.root / "a.txt").exists())
        self.assertTrue((self.root / "b.txt").exists())
        self.assertFalse((self.root / "c.txt").exists())

    def test_sad_an_unexpected_exception_stops_the_delete(self) -> None:
        # Not an OSError: a backend bug. Nothing after it is deleted.
        self.fs.remove_fail[str(self.root / "a.txt")] = RuntimeError("backend bug")
        self.select("a.txt", "b.txt")
        with self.question(), self.warning() as warning:
            self.pane._delete_selected()
            self.assertTrue(self.idle())
        warning.assert_called_once()
        self.assertIn("backend bug", warning.call_args[0][2])
        self.assertTrue((self.root / "b.txt").exists())

    def test_sad_no_on_the_question_deletes_nothing(self) -> None:
        from PyQt6.QtWidgets import QMessageBox

        self.select("a.txt")
        with self.question(QMessageBox.StandardButton.No), self.warning():
            self.pane._delete_selected()
            self.assertTrue(self.idle())
        self.assertTrue((self.root / "a.txt").exists())
        self.assertFalse(self.pane.removal_running)

    def test_edge_a_second_delete_while_one_runs_is_refused(self) -> None:
        first = str(self.root / "a.txt")
        gate = self.fs.hold_remove(first)
        self.select("a.txt")
        with self.question() as question, self.warning():
            self.pane._delete_selected()
            self.assertTrue(self.wait(lambda: self.fs.entered[first].is_set()))
            self.pane._delete_selected()  # same pane, same path
            self.pane._trash_selected()
            self.assertIn("still running", self.pane._status.text())
            gate.set()
            self.assertTrue(self.idle())
        question.assert_called_once()
        self.assertEqual(self.fs.removed, [first])

    def test_edge_another_pane_cannot_delete_a_path_that_is_being_deleted(self) -> None:
        first = str(self.root / "plain")
        gate = self.fs.hold_remove(first)
        other = self.make_pane(self.fs)
        self.select("plain")
        with self.question(), self.warning() as warning:
            self.pane._delete_selected()
            self.assertTrue(self.wait(lambda: self.fs.entered[first].is_set()))
            self.select("plain", pane=other)
            other._delete_selected()
            self.assertTrue(self.idle(other))
            warning.assert_called_once()
            self.assertIn("already being deleted", warning.call_args[0][2])
            gate.set()
            self.assertTrue(self.idle())
        self.assertEqual(self.fs.removed, [first])

    def test_edge_closing_the_pane_during_the_delete_does_not_crash(self) -> None:
        first = str(self.root / "a.txt")
        gate = self.fs.hold_remove(first)
        self.select("a.txt", "b.txt", "c.txt")
        with self.question(), self.warning() as warning:
            self.pane._delete_selected()
            self.assertTrue(self.wait(lambda: self.fs.entered[first].is_set()))
            self.pane.close()
            self.pane.deleteLater()
            gate.set()
            from ui import file_pane as FP

            self.assertTrue(self.wait(lambda: not FP._paths_in_removal()))
            for _ in range(20):
                self.app.processEvents()
        warning.assert_not_called()
        # The pane went away: the delete stopped after the entry in progress.
        self.assertEqual(self.fs.removed, [first])
        self.assertTrue((self.root / "b.txt").exists())
        # The paths are free again for a new pane.
        pane = self.make_pane(self.fs)
        self.select("b.txt", pane=pane)
        with self.question(), self.warning():
            pane._delete_selected()
            self.assertTrue(self.idle(pane))
        self.assertFalse((self.root / "b.txt").exists())

    def test_edge_closing_the_pane_during_the_check_deletes_nothing(self) -> None:
        gate = self.fs.hold(str(self.root / "plain"))
        self.select("plain")
        with self.question() as question, self.warning():
            self.pane._delete_selected()
            self.pane.shutdown()
            gate.set()
            time.sleep(0.2)
            for _ in range(20):
                self.app.processEvents()
        question.assert_not_called()
        self.assertTrue((self.root / "plain" / "x.txt").exists())
        from ui import file_pane as FP

        self.assertEqual(FP._paths_in_removal(), [])

    def test_edge_a_reconnect_during_the_check_drops_the_delete(self) -> None:
        from tests.test_pane_stale_targets import _HomeFS

        gate = self.fs.hold(str(self.root / "plain"))
        self.select("plain")
        with self.question() as question, self.warning():
            self.pane._delete_selected()
            self.pane.set_backend(_HomeFS(str(self.root)))
            gate.set()
            self.assertTrue(self.idle())
        question.assert_not_called()
        self.assertTrue((self.root / "plain").exists())


class HiddenEntriesConfirmTest(_Base):
    def test_happy_a_folder_with_hidden_entries_asks_a_second_time(self) -> None:
        from PyQt6.QtWidgets import QMessageBox

        self.select("dotted")
        with self.question(), self.warning(QMessageBox.StandardButton.Yes) as warning:
            self.pane._delete_selected()
            self.assertTrue(self.idle())
        warning.assert_called_once()
        args = warning.call_args[0]
        self.assertIn("2 hidden", args[2])
        self.assertIn(".env", args[2])
        self.assertIn(".git", args[2])
        # Buttons Yes|No, default No.
        self.assertEqual(args[4], QMessageBox.StandardButton.No)
        self.assertFalse((self.root / "dotted").exists())

    def test_sad_no_on_the_second_question_keeps_the_folder(self) -> None:
        from PyQt6.QtWidgets import QMessageBox

        self.select("dotted")
        with self.question(), self.warning(QMessageBox.StandardButton.No):
            self.pane._delete_selected()
            self.assertTrue(self.idle())
        self.assertTrue((self.root / "dotted" / ".env").exists())
        self.assertEqual(self.fs.removed, [])

    def test_edge_the_real_second_dialog_defaults_to_no(self) -> None:
        from PyQt6.QtCore import Qt, QTimer
        from PyQt6.QtTest import QTest
        from PyQt6.QtWidgets import QApplication, QMessageBox

        seen: list[str] = []

        def press_enter() -> None:
            box = QApplication.activeModalWidget()
            if isinstance(box, QMessageBox):
                seen.append(box.text())
                QTest.keyClick(box, Qt.Key.Key_Return)
            else:
                QTimer.singleShot(20, press_enter)

        self.select("dotted")
        with self.question():
            QTimer.singleShot(20, press_enter)
            self.pane._delete_selected()
            self.assertTrue(self.idle())
        self.assertEqual(len(seen), 1)
        self.assertIn("hidden", seen[0])
        self.assertTrue((self.root / "dotted" / ".env").exists())

    def test_edge_no_second_question_without_hidden_entries(self) -> None:
        self.select("plain", "a.txt")
        with self.question(), self.warning() as warning:
            self.pane._delete_selected()
            self.assertTrue(self.idle())
        warning.assert_not_called()
        self.assertFalse((self.root / "plain").exists())

    def test_edge_a_selected_dotfile_alone_needs_no_second_question(self) -> None:
        from models.file_item import FileItem

        (self.root / ".hidden.txt").write_text("h")

        with mock.patch.object(
            self.pane,
            "selected_file_items",
            return_value=[FileItem(name=".hidden.txt", is_dir=False, size=1)],
        ), self.question(), self.warning() as warning:
            self.pane._delete_selected()
            self.assertTrue(self.idle())
        warning.assert_not_called()
        self.assertFalse((self.root / ".hidden.txt").exists())

    def test_sad_an_incomplete_check_cannot_rule_hidden_entries_out(self) -> None:
        from PyQt6.QtWidgets import QMessageBox

        self.fs.fail[str(self.root / "plain")] = PermissionError(13, "Permission denied")
        self.select("plain")
        with self.question(), self.warning(QMessageBox.StandardButton.No) as warning:
            self.pane._delete_selected()
            self.assertTrue(self.idle())
        warning.assert_called_once()
        self.assertIn("cannot be ruled out", warning.call_args[0][2])
        self.assertEqual(warning.call_args[0][4], QMessageBox.StandardButton.No)
        self.assertTrue((self.root / "plain").exists())

    def test_happy_move_to_trash_asks_the_same_second_question(self) -> None:
        from PyQt6.QtWidgets import QMessageBox

        self.select("dotted")
        with mock.patch("core.trash.trash") as trash, self.question(), self.warning(
            QMessageBox.StandardButton.No
        ) as warning:
            self.pane._trash_selected()
            self.assertTrue(self.idle())
        warning.assert_called_once()
        self.assertIn("2 hidden", warning.call_args[0][2])
        self.assertIn("trash", warning.call_args[0][2])
        trash.assert_not_called()

    def test_happy_move_to_trash_runs_in_the_background(self) -> None:
        from PyQt6.QtCore import QTimer

        entered, gate = threading.Event(), threading.Event()
        moved: list[str] = []

        def slow_trash(backend, path, *a, **kw):
            entered.set()
            gate.wait(timeout=10)
            moved.append(path)
            return "id"

        self.select("a.txt")
        with (
            mock.patch("core.trash.trash", side_effect=slow_trash),
            self.question(),
            self.warning(),
        ):
            self.pane._trash_selected()
            self.assertTrue(self.wait(entered.is_set))
            fired: list[int] = []
            QTimer.singleShot(20, lambda: fired.append(1))
            self.assertTrue(self.wait(lambda: fired, timeout=2.0))
            gate.set()
            self.assertTrue(self.idle())
        self.assertEqual(moved, [str(self.root / "a.txt")])
        self.assertIn("Moved 1", self.pane._status.text())


if __name__ == "__main__":
    unittest.main()
