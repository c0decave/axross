"""The Compare window's Delete runs in the background, like the pane's Delete.

Before: ``MainWindow._delete_compared`` called ``backend.remove(path)`` for
each confirmed path on the GUI thread, so deleting many one-sided files on a
slow share froze the whole window, with no progress and no Cancel. A folder
row came before the rows inside it, so its non-recursive remove failed
("not empty") although everything in it was being deleted too.

Now the pane that holds the paths runs them on its removal job
(``FilePaneWidget.remove_paths``, the removal phase of the pane's Delete):
the paths are claimed against a parallel delete, the pane's status line
shows the progress with Cancel, errors are reported per entry, the folder
is reloaded at the end, and the paths go deepest first - still one by one
and non-recursively, so a folder goes only when what was asked for in it
is gone.
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
        for name in ("a.txt", "b.txt", "c.txt"):
            (self.left_dir / name).write_text(name)
        (self.left_dir / "sub").mkdir()
        (self.left_dir / "sub" / "x.txt").write_text("x")
        (self.right_dir / "only_right.txt").write_text("R")
        self.left = self.win._panes[0]
        self.left.navigate(str(self.left_dir))
        self.right = self.win._add_pane_to_splitter(
            self.win._root_splitter, type(self.left.backend)()
        )
        self.right.navigate(str(self.right_dir))
        self.win._set_active_pane(self.left)
        self.win._target_pane = self.right
        self.errors: list[BaseException] = []
        hook = mock.patch.object(sys, "excepthook", lambda t, e, tb: self.errors.append(e))
        hook.start()
        self.addCleanup(hook.stop)

    def wait(self, predicate, timeout: float = 10.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            self.app.processEvents()
            if predicate():
                return True
            time.sleep(0.005)
        return predicate()

    def idle(self, pane=None) -> bool:
        pane = pane or self.left
        return self.wait(lambda: not pane.removal_running and not pane.is_loading)

    def gate_remove(self, backend, hold: str, fail: dict | None = None):
        """backend.remove(hold) blocks until released; paths in *fail*
        raise. Returns (entered, release, calls)."""
        entered, release = threading.Event(), threading.Event()
        calls: list[tuple[str, bool]] = []
        real = backend.remove

        def remove(path, recursive=False):
            calls.append((path, recursive))
            if path == hold:
                entered.set()
                release.wait(10)
            if fail and path in fail:
                raise fail[path]
            return real(path, recursive=recursive)

        patcher = mock.patch.object(backend, "remove", side_effect=remove)
        patcher.start()
        self.addCleanup(patcher.stop)
        return entered, release, calls

    def paths(self, *names: str) -> list[str]:
        return [str(self.left_dir / n) for n in names]


class CompareDeleteAsyncTest(_Base):
    def test_happy_the_gui_runs_while_a_slow_compare_delete_works(self) -> None:
        from PyQt6.QtCore import QTimer

        target = str(self.left_dir / "a.txt")
        entered, release, _calls = self.gate_remove(self.left.backend, target)
        with mock.patch("ui.file_pane.QMessageBox.warning") as warning:
            started = time.monotonic()
            self.win._delete_compared(self.left, self.paths("a.txt", "b.txt"))
            self.assertLess(time.monotonic() - started, 0.5, "the delete blocked the window")
            self.assertTrue(self.wait(entered.is_set))
            fired: list[int] = []
            QTimer.singleShot(20, lambda: fired.append(1))
            self.assertTrue(self.wait(lambda: fired, 2.0), "the event loop did not run")
            self.assertTrue(self.left.removal_running)
            self.assertTrue(self.left._cancel_delete_btn.isVisibleTo(self.win))
            self.assertIn("Deleting", self.left._status.text())
            release.set()
            self.assertTrue(self.idle())
        warning.assert_not_called()
        self.assertFalse((self.left_dir / "a.txt").exists())
        self.assertFalse((self.left_dir / "b.txt").exists())
        self.assertIn("Deleted 2 of 2", self.left._status.text())
        self.assertEqual(self.errors, [])

    def test_sad_a_failing_entry_is_reported_and_the_others_go(self) -> None:
        bad = str(self.left_dir / "b.txt")
        _e, release, _calls = self.gate_remove(
            self.left.backend, "", fail={bad: PermissionError(13, "denied", bad)}
        )
        release.set()
        with mock.patch("ui.file_pane.QMessageBox.warning") as warning:
            self.win._delete_compared(self.left, self.paths("a.txt", "b.txt", "c.txt"))
            self.assertTrue(self.idle())
        warning.assert_called_once()
        self.assertIn("b.txt", warning.call_args[0][2])
        self.assertIn("denied", warning.call_args[0][2])
        self.assertFalse((self.left_dir / "a.txt").exists())
        self.assertTrue((self.left_dir / "b.txt").exists())
        self.assertFalse((self.left_dir / "c.txt").exists())

    def test_sad_cancel_stops_between_entries_and_keeps_the_rest(self) -> None:
        first = str(self.left_dir / "a.txt")
        entered, release, calls = self.gate_remove(self.left.backend, first)
        with mock.patch("ui.file_pane.QMessageBox.warning") as warning:
            self.win._delete_compared(self.left, self.paths("a.txt", "b.txt", "c.txt"))
            self.assertTrue(self.wait(entered.is_set))
            self.left._cancel_delete_btn.click()
            release.set()
            self.assertTrue(self.idle())
        warning.assert_not_called()
        self.assertEqual([p for p, _r in calls], [first])
        self.assertTrue((self.left_dir / "b.txt").exists())
        self.assertTrue((self.left_dir / "c.txt").exists())
        status = self.left._status.text()
        self.assertIn("cancelled after 1 of 3", status)
        self.assertIn("2 kept", status)

    def test_sad_a_production_gate_refusal_deletes_nothing(self) -> None:
        with mock.patch("ui.production_gate.confirm_production", return_value=False):
            self.win._delete_compared(self.left, self.paths("a.txt"))
            self.assertTrue(self.idle())
        self.assertTrue((self.left_dir / "a.txt").exists())
        self.assertFalse(self.left.removal_running)

    def test_edge_a_folder_and_its_contents_go_deepest_first(self) -> None:
        _e, release, calls = self.gate_remove(self.left.backend, "")
        release.set()
        with mock.patch("ui.file_pane.QMessageBox.warning") as warning:
            # The Compare window lists a folder before the rows inside it.
            self.win._delete_compared(self.left, self.paths("sub", "sub/x.txt"))
            self.assertTrue(self.idle())
        warning.assert_not_called()
        self.assertFalse((self.left_dir / "sub").exists())
        self.assertEqual(
            calls, [(str(self.left_dir / "sub" / "x.txt"), False), (str(self.left_dir / "sub"), False)]
        )

    def test_edge_a_folder_with_more_in_it_than_was_asked_for_stays(self) -> None:
        (self.left_dir / "sub" / "unseen.txt").write_text("u")
        with mock.patch("ui.file_pane.QMessageBox.warning") as warning:
            self.win._delete_compared(self.left, self.paths("sub", "sub/x.txt"))
            self.assertTrue(self.idle())
        warning.assert_called_once()  # "sub": not empty - never removed recursively
        self.assertTrue((self.left_dir / "sub" / "unseen.txt").exists())
        self.assertFalse((self.left_dir / "sub" / "x.txt").exists())

    def test_edge_a_second_delete_while_one_runs_is_refused(self) -> None:
        first = str(self.left_dir / "a.txt")
        entered, release, calls = self.gate_remove(self.left.backend, first)
        with (
            mock.patch("ui.file_pane.QMessageBox.warning"),
            mock.patch("ui.file_pane.QMessageBox.information") as info,
        ):
            self.win._delete_compared(self.left, self.paths("a.txt"))
            self.assertTrue(self.wait(entered.is_set))
            self.win._delete_compared(self.left, self.paths("b.txt"))
            info.assert_called_once()
            self.assertIn("still running", info.call_args[0][2])
            release.set()
            self.assertTrue(self.idle())
        self.assertTrue((self.left_dir / "b.txt").exists())
        self.assertEqual([p for p, _r in calls], [first])

    def test_e2e_delete_from_the_compare_window(self) -> None:
        from ui.compare_dialog import CompareDialog

        before = set(self.win.findChildren(CompareDialog))
        self.win._open_compare_panes()
        (dlg,) = set(self.win.findChildren(CompareDialog)) - before
        self.addCleanup(dlg.close)
        dlg.wait_for_compare()
        dlg._table.selectAll()
        with (
            mock.patch("ui.compare_dialog.QMessageBox.question") as question,
            mock.patch("ui.file_pane.QMessageBox.warning") as warning,
        ):
            from PyQt6.QtWidgets import QMessageBox

            question.return_value = QMessageBox.StandardButton.Yes
            dlg._delete_selected()
            self.assertTrue(self.idle(self.left))
            self.assertTrue(self.idle(self.right))
        warning.assert_not_called()
        self.assertEqual(sorted(os.listdir(self.left_dir)), [])
        self.assertEqual(sorted(os.listdir(self.right_dir)), [])
        self.assertIn("Deleted 5 of 5", self.left._status.text())
        self.assertIn("Deleted 1 of 1", self.right._status.text())
        self.assertEqual(self.errors, [])


if __name__ == "__main__":
    unittest.main()
