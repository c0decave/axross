"""Navigation in the file pane loads in the background: the UI stays live,
shows what is happening and a load can be cancelled or superseded."""
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

from core.local_fs import LocalFS  # noqa: E402


class SlowFS(LocalFS):
    """LocalFS whose listing of chosen paths blocks until released."""

    def __init__(self) -> None:
        super().__init__()
        self.gates: dict[str, threading.Event] = {}
        self.fail: dict[str, Exception] = {}
        self.calls: list[str] = []
        self.active = 0
        self.max_active = 0
        self._lock = threading.Lock()

    def hold(self, path: str) -> threading.Event:
        ev = threading.Event()
        self.gates[path] = ev
        return ev

    def list_dir(self, path):
        with self._lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            self.calls.append(path)
        try:
            gate = self.gates.get(path)
            if gate is not None:
                gate.wait(timeout=5)
            if path in self.fail:
                raise self.fail[path]
            return super().list_dir(path)
        finally:
            with self._lock:
                self.active -= 1


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
        from ui.file_pane import FilePaneWidget

        self.root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        for d in ("a", "b", "c"):
            (self.root / d).mkdir()
            (self.root / d / f"{d}_file.txt").write_text(d)
        (self.root / "top.txt").write_text("t")
        p = mock.patch.object(CP, "DEFAULT_PATH", self.root / "cols.json")
        p.start()
        self.addCleanup(p.stop)
        self.fs = SlowFS()
        self.pane = FilePaneWidget(self.fs)
        self.addCleanup(self.pane.deleteLater)
        self.pane.resize(800, 500)
        self.pane.show()
        self.pane.navigate(str(self.root))  # synchronous: the starting point
        self.app.processEvents()
        self.finished: list = []
        self.pane.navigation_finished.connect(lambda p, ok: self.finished.append((p, ok)))

    def settle(self, timeout=3.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            self.app.processEvents()
            if not self.pane.is_loading:
                return True
            time.sleep(0.002)
        return False

    def names(self) -> set[str]:
        m = self.pane._proxy
        return {m.data(m.index(r, 0)) for r in range(m.rowCount())}

    def p(self, *parts: str) -> str:
        return str(self.root.joinpath(*parts))


class AsyncLoadTest(_Base):
    def test_navigate_async_returns_at_once_and_the_ui_stays_live(self) -> None:
        gate = self.fs.hold(self.p("a"))
        start = time.time()
        self.pane.navigate_async(self.p("a"))
        self.assertLess(time.time() - start, 0.3)
        self.assertTrue(self.pane.is_loading)
        # the old folder is still shown and the path has not changed yet
        self.assertEqual(self.pane.current_path, str(self.root))
        self.assertIn("top.txt", self.names())
        self.app.processEvents()
        gate.set()
        self.assertTrue(self.settle())

    def test_while_loading_the_pane_shows_progress_and_a_cancel_button(self) -> None:
        gate = self.fs.hold(self.p("a"))
        self.pane.navigate_async(self.p("a"))
        self.assertTrue(self.pane._progress_bar.isVisible())
        self.assertTrue(self.pane._cancel_nav_btn.isVisible())
        self.assertIn("Loading", self.pane._status.text())
        gate.set()
        self.assertTrue(self.settle())
        self.assertFalse(self.pane._progress_bar.isVisible())
        self.assertFalse(self.pane._cancel_nav_btn.isVisible())

    def test_a_finished_load_is_applied_like_a_normal_navigation(self) -> None:
        seen = []
        self.pane.path_changed.connect(seen.append)
        gate = self.fs.hold(self.p("a"))
        self.pane.navigate_async(self.p("a"))
        gate.set()
        self.assertTrue(self.settle())
        self.assertEqual(self.pane.current_path, self.p("a"))
        self.assertIn("a_file.txt", self.names())
        self.assertEqual(self.pane._path_edit.text(), self.p("a"))
        self.assertEqual(self.pane._status.text(), "1 items")
        self.assertEqual(seen, [self.p("a")])
        self.assertEqual(self.pane._history[-1], self.p("a"))
        self.assertEqual(self.finished[-1], (self.p("a"), True))

    def test_a_fast_local_load_is_applied_without_waiting_for_a_poll_tick(self) -> None:
        start = time.time()
        self.pane.navigate_async(self.p("b"))
        self.assertTrue(self.settle(1.0))
        self.assertLess(time.time() - start, 0.5)
        self.assertEqual(self.pane.current_path, self.p("b"))

    def test_the_synchronous_navigate_is_unchanged(self) -> None:
        self.pane.navigate(self.p("c"))
        self.assertEqual(self.pane.current_path, self.p("c"))
        self.assertIn("c_file.txt", self.names())
        self.assertFalse(self.pane.is_loading)

    def test_a_backend_error_keeps_the_old_folder_and_says_so(self) -> None:
        self.fs.fail[self.p("a")] = PermissionError("denied")
        self.pane.navigate_async(self.p("a"))
        self.assertTrue(self.settle())
        self.assertEqual(self.pane.current_path, str(self.root))
        self.assertIn("denied", self.pane._status.text())
        self.assertFalse(self.pane._progress_bar.isVisible())
        self.assertFalse(self.pane._cancel_nav_btn.isVisible())
        self.assertEqual(self.finished[-1], (self.p("a"), False))
        self.assertNotIn(self.p("a"), self.pane._history)

    def test_a_non_oserror_failure_is_contained_too(self) -> None:
        self.fs.fail[self.p("a")] = RuntimeError("driver bug")
        self.pane.navigate_async(self.p("a"))
        self.assertTrue(self.settle())
        self.assertIn("driver bug", self.pane._status.text())
        self.assertEqual(self.pane.current_path, str(self.root))


class CancelTest(_Base):
    def test_cancel_button_keeps_the_old_folder_and_ignores_the_late_result(self) -> None:
        gate = self.fs.hold(self.p("a"))
        self.pane.navigate_async(self.p("a"))
        self.pane._cancel_nav_btn.click()
        self.assertFalse(self.pane.is_loading)
        self.assertFalse(self.pane._cancel_nav_btn.isVisible())
        self.assertIn("ancel", self.pane._status.text())
        gate.set()
        time.sleep(0.2)
        self.app.processEvents()
        self.assertEqual(self.pane.current_path, str(self.root))
        self.assertIn("top.txt", self.names())
        self.assertNotIn(self.p("a"), self.pane._history)
        self.assertEqual(self.finished[-1], (self.p("a"), False))

    def test_escape_in_the_pane_cancels_instead_of_clearing_the_selection(self) -> None:
        from PyQt6.QtCore import Qt
        from PyQt6.QtTest import QTest

        gate = self.fs.hold(self.p("a"))
        self.pane._table.selectRow(0)
        self.pane.navigate_async(self.p("a"))
        QTest.keyClick(self.pane._table, Qt.Key.Key_Escape)
        self.assertFalse(self.pane.is_loading)
        self.assertEqual(len(self.pane._table.selectionModel().selectedRows()), 1)
        gate.set()

    def test_escape_without_a_load_still_clears_the_selection(self) -> None:
        from PyQt6.QtCore import Qt
        from PyQt6.QtTest import QTest

        self.pane._table.selectRow(0)
        QTest.keyClick(self.pane._table, Qt.Key.Key_Escape)
        self.assertEqual(len(self.pane._table.selectionModel().selectedRows()), 0)

    def test_cancelling_when_nothing_loads_is_harmless(self) -> None:
        self.pane.cancel_navigation()
        self.assertFalse(self.pane.is_loading)

    def test_a_new_navigation_supersedes_the_running_one(self) -> None:
        gate_a = self.fs.hold(self.p("a"))
        self.pane.navigate_async(self.p("a"))
        self.pane.navigate_async(self.p("b"))
        gate_a.set()
        self.assertTrue(self.settle())
        time.sleep(0.2)
        self.app.processEvents()
        self.assertEqual(self.pane.current_path, self.p("b"))
        self.assertIn("b_file.txt", self.names())
        self.assertNotIn(self.p("a"), self.pane._history)

    def test_two_loads_never_list_the_backend_at_the_same_time(self) -> None:
        gate_a = self.fs.hold(self.p("a"))
        self.pane.navigate_async(self.p("a"))
        time.sleep(0.05)
        self.pane.navigate_async(self.p("b"))
        time.sleep(0.1)
        gate_a.set()
        self.assertTrue(self.settle())
        self.assertEqual(self.fs.max_active, 1)

    def test_closing_the_pane_during_a_load_is_safe(self) -> None:
        gate = self.fs.hold(self.p("a"))
        self.pane.navigate_async(self.p("a"))
        self.pane.shutdown()
        gate.set()
        time.sleep(0.2)
        self.app.processEvents()
        self.assertEqual(self.pane.current_path, str(self.root))


class HistoryTest(_Base):
    def test_back_and_forward_move_the_history_position_only_on_success(self) -> None:
        self.pane.navigate(self.p("a"))
        self.pane.navigate(self.p("b"))
        pos = self.pane._history_pos
        self.pane._go_back()
        self.assertEqual(self.pane._history_pos, pos)  # not yet: the load is running or done
        self.assertTrue(self.settle())
        self.assertEqual(self.pane.current_path, self.p("a"))
        self.assertEqual(self.pane._history_pos, pos - 1)
        self.pane._go_forward()
        self.assertTrue(self.settle())
        self.assertEqual(self.pane.current_path, self.p("b"))
        self.assertEqual(self.pane._history_pos, pos)

    def test_a_failed_back_leaves_the_history_alone(self) -> None:
        self.pane.navigate(self.p("a"))
        self.pane.navigate(self.p("b"))
        before = (list(self.pane._history), self.pane._history_pos)
        self.fs.fail[self.p("a")] = OSError("gone")
        self.pane._go_back()
        self.assertTrue(self.settle())
        self.assertEqual((self.pane._history, self.pane._history_pos), before)
        self.assertEqual(self.pane.current_path, self.p("b"))

    def test_a_normal_async_navigation_truncates_forward_history(self) -> None:
        self.pane.navigate(self.p("a"))
        self.pane.navigate(self.p("b"))
        self.pane._go_back()
        self.assertTrue(self.settle())
        self.pane.navigate_async(self.p("c"))
        self.assertTrue(self.settle())
        self.assertEqual(self.pane._history[-1], self.p("c"))
        self.assertNotIn(self.p("b"), self.pane._history[self.pane._history_pos :])


class EntryPointTest(_Base):
    def test_the_ui_entry_points_load_in_the_background(self) -> None:
        self.pane.navigate(self.p("a"))
        gate = self.fs.hold(str(self.root))
        self.pane._go_up()
        self.assertTrue(self.pane.is_loading)
        gate.set()
        self.assertTrue(self.settle())
        self.assertEqual(self.pane.current_path, str(self.root))

        gate = self.fs.hold(self.p("b"))
        self.pane._path_edit.setText(self.p("b"))
        self.pane._on_path_entered()
        self.assertTrue(self.pane.is_loading)
        gate.set()
        self.assertTrue(self.settle())
        self.assertEqual(self.pane.current_path, self.p("b"))

        home = self.fs.home()
        gate = self.fs.hold(home)
        self.pane._go_home()
        self.assertTrue(self.pane.is_loading)
        gate.set()
        self.assertTrue(self.settle())

    def test_double_click_on_a_folder_loads_in_the_background(self) -> None:
        gate = self.fs.hold(self.p("a"))
        m = self.pane._proxy
        row = next(r for r in range(m.rowCount()) if m.data(m.index(r, 0)) == "a")
        self.pane._on_double_click(m.index(row, 0))
        self.assertTrue(self.pane.is_loading)
        self.assertEqual(self.pane.current_path, str(self.root))
        gate.set()
        self.assertTrue(self.settle())
        self.assertEqual(self.pane.current_path, self.p("a"))

    def test_the_refresh_button_and_ctrl_r_refresh_in_the_background(self) -> None:
        from PyQt6.QtCore import Qt
        from PyQt6.QtTest import QTest

        (self.root / "new.txt").write_text("n")
        gate = self.fs.hold(str(self.root))
        QTest.keyClick(self.pane._table, Qt.Key.Key_R, Qt.KeyboardModifier.ControlModifier)
        self.assertTrue(self.pane.is_loading)
        gate.set()
        self.assertTrue(self.settle())
        self.assertIn("new.txt", self.names())
        (self.root / "newer.txt").write_text("n")
        gate = self.fs.hold(str(self.root))
        self.pane._btn_refresh.click()
        self.assertTrue(self.pane.is_loading)
        gate.set()
        self.assertTrue(self.settle())
        self.assertIn("newer.txt", self.names())

    def test_refresh_keeps_the_history_untouched(self) -> None:
        before = list(self.pane._history), self.pane._history_pos
        self.pane.refresh_async()
        self.assertTrue(self.settle())
        self.assertEqual((self.pane._history, self.pane._history_pos), before)


class QuietRefreshTest(_Base):
    def test_a_watcher_refresh_shows_no_busy_ui(self) -> None:
        (self.root / "fresh.txt").write_text("x")
        gate = self.fs.hold(str(self.root))
        self.pane._on_debounce_fired()
        self.assertTrue(self.pane.is_loading)
        self.assertFalse(self.pane._cancel_nav_btn.isVisible())
        self.assertFalse(self.pane._progress_bar.isVisible())
        gate.set()
        self.assertTrue(self.settle())
        self.assertIn("fresh.txt", self.names())

    def test_a_watcher_refresh_does_not_interrupt_a_user_navigation(self) -> None:
        gate = self.fs.hold(self.p("a"))
        self.pane.navigate_async(self.p("a"))
        calls = len(self.fs.calls)
        self.pane._on_debounce_fired()
        time.sleep(0.1)
        self.assertEqual(len(self.fs.calls), calls)
        gate.set()
        self.assertTrue(self.settle())
        self.assertEqual(self.pane.current_path, self.p("a"))

    def test_a_watcher_result_for_an_old_folder_is_dropped(self) -> None:
        gate = self.fs.hold(str(self.root))
        self.pane._on_debounce_fired()  # slow quiet refresh of the root
        self.pane.navigate_async(self.p("b"))  # the user moves on
        gate.set()
        self.assertTrue(self.settle())
        time.sleep(0.2)
        self.app.processEvents()
        self.assertEqual(self.pane.current_path, self.p("b"))


if __name__ == "__main__":
    unittest.main()
