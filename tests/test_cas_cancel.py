"""Duplicate Finder: the rebuild runs off the UI thread, shows progress and
can be stopped with Cancel, Close or Esc."""

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

from core import cas as CAS  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


def _tree(root: Path, files: int = 12, dirs: int = 3) -> None:
    for d in range(dirs):
        (root / f"d{d}").mkdir()
        for i in range(files // dirs):
            (root / f"d{d}" / f"f{i}.txt").write_text(f"content {d}-{i}")


class CoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        _tree(self.tmp)
        self.db = self.tmp / "cas.db"
        self.fs = LocalFS()

    def rebuild(self, **kw) -> int:
        return CAS.rebuild(self.fs, str(self.tmp), backend_id="t", db_path=self.db, **kw)

    def test_default_behaviour_is_unchanged(self) -> None:
        self.assertEqual(self.rebuild(), 12)

    def test_cancel_before_the_start_does_nothing(self) -> None:
        with mock.patch.object(LocalFS, "checksum") as chk:
            self.assertEqual(self.rebuild(cancel=lambda: True), 0)
        chk.assert_not_called()

    def test_cancel_midway_returns_the_partial_count_without_raising(self) -> None:
        seen = []

        def cancel() -> bool:
            return len(seen) >= 5

        def progress(scanned: int, indexed: int, path: str) -> None:
            seen.append((scanned, indexed, path))

        n = self.rebuild(cancel=cancel, progress=progress)
        self.assertGreaterEqual(n, 4)
        self.assertLess(n, 12)

    def test_progress_reports_growing_counts_and_the_current_path(self) -> None:
        events = []
        self.rebuild(progress=lambda s, i, p: events.append((s, i, p)))
        self.assertEqual(len(events), 12)
        self.assertEqual([e[0] for e in events], sorted(e[0] for e in events))
        self.assertEqual(events[-1][1], 12)
        self.assertTrue(events[-1][2].startswith(str(self.tmp)))

    def test_progress_counts_scanned_files_even_when_hashing_fails(self) -> None:
        events = []
        with mock.patch.object(LocalFS, "checksum", side_effect=OSError("nope")):
            n = self.rebuild(progress=lambda s, i, p: events.append((s, i)))
        self.assertEqual(n, 0)
        self.assertEqual(events[-1], (12, 0))

    def test_a_failing_progress_callback_does_not_abort_the_rebuild(self) -> None:
        def boom(*_a) -> None:
            raise RuntimeError("ui gone")

        self.assertEqual(self.rebuild(progress=boom), 12)

    def test_the_walk_stops_between_directories(self) -> None:
        calls = []

        def cancel() -> bool:
            calls.append(1)
            return len(calls) > 3

        files = list(CAS._walk_files(self.fs, str(self.tmp), cancel=cancel))
        self.assertLess(len(files), 12)


def _app():
    from PyQt6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


class DialogTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            cls.app = _app()
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        _tree(self.tmp, files=30, dirs=3)
        self.gate = threading.Event()
        self.hashed: list[str] = []
        real = LocalFS.checksum

        def slow(fs, path, algorithm="sha256"):
            self.hashed.append(path)
            self.gate.wait(timeout=0.04)  # ~25 files/s unless the gate is opened
            return real(fs, path, algorithm)

        p = mock.patch.object(LocalFS, "checksum", slow)
        p.start()
        self.addCleanup(p.stop)
        dbdir = Path(tempfile.mkdtemp())  # outside the scanned tree
        self.addCleanup(shutil.rmtree, dbdir, ignore_errors=True)
        p2 = mock.patch.object(CAS, "_DEFAULT_DB", dbdir / "cas.db")
        p2.start()
        self.addCleanup(p2.stop)

        class _Pane:
            backend = LocalFS()
            current_path = str(self.tmp)

        from ui.cas_dialog import CasDuplicatesDialog

        self.dlg = CasDuplicatesDialog(_Pane())
        self.addCleanup(self.dlg.deleteLater)
        self.dlg.show()
        # no confirmation / result popups in tests
        q = mock.patch("ui.cas_dialog.QMessageBox.question")
        ask = q.start()
        self.addCleanup(q.stop)
        from PyQt6.QtWidgets import QMessageBox

        ask.return_value = QMessageBox.StandardButton.Yes
        for name in ("information", "warning"):
            m = mock.patch(f"ui.cas_dialog.QMessageBox.{name}")
            setattr(self, f"_{name}", m.start())
            self.addCleanup(m.stop)

    def _wait(self, cond, timeout=5.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            self.app.processEvents()
            if cond():
                return True
            time.sleep(0.01)
        return False

    def _start(self) -> None:
        self.dlg._do_rebuild_active()
        self.assertTrue(self._wait(lambda: len(self.hashed) >= 3), "worker never started")

    def test_the_ui_stays_responsive_and_shows_progress_while_running(self) -> None:
        self._start()
        self.assertTrue(self.dlg._busy_bar.isVisible())
        self.assertEqual(self.dlg._busy_bar.maximum(), 0)  # indeterminate "working" bar
        self.assertTrue(self._wait(lambda: "indexed" in self.dlg._progress_label.text()))
        self.assertTrue(self.dlg._progress_label.isVisible())
        self.assertFalse(self.dlg._rebuild_btn.isEnabled())
        self.assertTrue(self.dlg._cancel_btn.isVisible())
        self.dlg._cancel_btn.click()
        self._wait(lambda: not self.dlg._busy_bar.isVisible())

    def test_cancel_button_stops_early_and_says_so(self) -> None:
        self._start()
        self.dlg._cancel_btn.click()
        self.assertTrue(self._wait(lambda: not self.dlg._busy_bar.isVisible()))
        self.assertLess(len(self.hashed), 30)
        self.assertTrue(self.dlg.isVisible(), "Cancel must keep the dialog open")
        self.assertTrue(self.dlg._rebuild_btn.isEnabled())
        self.assertTrue(self._information.called)
        self.assertIn("cancel", self._information.call_args[0][2].lower())

    def test_escape_cancels_the_running_scan_and_closes(self) -> None:
        self._start()
        self.dlg.reject()
        self.assertFalse(self.dlg.isVisible())
        n = len(self.hashed)
        time.sleep(0.3)
        self.app.processEvents()
        self.assertLess(len(self.hashed), 30, "worker kept going after Esc")
        self.assertLessEqual(len(self.hashed) - n, 2)

    def test_the_close_button_does_the_same(self) -> None:
        from PyQt6.QtWidgets import QDialogButtonBox

        self._start()
        box = self.dlg.findChild(QDialogButtonBox)
        box.button(QDialogButtonBox.StandardButton.Close).click()
        self.assertFalse(self.dlg.isVisible())
        time.sleep(0.2)
        self.assertLess(len(self.hashed), 30)

    def test_the_window_close_button_does_the_same(self) -> None:
        self._start()
        self.dlg.close()
        self.assertFalse(self.dlg.isVisible())
        time.sleep(0.2)
        self.assertLess(len(self.hashed), 30)

    def test_a_finished_run_reports_and_reloads(self) -> None:
        self.gate.set()  # full speed
        self.dlg._do_rebuild_active()
        self.assertTrue(self._wait(lambda: not self.dlg._busy_bar.isVisible()))
        self.assertEqual(len(self.hashed), 30)
        self.assertIn("30", self._information.call_args[0][2])
        self.assertTrue(self.dlg._rebuild_btn.isEnabled())
        self.assertFalse(self.dlg._cancel_btn.isVisible())

    def test_a_backend_error_is_reported_not_swallowed(self) -> None:
        with mock.patch.object(CAS, "rebuild", side_effect=RuntimeError("disk exploded")):
            self.dlg._do_rebuild_active()
            self.assertTrue(self._wait(lambda: self._warning.called))
        self.assertIn("disk exploded", self._warning.call_args[0][2])
        self.assertTrue(self.dlg._rebuild_btn.isEnabled())
        self.assertFalse(self.dlg._busy_bar.isVisible())

    def test_declining_the_confirmation_starts_nothing(self) -> None:
        from PyQt6.QtWidgets import QMessageBox

        with mock.patch("ui.cas_dialog.QMessageBox.question") as ask:
            ask.return_value = QMessageBox.StandardButton.No
            self.dlg._do_rebuild_active()
        self.assertEqual(self.hashed, [])
        self.assertFalse(self.dlg._busy_bar.isVisible())

    def test_a_second_start_while_running_is_ignored(self) -> None:
        self._start()
        n = len(self.hashed)
        self.dlg._do_rebuild_active()
        self.dlg._cancel_btn.click()
        self._wait(lambda: not self.dlg._busy_bar.isVisible())
        self.assertLess(len(self.hashed) - n, 5)

    def test_closing_an_idle_dialog_still_works(self) -> None:
        self.dlg.reject()
        self.assertFalse(self.dlg.isVisible())


if __name__ == "__main__":
    unittest.main()
