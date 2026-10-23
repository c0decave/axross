"""Metadata search: "Index Current Pane" runs in the background with progress,
and Cancel / Close / Esc stop it."""

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

from core import metadata_index as MX  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


def _tree(root: Path, files: int, dirs: int = 3) -> None:
    for d in range(dirs):
        (root / f"d{d}").mkdir()
        for i in range(files // dirs):
            (root / f"d{d}" / f"f{i}.txt").write_text("x")


class CoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        _tree(self.tmp, 12)
        self.db = Path(tempfile.mkdtemp()) / "m.db"
        self.addCleanup(shutil.rmtree, self.db.parent, ignore_errors=True)

    def index(self, **kw) -> int:
        return MX.index_dir(LocalFS(), str(self.tmp), backend_id="t", db_path=self.db, **kw)

    def test_default_behaviour_is_unchanged(self) -> None:
        self.assertEqual(self.index(), 12 + 3)  # files + the three directories

    def test_cancel_before_the_start_indexes_nothing(self) -> None:
        self.assertEqual(self.index(cancel=lambda: True), 0)

    def test_cancel_midway_keeps_the_partial_count(self) -> None:
        seen: list = []
        n = self.index(cancel=lambda: len(seen) >= 4, progress=lambda s, i, p: seen.append(p))
        self.assertGreaterEqual(n, 3)
        self.assertLess(n, 15)

    def test_progress_grows_and_names_the_current_path(self) -> None:
        events: list = []
        self.index(progress=lambda s, i, p: events.append((s, i, p)))
        self.assertEqual(len(events), 15)
        self.assertEqual([e[1] for e in events], sorted(e[1] for e in events))
        self.assertEqual(events[-1][1], 15)
        self.assertTrue(events[-1][2].startswith(str(self.tmp)))

    def test_a_failing_progress_callback_does_not_abort(self) -> None:
        def boom(*_a) -> None:
            raise RuntimeError("ui gone")

        self.assertEqual(self.index(progress=boom), 15)


class DialogTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        _tree(self.tmp, 45)
        dbdir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, dbdir, ignore_errors=True)
        p = mock.patch.object(MX, "_DEFAULT_DB", dbdir / "m.db")
        p.start()
        self.addCleanup(p.stop)
        self.seen: list[str] = []
        real = MX._index_item
        gate = threading.Event()

        def slow(db, bid, path, item, **kw):
            self.seen.append(path)
            gate.wait(timeout=0.03)
            return real(db, bid, path, item, **kw)

        self.gate = gate
        p2 = mock.patch.object(MX, "_index_item", slow)
        p2.start()
        self.addCleanup(p2.stop)

        class _Pane:
            backend = LocalFS()
            current_path = str(self.tmp)

        from PyQt6.QtWidgets import QMessageBox

        from ui.metadata_search_dialog import MetadataSearchDialog

        self.dlg = MetadataSearchDialog(_Pane())
        self.addCleanup(self.dlg.deleteLater)
        self.dlg.show()
        q = mock.patch("ui.metadata_search_dialog.QMessageBox.question")
        q.start().return_value = QMessageBox.StandardButton.Yes
        self.addCleanup(q.stop)
        for name in ("information", "warning"):
            m = mock.patch(f"ui.metadata_search_dialog.QMessageBox.{name}")
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
        self.dlg._do_index_active()
        self.assertTrue(self._wait(lambda: len(self.seen) >= 3), "worker never started")

    def test_progress_line_and_cancel_button_while_running(self) -> None:
        self._start()
        self.assertTrue(self.dlg._busy_bar.isVisible())
        self.assertEqual(self.dlg._busy_bar.maximum(), 0)
        self.assertTrue(self._wait(lambda: "indexed" in self.dlg._progress_label.text()))
        self.assertFalse(self.dlg._index_btn.isEnabled())
        self.dlg._cancel_btn.click()
        self.assertTrue(self._wait(lambda: not self.dlg._busy_bar.isVisible()))

    def test_cancel_stops_early_and_keeps_the_dialog(self) -> None:
        self._start()
        self.dlg._cancel_btn.click()
        self.assertTrue(self._wait(lambda: not self.dlg._busy_bar.isVisible()))
        self.assertLess(len(self.seen), 48)
        self.assertTrue(self.dlg.isVisible())
        self.assertTrue(self.dlg._index_btn.isEnabled())
        self.assertIn("cancel", self._information.call_args[0][2].lower())

    def test_escape_and_close_stop_the_scan(self) -> None:
        self._start()
        self.dlg.reject()
        self.assertFalse(self.dlg.isVisible())
        time.sleep(0.3)
        self.app.processEvents()
        self.assertLess(len(self.seen), 48)

    def test_window_close_stops_the_scan(self) -> None:
        self._start()
        self.dlg.close()
        self.assertFalse(self.dlg.isVisible())
        time.sleep(0.2)
        self.assertLess(len(self.seen), 48)

    def test_a_finished_run_reports_the_count(self) -> None:
        self.gate.set()
        self.dlg._do_index_active()
        self.assertTrue(self._wait(lambda: not self.dlg._busy_bar.isVisible()))
        self.assertIn("48", self._information.call_args[0][2])
        self.assertTrue(self.dlg._index_btn.isEnabled())

    def test_an_error_is_reported(self) -> None:
        with mock.patch.object(MX, "index_dir", side_effect=RuntimeError("db locked")):
            self.dlg._do_index_active()
            self.assertTrue(self._wait(lambda: self._warning.called))
        self.assertIn("db locked", self._warning.call_args[0][2])
        self.assertFalse(self.dlg._busy_bar.isVisible())

    def test_declining_starts_nothing(self) -> None:
        from PyQt6.QtWidgets import QMessageBox

        with mock.patch("ui.metadata_search_dialog.QMessageBox.question") as ask:
            ask.return_value = QMessageBox.StandardButton.No
            self.dlg._do_index_active()
        self.assertEqual(self.seen, [])


if __name__ == "__main__":
    unittest.main()
