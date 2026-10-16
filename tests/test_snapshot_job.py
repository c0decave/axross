"""Snapshot browser: Save / Restore stream in the background with progress
and can be cancelled (Cancel, Esc, Close)."""

from __future__ import annotations

import io
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.local_fs import LocalFS  # noqa: E402

MIB = 1024 * 1024
CHUNKS = 40  # 40 MiB, read one MiB at a time


class _SlowStream(io.RawIOBase):
    """40 MiB of 'x' that takes ~25 ms per MiB unless the gate is open."""

    def __init__(self, gate: threading.Event) -> None:
        self.left = CHUNKS * MIB
        self.gate = gate
        self.reads = 0

    def readable(self) -> bool:
        return True

    def read(self, n: int = -1) -> bytes:
        if self.left <= 0:
            return b""
        self.reads += 1
        self.gate.wait(timeout=0.025)
        n = min(n if n > 0 else MIB, self.left)
        self.left -= n
        return b"x" * n

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


class SnapshotJobTest(unittest.TestCase):
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
        self.target_file = self.tmp / "live.bin"
        self.target_file.write_bytes(b"original")
        self.gate = threading.Event()
        self.stream: _SlowStream | None = None

        def fake_read(entry):
            self.stream = _SlowStream(self.gate)
            return self.stream

        for name, value in (
            ("read_snapshot", fake_read),
            ("browse", lambda backend, path: []),
        ):
            m = mock.patch(f"core.snapshot_browser.{name}", value)
            m.start()
            self.addCleanup(m.stop)

        from ui.snapshot_browser_dialog import SnapshotBrowserDialog

        self.dlg = SnapshotBrowserDialog(LocalFS(), str(self.target_file))
        self.addCleanup(self.dlg.deleteLater)
        self.dlg.show()
        self.entry = SimpleNamespace(
            version_id="v1234567890abc",
            modified=datetime(2026, 1, 1),
            is_current=False,
            label="v1",
            size=CHUNKS * MIB,
        )
        self.dlg._selected_entry = lambda: self.entry
        self.save_target = self.tmp / "saved.bin"
        patches = [
            mock.patch(
                "ui.snapshot_browser_dialog.QFileDialog.getSaveFileName",
                return_value=(str(self.save_target), ""),
            )
        ]
        from PyQt6.QtWidgets import QMessageBox

        q = mock.patch("ui.snapshot_browser_dialog.QMessageBox.question")
        q.start().return_value = QMessageBox.StandardButton.Yes
        self.addCleanup(q.stop)
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        for name in ("information", "warning"):
            m = mock.patch(f"ui.snapshot_browser_dialog.QMessageBox.{name}")
            setattr(self, f"_{name}", m.start())
            self.addCleanup(m.stop)

    def _wait(self, cond, timeout=8.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            self.app.processEvents()
            if cond():
                return True
            time.sleep(0.01)
        return False

    def _started(self) -> None:
        self.assertTrue(self._wait(lambda: self.stream is not None and self.stream.reads >= 3))

    # --- save ------------------------------------------------------------
    def test_save_shows_progress_and_the_ui_stays_live(self) -> None:
        self.dlg._save_as_selected()
        self._started()
        self.assertTrue(self.dlg._busy_bar.isVisible())
        self.assertTrue(self._wait(lambda: "MiB" in self.dlg._progress_label.text()))
        self.assertFalse(self.dlg._save_btn.isEnabled())
        self.assertFalse(self.dlg._restore_btn.isEnabled())
        self.dlg._cancel_btn.click()
        self._wait(lambda: not self.dlg._busy_bar.isVisible())

    def test_save_cancel_stops_early_and_removes_the_partial_file(self) -> None:
        self.dlg._save_as_selected()
        self._started()
        self.dlg._cancel_btn.click()
        self.assertTrue(self._wait(lambda: not self.dlg._busy_bar.isVisible()))
        self.assertFalse(self.save_target.exists())
        self.assertLess(self.stream.reads, CHUNKS)
        self.assertIn("ancel", self._information.call_args[0][2])
        self.assertTrue(self.dlg._save_btn.isEnabled())
        self.assertTrue(self.dlg.isVisible())

    def test_save_runs_to_the_end_when_left_alone(self) -> None:
        self.gate.set()
        self.dlg._save_as_selected()
        self.assertTrue(self._wait(lambda: not self.dlg._busy_bar.isVisible()))
        self.assertEqual(self.save_target.stat().st_size, CHUNKS * MIB)
        self.assertIn(str(self.save_target), self._information.call_args[0][2])

    def test_save_error_is_reported_and_leaves_no_partial_file(self) -> None:
        def broken(entry):
            raise OSError("version vanished")

        with mock.patch("core.snapshot_browser.read_snapshot", broken):
            self.dlg._save_as_selected()
            self.assertTrue(self._wait(lambda: self._warning.called))
        self.assertIn("version vanished", self._warning.call_args[0][2])
        self.assertFalse(self.save_target.exists())
        self.assertTrue(self.dlg._save_btn.isEnabled())

    # Found in review: the copy wrote straight into the chosen file, so a
    # failed or cancelled save over an EXISTING file deleted it ("remove
    # the partial file") - the file the user had, gone, and no version
    # saved in its place. A read error before a single byte even unlinked
    # it without having opened it.
    def test_sad_a_failed_save_over_an_existing_file_keeps_that_file(self) -> None:
        self.save_target.write_bytes(b"precious")

        def broken(entry):
            raise OSError("version vanished")

        with mock.patch("core.snapshot_browser.read_snapshot", broken):
            self.dlg._save_as_selected()
            self.assertTrue(self._wait(lambda: self._warning.called))
        self.assertEqual(self.save_target.read_bytes(), b"precious")
        self.assertEqual(sorted(p.name for p in self.tmp.iterdir()), ["live.bin", "saved.bin"])

    def test_sad_a_cancelled_save_over_an_existing_file_keeps_that_file(self) -> None:
        self.save_target.write_bytes(b"precious")
        self.dlg._save_as_selected()
        self._started()
        self.dlg._cancel_btn.click()
        self.assertTrue(self._wait(lambda: not self.dlg._busy_bar.isVisible()))
        self.assertEqual(self.save_target.read_bytes(), b"precious")
        self.assertEqual(sorted(p.name for p in self.tmp.iterdir()), ["live.bin", "saved.bin"])

    def test_happy_a_finished_save_replaces_an_existing_file(self) -> None:
        self.save_target.write_bytes(b"precious")
        self.gate.set()
        self.dlg._save_as_selected()
        self.assertTrue(self._wait(lambda: not self.dlg._busy_bar.isVisible()))
        self.assertEqual(self.save_target.stat().st_size, CHUNKS * MIB)
        self.assertEqual(sorted(p.name for p in self.tmp.iterdir()), ["live.bin", "saved.bin"])

    def test_edge_a_save_into_a_missing_folder_reports_and_creates_nothing(self) -> None:
        missing = self.tmp / "gone" / "saved.bin"
        self.gate.set()
        with mock.patch(
            "ui.snapshot_browser_dialog.QFileDialog.getSaveFileName",
            return_value=(str(missing), ""),
        ):
            self.dlg._save_as_selected()
            self.assertTrue(self._wait(lambda: self._warning.called))
        self.assertFalse(missing.exists())

    def test_declining_the_file_dialog_starts_nothing(self) -> None:
        with mock.patch(
            "ui.snapshot_browser_dialog.QFileDialog.getSaveFileName", return_value=("", "")
        ):
            self.dlg._save_as_selected()
        self.assertIsNone(self.stream)

    # --- restore ---------------------------------------------------------
    def test_restore_cancel_leaves_the_current_file_untouched(self) -> None:
        self.dlg._restore_selected()
        self._started()
        self.dlg._cancel_btn.click()
        self.assertTrue(self._wait(lambda: not self.dlg._busy_bar.isVisible()))
        self.assertEqual(self.target_file.read_bytes(), b"original")
        self.assertEqual([p.name for p in self.tmp.iterdir() if p.name != "live.bin"], [])
        self.assertIn("ancel", self._information.call_args[0][2])

    def test_restore_completes_and_replaces_the_file(self) -> None:
        self.gate.set()
        self.dlg._restore_selected()
        self.assertTrue(self._wait(lambda: not self.dlg._busy_bar.isVisible()))
        self.assertEqual(self.target_file.stat().st_size, CHUNKS * MIB)
        self.assertIn("Restored", self._information.call_args[0][2])

    def test_restore_declined_does_nothing(self) -> None:
        from PyQt6.QtWidgets import QMessageBox

        with mock.patch("ui.snapshot_browser_dialog.QMessageBox.question") as ask:
            ask.return_value = QMessageBox.StandardButton.No
            self.dlg._restore_selected()
        self.assertIsNone(self.stream)
        self.assertEqual(self.target_file.read_bytes(), b"original")

    # --- closing ---------------------------------------------------------
    def test_escape_stops_a_running_copy(self) -> None:
        self.dlg._save_as_selected()
        self._started()
        self.dlg.reject()
        self.assertFalse(self.dlg.isVisible())
        reads = self.stream.reads
        time.sleep(0.3)
        self.assertLessEqual(self.stream.reads - reads, 2)
        self.assertLess(self.stream.reads, CHUNKS)

    def test_window_close_stops_a_running_copy(self) -> None:
        self.dlg._restore_selected()
        self._started()
        self.dlg.close()
        self.assertFalse(self.dlg.isVisible())
        time.sleep(0.3)
        self.assertLess(self.stream.reads, CHUNKS)
        self.assertEqual(self.target_file.read_bytes(), b"original")


if __name__ == "__main__":
    unittest.main()
