"""ScanJob: background job with progress, cancel, abandon, replace."""

from __future__ import annotations

import os
import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


class ScanJobTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from ui.scan_job import ScanJob

        self.job = ScanJob()
        self.addCleanup(self.job.deleteLater)
        self.done: list = []
        self.job.finished.connect(lambda *a: self.done.append(a))

    def _wait(self, cond, timeout=3.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            self.app.processEvents()
            if cond():
                return True
            time.sleep(0.002)
        return False

    def test_a_quick_job_reports_without_waiting_for_the_poll_interval(self) -> None:
        from ui.scan_job import ScanJob

        job = ScanJob(interval_ms=5000)  # polling alone would take 5 s
        self.addCleanup(job.deleteLater)
        got: list = []
        job.finished.connect(lambda *a: got.append(a))
        start = time.time()
        job.start(lambda cancel, progress: 42)
        self.assertTrue(self._wait(lambda: got, timeout=1.0))
        self.assertLess(time.time() - start, 0.5)
        self.assertEqual(got[0][:2], ("done", 42))

    def test_errors_are_reported_not_raised(self) -> None:
        def boom(cancel, progress):
            raise ValueError("bad")

        self.job.start(boom)
        self.assertTrue(self._wait(lambda: self.done))
        kind, value, cancelled = self.done[0]
        self.assertEqual(kind, "error")
        self.assertIsInstance(value, ValueError)

    def test_a_second_start_while_running_is_refused(self) -> None:
        gate = threading.Event()
        self.assertTrue(self.job.start(lambda c, p: gate.wait(2)))
        self.assertFalse(self.job.start(lambda c, p: 1))
        gate.set()
        self.assertTrue(self._wait(lambda: self.done))

    def test_replace_supersedes_the_running_job_and_drops_its_result(self) -> None:
        gate = threading.Event()
        self.job.start(lambda c, p: (gate.wait(2), "old")[1])
        self.assertTrue(self.job.start(lambda c, p: "new", replace=True))
        self.assertTrue(self._wait(lambda: self.done))
        gate.set()
        time.sleep(0.1)
        self.app.processEvents()
        self.assertEqual([d[1] for d in self.done], ["new"])

    def test_replace_works_even_when_the_old_result_is_waiting_to_be_polled(self) -> None:
        self.job.start(lambda c, p: "first")
        time.sleep(0.05)  # thread finished, result not yet delivered
        self.assertTrue(self.job.start(lambda c, p: "second", replace=True))
        self.assertTrue(self._wait(lambda: self.done))
        self.assertEqual(self.done[-1][1], "second")

    def test_abandon_drops_the_result(self) -> None:
        gate = threading.Event()
        self.job.start(lambda c, p: gate.wait(2))
        self.job.abandon()
        gate.set()
        time.sleep(0.2)
        self.app.processEvents()
        self.assertEqual(self.done, [])

    def test_cancel_is_visible_to_the_worker(self) -> None:
        seen: list = []

        def work(cancel, progress):
            while not cancel():
                time.sleep(0.005)
            seen.append("stopped")
            return 0

        self.job.start(work)
        self.job.cancel()
        self.assertTrue(self._wait(lambda: self.done))
        self.assertEqual(seen, ["stopped"])
        self.assertTrue(self.done[0][2])  # cancelled flag

    def test_progress_text_follows_the_formatter(self) -> None:
        from ui.scan_job import ScanJob

        job = ScanJob(interval_ms=10, formatter=lambda st: f"copied {st['scanned']}")
        self.addCleanup(job.deleteLater)
        texts: list = []
        job.progress.connect(texts.append)
        gate = threading.Event()

        def work(cancel, progress):
            progress(7, 0, "")
            gate.wait(2)

        job.start(work)
        self.assertTrue(self._wait(lambda: "copied 7" in texts))
        gate.set()

    def test_running_property(self) -> None:
        gate = threading.Event()
        self.assertFalse(self.job.running)
        self.job.start(lambda c, p: gate.wait(2))
        self.assertTrue(self.job.running)
        gate.set()
        self._wait(lambda: self.done)
        self.assertFalse(self.job.running)


if __name__ == "__main__":
    unittest.main()
