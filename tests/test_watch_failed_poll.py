"""A failed poll is "no news", never an empty folder.

Before: ``PollingWatcher._snapshot`` turned an ``OSError`` from
``list_dir`` into an empty snapshot, so one failed listing (a network
blip) reported every entry as "deleted" and the next good listing every
entry as "created". The file pane turns each burst into a background
refresh. Any other exception (``EOFError``, ``paramiko.SSHException``)
escaped ``_run`` and ended the watcher thread for good, silently.

Now a failed listing keeps the previous snapshot and the watcher goes on.
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

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import watch as W  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


class _FlakyFS(LocalFS):
    """LocalFS whose listing fails while ``failure`` is set."""

    def __init__(self) -> None:
        super().__init__()
        self.failure: BaseException | None = None

    def list_dir(self, path):
        if self.failure is not None:
            raise self.failure
        return super().list_dir(path)


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        for name in ("a.txt", "b.txt"):
            (self.tmp / name).write_text(name)
        self.fs = _FlakyFS()
        self.events: list = []
        self.lock = threading.Lock()

    def cb(self, *event) -> None:
        with self.lock:
            self.events.append(event)

    def start(self) -> W.PollingWatcher:
        w = W.watch(self.fs, str(self.tmp), self.cb, interval=0.2, force_polling=True)
        self.addCleanup(w.stop, 2.0)
        return w


class FailedPollTest(_Base):
    def test_happy_a_failed_poll_reports_nothing(self) -> None:
        w = self.start()
        self.fs.failure = OSError("connection reset")
        self.assertTrue(w.wait_for_tick(2, timeout=5))
        self.fs.failure = None
        self.assertTrue(w.wait_for_tick(2, timeout=5))
        self.assertEqual(self.events, [])

    def test_sad_a_non_oserror_does_not_end_the_watcher(self) -> None:
        w = self.start()
        self.fs.failure = EOFError("transport closed")
        time.sleep(0.6)
        self.fs.failure = None
        (self.tmp / "c.txt").write_text("c")
        self.assertTrue(w.wait_for_tick(2, timeout=5))
        self.assertEqual(self.events, [("created", str(self.tmp / "c.txt"), "file")])

    def test_edge_a_change_made_during_the_outage_is_reported_once(self) -> None:
        w = self.start()
        self.fs.failure = OSError("timeout")
        self.assertTrue(w.wait_for_tick(1, timeout=5))
        (self.tmp / "b.txt").unlink()
        self.assertTrue(w.wait_for_tick(1, timeout=5))
        self.fs.failure = None
        self.assertTrue(w.wait_for_tick(2, timeout=5))
        self.assertEqual(self.events, [("deleted", str(self.tmp / "b.txt"), "file")])

    def test_edge_a_failed_first_listing_is_no_baseline(self) -> None:
        self.fs.failure = OSError("not reachable yet")
        w = self.start()
        self.fs.failure = None
        self.assertTrue(w.wait_for_tick(2, timeout=5))
        self.assertEqual(self.events, [])  # a.txt / b.txt were there all along
        (self.tmp / "c.txt").write_text("c")
        self.assertTrue(w.wait_for_tick(2, timeout=5))
        self.assertEqual(self.events, [("created", str(self.tmp / "c.txt"), "file")])


class PaneTest(_Base):
    """End to end: the pane's background refresh is driven by watch events."""

    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def _pump(self, seconds: float) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.app.processEvents()
            time.sleep(0.02)

    def test_sad_a_network_blip_does_not_refresh_the_pane(self) -> None:
        from ui.file_pane import FilePaneWidget

        # Polling for this LocalFS subclass, as for every remote backend.
        patcher = mock.patch.dict(W._WATCHER_FACTORIES, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        pane = FilePaneWidget(self.fs)
        self.addCleanup(pane.shutdown)
        refreshes: list[float] = []
        pane._on_debounce_fired = lambda: refreshes.append(time.monotonic())
        pane.navigate(str(self.tmp))
        watcher = pane._watcher
        self.assertIsInstance(watcher, W.PollingWatcher)
        watcher._interval = 0.2  # the pane's 2 s, shortened after the first tick

        self.fs.failure = OSError("connection reset")
        self.assertTrue(watcher.wait_for_tick(2, timeout=8))
        self.fs.failure = None
        self.assertTrue(watcher.wait_for_tick(2, timeout=8))
        self._pump(0.6)
        self.assertEqual(refreshes, [])

        (self.tmp / "c.txt").write_text("c")  # the watcher is still alive
        self.assertTrue(watcher.wait_for_tick(2, timeout=8))
        self._pump(0.6)
        self.assertEqual(len(refreshes), 1)


if __name__ == "__main__":
    unittest.main()
