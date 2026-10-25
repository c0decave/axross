"""The polling watcher can start from a listing the caller already has.

Measured before: after every navigation the pane's watcher listed the
folder a second time, synchronously on the GUI thread (152 ms for 20 000
local entries; a full round trip on a remote backend), right after the
worker thread had fetched the same listing.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import watch as W  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from models.file_item import FileItem  # noqa: E402


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        for n in ("a.txt", "b.txt"):
            (self.tmp / n).write_text(n)
        self.fs = LocalFS()
        self.events: list = []
        self.lock = threading.Lock()

    def cb(self, *ev) -> None:
        with self.lock:
            self.events.append(ev)

    def start(self, **kw) -> W.PollingWatcher:
        w = W.watch(self.fs, str(self.tmp), self.cb, interval=0.2, force_polling=True, **kw)
        self.addCleanup(w.stop, 2.0)
        return w


class InitialEntriesTest(_Base):
    def test_happy_no_second_listing_at_start(self) -> None:
        listing = self.fs.list_dir(str(self.tmp))
        with mock.patch.object(LocalFS, "list_dir", wraps=self.fs.list_dir) as ld:
            w = W.PollingWatcher(
                self.fs, str(self.tmp), self.cb, interval=60, initial_entries=listing
            )
            w.start()
            self.addCleanup(w.stop, 2.0)
        ld.assert_not_called()

    def test_happy_an_unchanged_folder_reports_nothing(self) -> None:
        w = self.start(initial_entries=self.fs.list_dir(str(self.tmp)))
        self.assertTrue(w.wait_for_tick(2, timeout=5))
        self.assertEqual(self.events, [])

    def test_sad_a_change_after_the_listing_is_reported(self) -> None:
        listing = self.fs.list_dir(str(self.tmp))
        (self.tmp / "c.txt").write_text("new")  # between listing and watcher start
        w = self.start(initial_entries=listing)
        self.assertTrue(w.wait_for_tick(1, timeout=5))
        self.assertIn(("created", str(self.tmp / "c.txt"), "file"), self.events)

    def test_edge_without_a_listing_it_takes_its_own(self) -> None:
        with mock.patch.object(LocalFS, "list_dir", wraps=self.fs.list_dir) as ld:
            w = W.PollingWatcher(self.fs, str(self.tmp), self.cb, interval=60)
            w.start()
            self.addCleanup(w.stop, 2.0)
        ld.assert_called_once()

    def test_edge_same_snapshot_as_its_own_listing(self) -> None:
        listing = self.fs.list_dir(str(self.tmp))
        w = W.PollingWatcher(self.fs, str(self.tmp), self.cb, initial_entries=listing)
        self.assertEqual(W.PollingWatcher._snapshot_of(listing).entries, w._snapshot().entries)


class OffTheCallerThreadTest(_Base):
    """Measured: turning 20,000 entries into the first snapshot took 15 ms
    of every navigation's GUI-thread time; the watcher's thread does it."""

    def test_perf_happy_the_first_snapshot_is_made_on_the_watcher_thread(self) -> None:
        listing = self.fs.list_dir(str(self.tmp))
        threads = []
        real = W.PollingWatcher._snapshot_of

        def recording(items):
            threads.append(threading.current_thread())
            return real(items)

        with mock.patch.object(W.PollingWatcher, "_snapshot_of", staticmethod(recording)):
            w = W.PollingWatcher(self.fs, str(self.tmp), self.cb, interval=0.2,
                                 initial_entries=listing)
            w.start()
            self.addCleanup(w.stop, 2.0)
            self.assertNotIn(threading.current_thread(), threads)
            self.assertTrue(w.wait_for_tick(1, timeout=5))
        self.assertTrue(threads)
        self.assertNotIn(threading.current_thread(), threads)

    def test_sad_without_a_listing_start_still_lists_at_once(self) -> None:
        """start() promises that a change made after it returns is seen:
        without a listing it must not leave its own to the thread."""
        w = W.PollingWatcher(self.fs, str(self.tmp), self.cb, interval=0.2)
        w.start()
        self.addCleanup(w.stop, 2.0)
        (self.tmp / "after.txt").write_text("x")
        self.assertTrue(w.wait_for_tick(1, timeout=5))
        self.assertIn(("created", str(self.tmp / "after.txt"), "file"), self.events)

    def test_edge_a_listing_changed_by_the_caller_afterwards_does_not_matter(self) -> None:
        listing = self.fs.list_dir(str(self.tmp))
        w = self.start(initial_entries=listing)
        listing.clear()  # the caller's list: the watcher keeps its own
        self.assertTrue(w.wait_for_tick(2, timeout=5))
        self.assertEqual(self.events, [])


class PaneTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def test_navigation_hands_the_raw_listing_to_the_watcher(self) -> None:
        from ui.file_pane import FilePaneWidget

        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "x").write_text("x")
        fs = LocalFS()
        seen = {}

        def fake_watch(backend, path, callback, interval=2.0, initial_entries=None):
            seen["entries"] = initial_entries
            return mock.MagicMock()

        with mock.patch.object(W, "watch", fake_watch):
            pane = FilePaneWidget(fs)
            self.addCleanup(pane.deleteLater)
            pane._watch_enabled = True
            pane._stop_watcher()
            pane.navigate(str(tmp))
        names = [i.name for i in seen["entries"]]
        self.assertEqual(names, ["x"])  # no injected ".."

    def test_edge_at_the_root_nothing_is_stripped(self) -> None:
        from ui.file_pane import FilePaneWidget

        items = [FileItem(name="..", is_dir=True), FileItem(name="a")]
        self.assertEqual(FilePaneWidget._raw_listing(LocalFS(), "/", items), items)
        self.assertEqual(
            [i.name for i in FilePaneWidget._raw_listing(LocalFS(), "/tmp", items)], ["a"]
        )


if __name__ == "__main__":
    unittest.main()
