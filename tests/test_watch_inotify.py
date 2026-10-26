"""Local panes are watched by inotify (watchdog) instead of a 2 s poll.

Before 0.14.51 ``watchdog`` was declared nowhere, so no install had it and
every local pane listed its folder again every 2 seconds
(core.watch.PollingWatcher). The inotify path in core/watch.py had never run
anywhere; declaring the package showed what it would have done:

* it registered a PollingWatcher "factory" for sftp, which made
  auto_refresh_by_default() true for every SFTP pane - each would have
  listed its remote folder every 2 s without being asked;
* a rename inside the folder was a "moved" event, and nothing handled it;
* when the push watcher could not start (folder gone, inotify instance
  limit), the thread died with a log line and the pane was not watched at
  all.

The tests that need the real package skip without it; the declaration gate
(tests/test_declared_dependencies.py) keeps it in the base install.
"""

from __future__ import annotations

import errno
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import watch as W  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

try:
    import watchdog  # noqa: F401
except ImportError:  # pragma: no cover - the base install has it
    HAVE_WATCHDOG = False
else:
    HAVE_WATCHDOG = True

needs_watchdog = unittest.skipUnless(HAVE_WATCHDOG, "watchdog not installed")

#: How long an event may take to arrive, and how long a quiet folder is
#: watched to see that nothing arrives.
ARRIVE = 3.0
QUIET = 1.0


# A stand-in for the watchdog package, so the registration logic can be
# checked where the real package is not installed.
_FAKE_WATCHDOG = {
    "watchdog/__init__.py": "",
    "watchdog/events.py": "class FileSystemEventHandler:\n    pass\n",
    "watchdog/observers/__init__.py": textwrap.dedent("""\
        class Observer:
            def schedule(self, *a, **kw):
                pass
            def start(self):
                pass
            def stop(self):
                pass
            def join(self, timeout=None):
                pass
        """),
}


def _with_fake_watchdog(code: str) -> str:
    tmp = Path(tempfile.mkdtemp())
    try:
        for rel, text in _FAKE_WATCHDOG.items():
            (tmp / rel).parent.mkdir(parents=True, exist_ok=True)
            (tmp / rel).write_text(text)
        env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(tmp), str(ROOT)]))
        done = subprocess.run(
            [sys.executable, "-c", code], cwd=ROOT, env=env,
            capture_output=True, text=True, timeout=120)
        if done.returncode != 0:
            raise AssertionError(done.stderr)
        return done.stdout.strip()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


class RegistrationTest(unittest.TestCase):
    """What core.watch registers once watchdog can be imported."""

    def test_sad_sftp_is_not_registered_so_it_does_not_poll_by_default(self) -> None:
        out = _with_fake_watchdog(textwrap.dedent("""\
            from core import watch as W
            from core.local_fs import LocalFS
            class SSHSession(LocalFS):
                pass
            print(sorted(W._WATCHER_FACTORIES), W.auto_refresh_by_default(SSHSession()))
            """))
        self.assertEqual(out, "['local'] False")

    def test_happy_local_gets_the_push_watcher(self) -> None:
        out = _with_fake_watchdog(textwrap.dedent("""\
            from core import watch as W
            print(W._WATCHER_FACTORIES['local'].__name__,
                  W.auto_refresh_by_default(W.LocalFS()))
            """))
        self.assertEqual(out, "_LocalFSInotifyWatcher True")


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / "a.txt").write_text("a")
        (self.tmp / "sub").mkdir()
        self.outside = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.outside, ignore_errors=True)
        self.fs = LocalFS()
        self.events: list[tuple[str, str, str]] = []
        self.lock = threading.Lock()
        self.arrived = threading.Event()

    def cb(self, *ev) -> None:
        with self.lock:
            self.events.append(ev)
        self.arrived.set()

    def start(self, path: Path | None = None) -> W.Watcher:
        w = W.watch(self.fs, str(path or self.tmp), self.cb)
        self.addCleanup(w.stop, 2.0)
        return w

    def settle(self) -> None:
        # Let the observer finish starting and swallow anything the setup
        # itself caused.
        time.sleep(0.3)
        with self.lock:
            self.events.clear()
        self.arrived.clear()

    def wait_event(self) -> list:
        self.assertTrue(self.arrived.wait(ARRIVE), "no event arrived")
        time.sleep(0.1)
        with self.lock:
            return list(self.events)

    def assert_quiet(self) -> None:
        time.sleep(QUIET)
        with self.lock:
            self.assertEqual(self.events, [])


@needs_watchdog
class HappyTest(_Base):
    def test_happy_a_local_folder_gets_the_push_watcher(self) -> None:
        w = self.start()
        self.assertIsInstance(w, W._LocalFSInotifyWatcher)

    def test_happy_create_modify_delete_each_arrive(self) -> None:
        self.start()
        self.settle()
        (self.tmp / "new.txt").write_text("x")
        self.assertTrue(self.wait_event())
        self.settle()
        with open(self.tmp / "a.txt", "a") as fh:
            fh.write("more")
        self.assertTrue(self.wait_event())
        self.settle()
        (self.tmp / "a.txt").unlink()
        self.assertTrue(self.wait_event())

    def test_happy_a_rename_inside_the_folder_arrives(self) -> None:
        self.start()
        self.settle()
        os.rename(self.tmp / "a.txt", self.tmp / "b.txt")
        events = self.wait_event()
        paths = {p for _, p, _ in events}
        self.assertIn(str(self.tmp / "b.txt"), paths)

    def test_happy_moving_in_and_out_arrives(self) -> None:
        self.start()
        self.settle()
        shutil.move(str(self.tmp / "a.txt"), str(self.outside / "a.txt"))
        self.assertTrue(self.wait_event())
        self.settle()
        shutil.move(str(self.outside / "a.txt"), str(self.tmp / "back.txt"))
        self.assertTrue(self.wait_event())


@needs_watchdog
class QuietTest(_Base):
    """What the pane does itself must not look like a change, or a refresh
    would cause the next refresh."""

    def test_edge_listing_the_folder_is_no_event(self) -> None:
        self.start()
        self.settle()
        self.fs.list_dir(str(self.tmp))
        list(os.scandir(self.tmp))
        self.assert_quiet()

    def test_edge_reading_a_file_is_no_event(self) -> None:
        # Thumbnails and the preview read files in the shown folder.
        self.start()
        self.settle()
        with self.fs.open_read(str(self.tmp / "a.txt")) as fh:
            fh.read()
        self.fs.stat(str(self.tmp / "a.txt"))
        self.assert_quiet()

    def test_edge_a_change_in_a_subfolder_is_no_event(self) -> None:
        # The pane shows one level; the watch is not recursive.
        self.start()
        self.settle()
        (self.tmp / "sub" / "deep.txt").write_text("x")
        self.assert_quiet()


@needs_watchdog
class StopTest(_Base):
    def test_edge_stop_leaves_no_thread(self) -> None:
        before = {t.ident for t in threading.enumerate()}
        w = W.watch(self.fs, str(self.tmp), self.cb)
        time.sleep(0.3)
        started = time.monotonic()
        w.stop(2.0)
        self.assertLess(time.monotonic() - started, 2.0)
        time.sleep(0.2)
        left = [t for t in threading.enumerate() if t.ident not in before]
        self.assertEqual(left, [])

    def test_edge_no_event_after_stop(self) -> None:
        w = W.watch(self.fs, str(self.tmp), self.cb)
        time.sleep(0.3)
        w.stop(2.0)
        with self.lock:
            self.events.clear()
        (self.tmp / "late.txt").write_text("x")
        self.assert_quiet()


@needs_watchdog
class FallbackTest(_Base):
    """A push watcher that cannot start falls back to polling, so the pane
    is still watched."""

    def test_sad_a_missing_folder_falls_back_to_polling(self) -> None:
        gone = self.tmp / "gone"
        with self.assertLogs("core.watch", level="WARNING") as logs:
            w = self.start(gone)
        self.assertIsInstance(w, W.PollingWatcher)
        self.assertIn(str(gone), "\n".join(logs.output))

    def test_sad_the_inotify_limit_falls_back_to_polling(self) -> None:
        full = OSError(errno.EMFILE, "inotify instance limit reached")
        with mock.patch.object(W._WatchdogObserver, "schedule", side_effect=full), \
                self.assertLogs("core.watch", level="WARNING"):
            w = self.start()
        self.assertIsInstance(w, W.PollingWatcher)
        self.settle()
        (self.tmp / "polled.txt").write_text("x")
        # The poll runs every 2 s.
        self.assertTrue(self.arrived.wait(ARRIVE + 2.0))

    def test_edge_the_failed_observer_leaves_no_thread(self) -> None:
        before = {t.ident for t in threading.enumerate()}
        w = W.watch(self.fs, str(self.tmp / "gone"), self.cb)
        w.stop(2.0)
        time.sleep(0.2)
        left = [t for t in threading.enumerate() if t.ident not in before]
        self.assertEqual(left, [])


@needs_watchdog
class PaneTest(unittest.TestCase):
    """e2e: a real local pane picks up a change without a poll, and stays
    quiet while nothing changes."""

    @classmethod
    def setUpClass(cls) -> None:
        from PyQt6.QtWidgets import QApplication
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        for n in ("a.txt", "b.png", "c.md"):
            (self.tmp / n).write_bytes(b"x" * 64)

    def pump(self, seconds: float, until=None) -> bool:
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self.app.processEvents()
            if until is not None and until():
                return True
            time.sleep(0.02)
        return False

    def names(self, pane) -> set[str]:
        return {item.name for item in pane._model._items}

    def test_e2e_pane_sees_a_new_file_and_stays_quiet(self) -> None:
        from ui.file_pane import FilePaneWidget

        pane = FilePaneWidget(LocalFS())
        self.addCleanup(pane.deleteLater)
        self.addCleanup(pane.shutdown)
        pane.resize(800, 500)
        pane.show()
        pane.navigate(str(self.tmp))
        self.assertTrue(self.pump(5.0, lambda: "a.txt" in self.names(pane)))
        self.assertIsInstance(pane._watcher, W._LocalFSInotifyWatcher)

        refreshes = []
        real = pane.refresh_async

        def counting(*a, **kw):
            refreshes.append(time.monotonic())
            return real(*a, **kw)

        pane.refresh_async = counting
        # Quiet: the pane's own listing, thumbnails and preview cause none.
        self.pump(3.0)
        self.assertEqual(refreshes, [])

        (self.tmp / "fresh.txt").write_text("new")
        self.assertTrue(self.pump(ARRIVE + 1.0, lambda: "fresh.txt" in self.names(pane)))
        # Well below the old 2 s poll plus its debounce.
        self.assertEqual(len(refreshes), 1)
        # And quiet again afterwards: the refresh did not cause another.
        self.pump(3.0)
        self.assertEqual(len(refreshes), 1)


if __name__ == "__main__":
    unittest.main()
