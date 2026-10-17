"""Auto-reconnect runs in the background and never freezes the window.

Found in review: ``MainWindow._check_connections`` (a 30 s QTimer slot on
the GUI thread) called ``ConnectionManager.connect`` synchronously. A
host that accepts TCP but never answers froze the window for the whole
handshake timeout (10 s measured), every interval, per dropped pane.
The pane also kept its reference on the dropped session after the
reconnect, so that session was never given back.
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


class _FS:
    """A minimal backend: a pane can list its home folder."""

    def __init__(self, home: str, connected: bool = True) -> None:
        self._home = home
        self.connected = connected
        self.name = "fake"

    def home(self) -> str:
        return self._home

    def list_dir(self, path: str):
        return []

    def is_dir(self, path: str) -> bool:
        return True

    def exists(self, path: str) -> bool:
        return True

    def normalize(self, path: str) -> str:
        return path

    def join(self, *parts: str) -> str:
        return os.path.join(*parts)

    def parent(self, path: str) -> str:
        return os.path.dirname(path)

    def disconnect(self) -> None:
        self.connected = False


class AutoReconnectBackgroundTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from ui import main_window as MW

        self.MW = MW
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        with mock.patch("pathlib.Path.home", return_value=Path(self.home)):
            self.win = MW.MainWindow()
        self.addCleanup(self.win.deleteLater)
        self.addCleanup(self.win.close)
        self.pane = self.win._panes[0]
        self.dropped = _FS(self.home, connected=False)
        self.pane._backend = self.dropped
        self.profile = mock.Mock(host="h")
        self.profile.name = "box"
        self.win._pane_profiles[self.pane] = self.profile
        self.addCleanup(self.win._pane_profiles.clear)
        self.gate = threading.Event()
        self.connects: list = []
        self.releases: list = []
        self.new_session = _FS(self.home)
        self.failure: Exception | None = None
        cm = self.win._connection_manager
        patches = [
            mock.patch.object(self.MW, "_is_ssh_session", return_value=True),
            mock.patch.object(cm, "connect", side_effect=self._connect),
            mock.patch.object(cm, "release", side_effect=self.releases.append),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.addCleanup(self.gate.set)

    def _connect(self, profile, **_kw):
        self.connects.append(profile)
        self.gate.wait(10)
        if self.failure is not None:
            raise self.failure
        return self.new_session

    def pump_until(self, cond, timeout: float = 5.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            self.app.processEvents()
            if cond():
                return True
            time.sleep(0.005)
        return cond()

    def test_happy_check_returns_at_once_and_the_pane_gets_the_new_session(self) -> None:
        start = time.monotonic()
        self.win._check_connections()
        self.assertLess(time.monotonic() - start, 1.0)
        self.assertTrue(self.pump_until(lambda: self.connects))
        self.assertIs(self.pane.backend, self.dropped)  # still connecting
        self.gate.set()
        self.assertTrue(self.pump_until(lambda: self.pane.backend is self.new_session))
        # The pane gives back its reference on the dropped session.
        self.assertEqual(self.releases, [self.profile])

    def test_sad_failed_reconnect_keeps_the_pane_and_retries_later(self) -> None:
        self.failure = OSError("no route")
        self.gate.set()
        self.win._check_connections()
        self.assertTrue(self.pump_until(lambda: not self.win._reconnecting))
        self.assertIs(self.pane.backend, self.dropped)
        self.assertEqual(self.releases, [])
        self.win._check_connections()  # the next tick tries again
        self.assertTrue(self.pump_until(lambda: len(self.connects) == 2))

    def test_edge_a_reconnect_in_flight_is_not_started_twice(self) -> None:
        self.win._check_connections()
        self.assertTrue(self.pump_until(lambda: self.connects))
        self.win._check_connections()
        self.win._check_connections()
        self.app.processEvents()
        time.sleep(0.1)
        self.assertEqual(len(self.connects), 1)
        self.gate.set()
        self.assertTrue(self.pump_until(lambda: self.pane.backend is self.new_session))

    def test_edge_pane_closed_meanwhile_gives_the_new_session_back(self) -> None:
        self.win._check_connections()
        self.assertTrue(self.pump_until(lambda: self.connects))
        del self.win._pane_profiles[self.pane]  # the pane closed
        self.gate.set()
        self.assertTrue(self.pump_until(lambda: self.releases))
        self.assertEqual(self.releases, [self.profile])
        self.assertIs(self.pane.backend, self.dropped)


if __name__ == "__main__":
    unittest.main()
