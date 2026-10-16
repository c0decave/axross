"""Switching the layout preset releases what the old layout held.

Found in review: ``_preset_tear_down_existing`` called ``close()`` on the
terminal panes, but TerminalPaneWidget has no closeEvent - its shell was
never stopped, so every Ctrl+Alt+L through a preset with terminals left
local shells (and their pty) running in the background. File panes on a
saved connection were dropped from the bookkeeping without
``ConnectionManager.release``, so the session stayed open until exit.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def _alive(pid: int) -> bool:
    """True while *pid* is running (a zombie of ours counts as gone)."""
    try:
        done, _status = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return False
    return done == 0


class PresetTeardownTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from ui import main_window as MW

        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home, ignore_errors=True)
        with mock.patch("pathlib.Path.home", return_value=Path(home)):
            self.win = MW.MainWindow()
        self.addCleanup(self.win.deleteLater)
        self.addCleanup(self.win.close)

    def _terminal_pids(self) -> list[int]:
        pids = []
        for term in self.win._terminal_panes:
            session = term._session
            if session is not None and getattr(session, "_pid", None):
                pids.append(session._pid)
        return pids

    def test_sad_leaving_a_preset_stops_its_local_shells(self) -> None:
        self.win.apply_layout_preset("dev-shells")
        pids = self._terminal_pids()
        self.assertEqual(len(pids), 2)
        self.assertTrue(all(_alive(p) for p in pids))
        self.win.apply_layout_preset("single")
        self.assertEqual(self.win._terminal_panes, [])
        deadline = time.time() + 3
        while any(_alive(p) for p in pids) and time.time() < deadline:
            time.sleep(0.02)
        self.assertFalse([p for p in pids if _alive(p)], "shells outlived their preset")

    def test_sad_leaving_a_preset_releases_a_file_panes_connection(self) -> None:
        self.win.apply_layout_preset("dual")
        pane = self.win._panes[0]
        profile = mock.Mock(name="profile")
        self.win._pane_profiles[pane] = profile
        with mock.patch.object(self.win._connection_manager, "release") as release:
            self.win.apply_layout_preset("single")
        release.assert_called_once_with(profile)
        self.assertEqual(self.win._pane_profiles, {})

    def test_happy_cycling_presets_keeps_one_live_set_of_panes(self) -> None:
        self.win.apply_layout_preset("triage")
        self.assertEqual(len(self.win._panes), 2)
        self.assertEqual(len(self._terminal_pids()), 1)
        self.win.apply_layout_preset("quad-files")
        self.assertEqual(len(self.win._panes), 4)
        self.assertEqual(self.win._terminal_panes, [])
        self.assertIs(self.win._active_pane, self.win._panes[0])

    def test_edge_a_preset_without_terminals_or_profiles_tears_down_cleanly(self) -> None:
        self.win.apply_layout_preset("single")
        with mock.patch.object(self.win._connection_manager, "release") as release:
            self.win.apply_layout_preset("dual")
        release.assert_not_called()
        self.assertEqual(len(self.win._panes), 2)


if __name__ == "__main__":
    unittest.main()
