"""Restoring a saved session takes the open terminal panes down properly.

Found in review: ``_restore_session`` closed the file panes one by one
but cleared the root splitter by detaching its children. A terminal pane
inside a nested splitter was deleted with that splitter while it stayed
in ``_terminal_panes`` and its shell kept running; closing the window
then raised in ``tp.shutdown()`` ("wrapped C/C++ object ... has been
deleted") and skipped the rest of closeEvent - transfer threads,
connections and archive temp dirs were never cleaned up.
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
    try:
        done, _status = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return False
    return done == 0


def _wait_dead(pid: int, timeout: float = 3.0) -> bool:
    end = time.time() + timeout
    while _alive(pid) and time.time() < end:
        time.sleep(0.02)
    return not _alive(pid)


class RestoreWithTerminalsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from ui import main_window as MW

        self.home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        with mock.patch("pathlib.Path.home", return_value=self.home):
            self.win = MW.MainWindow()
        session = mock.patch.object(
            MW.MainWindow, "_SESSION_FILE", self.home / "session.json"
        )
        session.start()
        self.addCleanup(session.stop)
        self.addCleanup(self.win.deleteLater)
        self.closed = False

    def tearDown(self) -> None:
        # Take dead terminal panes out first: an exception escaping the
        # C++-called closeEvent would abort the whole test process.
        for tp in list(self.win._terminal_panes):
            try:
                tp.shutdown()
            except RuntimeError:
                session = getattr(tp, "_session", None)
                if session is not None:
                    session.close()
        self.win._terminal_panes.clear()
        if not self.closed:
            self.win.close()

    def _close_window(self) -> None:
        """closeEvent called from Python, so an exception in it fails the
        test instead of aborting the process from inside Qt."""
        from PyQt6.QtGui import QCloseEvent

        self.win.closeEvent(QCloseEvent())
        self.closed = True

    def _open_local_terminal(self):
        self.win._embed_terminal_pane(None, "Local Shell", None, self.win._active_pane)
        self.app.processEvents()
        term = self.win._terminal_panes[-1]
        return term, term._session._pid

    def test_sad_restore_stops_the_shell_of_a_nested_terminal_pane(self) -> None:
        from PyQt6 import sip

        term, pid = self._open_local_terminal()
        self.win._save_session()
        self.win._restore_session()
        self.app.processEvents()
        self.assertNotIn(term, self.win._terminal_panes)
        self.assertTrue(_wait_dead(pid), "the terminal's shell outlived the restore")
        self.assertTrue(sip.isdeleted(term) or not term.isVisible())

    def test_sad_closing_the_window_after_a_restore_runs_the_whole_cleanup(self) -> None:
        self._open_local_terminal()
        self.win._save_session()
        self.win._restore_session()
        self.app.processEvents()
        with mock.patch.object(self.win._connection_manager, "disconnect_all") as disconnect:
            self._close_window()
        disconnect.assert_called_once()

    def test_happy_restore_without_terminals_rebuilds_the_file_panes(self) -> None:
        self.win._split_pane(__import__("PyQt6.QtCore", fromlist=["Qt"]).Qt.Orientation.Horizontal)
        self.assertEqual(len(self.win._panes), 2)
        self.win._save_session()
        self.win._restore_session()
        self.app.processEvents()
        self.assertEqual(len(self.win._panes), 2)
        self.assertEqual(self.win._terminal_panes, [])

    def test_edge_one_dead_terminal_does_not_stop_the_window_cleanup(self) -> None:
        """Defence in depth for closeEvent itself."""
        term, pid = self._open_local_terminal()
        session = term._session
        with mock.patch.object(term, "shutdown", side_effect=RuntimeError("gone")), \
                mock.patch.object(self.win._connection_manager, "disconnect_all") as disconnect:
            try:
                self._close_window()
            finally:
                session.close()  # the patched shutdown left the shell running
        disconnect.assert_called_once()
        self.assertTrue(_wait_dead(pid))


if __name__ == "__main__":
    unittest.main()
