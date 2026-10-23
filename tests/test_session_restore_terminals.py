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


def _destroy(win) -> None:
    """Delete *win* now. deleteLater alone waits for an event loop the tests
    never run: every leaked window was restyled by each later one's theme
    and its panes kept listing deleted temp dirs."""
    from PyQt6 import sip
    from PyQt6.QtCore import QCoreApplication, QEvent

    if win is None or sip.isdeleted(win):
        return
    win.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


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


def _same_dir(a, b) -> bool:
    try:
        return a is not None and os.path.samefile(a, b)
    except OSError:
        return False


class _TerminalWindowCase(unittest.TestCase):
    """A window with a private session.json; terminals are shut down after."""

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
        self.addCleanup(_destroy, self.win)
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


class RestoreWithTerminalsTest(_TerminalWindowCase):
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


class TerminalsComeBackOnStartTest(_TerminalWindowCase):
    """Local terminal panes come back on start: a fresh shell in the same
    place, in the folder the old shell was in. A terminal of a saved
    profile comes back as a placeholder and connects only on Reconnect."""

    def restart(self, session: dict | None = None):
        """Close the window (it saves the session) and start a new one the
        way main.py does. *session* replaces the saved file in between."""
        import json

        from ui import main_window as MW

        self._close_window()
        if session is not None:
            (self.home / "session.json").write_text(json.dumps(session))
        old = self.win
        with mock.patch("pathlib.Path.home", return_value=self.home):
            self.win = MW.MainWindow()
            self.closed = False
            self.restored = self.win.restore_layout_on_start()
        self.addCleanup(_destroy, self.win)
        _destroy(old)
        self.app.processEvents()
        return self.win

    def _cd(self, term, folder: Path) -> None:
        term._session.write(f"cd '{folder}'\n".encode())
        end = time.time() + 5
        while time.time() < end:
            self.app.processEvents()
            if term.working_directory() == str(folder):
                return
            time.sleep(0.02)
        self.fail(f"the shell never reached {folder}: {term.working_directory()}")

    def _shells(self):
        return [t._session._pid for t in self.win._terminal_panes if t._session]

    def test_happy_a_local_terminal_comes_back_beside_its_pane_in_its_folder(self) -> None:
        if not Path("/proc/self/cwd").exists():
            self.skipTest("needs /proc to read the shell's folder")
        folder = self.home / "work"
        folder.mkdir()
        term, pid = self._open_local_terminal()
        self._cd(term, folder)
        win = self.restart()
        self.assertTrue(self.restored)
        self.assertTrue(_wait_dead(pid))
        self.assertEqual(len(win._terminal_panes), 1)
        new = win._terminal_panes[0]
        self.assertIsNot(new, term)
        self.assertEqual(new._session._cwd, str(folder))
        self.assertTrue(_alive(new._session._pid))
        # Same place: a splitter beside the file pane, inside the root.
        holder = new.parent()
        self.assertIsNot(holder, win._root_splitter)
        self.assertIs(holder.parent(), win._root_splitter)
        self.assertIs(holder.widget(0), win._panes[0])

    def test_sad_a_terminal_folder_that_is_gone_starts_in_home(self) -> None:
        self.restart(
            {
                "splitter": {
                    "type": "splitter",
                    "children": [
                        {"type": "pane", "local": True, "path": str(self.home)},
                        {"type": "terminal", "local": True, "cwd": str(self.home / "gone")},
                    ],
                }
            }
        )
        # The shell finds the folder gone and starts at home itself: the GUI
        # thread no longer asks the filesystem (a dead network mount there
        # kept the window from appearing - tests/test_restore_dead_path.py).
        term = self.win._terminal_panes[0]
        self.assertEqual(term._session._fallback_cwd, str(self.home))
        end = time.time() + 10
        while time.time() < end and not _same_dir(term.working_directory(), self.home):
            self.app.processEvents()
            time.sleep(0.05)
        self.assertTrue(_same_dir(term.working_directory(), self.home),
                        term.working_directory())

    def test_edge_a_restored_terminal_closes_with_its_close_button(self) -> None:
        _term, pid = self._open_local_terminal()
        win = self.restart()
        new = win._terminal_panes[0]
        new_pid = new._session._pid
        new.close_requested.emit()
        self.app.processEvents()
        self.assertEqual(win._terminal_panes, [])
        self.assertTrue(_wait_dead(new_pid))
        self.assertTrue(_wait_dead(pid))

    def test_happy_a_profile_terminal_comes_back_disconnected_and_reconnects(self) -> None:
        from core.profiles import ConnectionProfile

        prod = ConnectionProfile(name="prod", host="h", username="u", auth_type="agent")
        session = {
            "splitter": {
                "type": "splitter",
                "children": [
                    {"type": "pane", "local": True, "path": str(self.home)},
                    {"type": "terminal", "profile": "prod"},
                ],
            }
        }
        from ui import main_window as MW

        with mock.patch.object(MW.ProfileManager, "get", return_value=prod), \
                mock.patch.object(MW.ConnectionManager, "connect",
                                  side_effect=OSError("host down")) as connect:
            win = self.restart(session)
            self.assertEqual(win._terminal_panes, [])
            connect.assert_not_called()
            placeholder = win._pane_placeholders[0]
            self.assertIn("Not connected — prod", placeholder.title_text())
            placeholder.reconnect_button.click()
            self.app.processEvents()
            connect.assert_called_once()
            self.assertIs(connect.call_args.args[0], prod)
        self.assertEqual(win._pane_placeholders, [])
        self.assertEqual(len(win._terminal_panes), 1)
        self.assertIs(win._root_splitter.widget(1), win._terminal_panes[0])
        # Saved again as the profile terminal it is, not as a local shell.
        self.assertEqual(
            win._serialize_splitter(win._root_splitter)["children"][1],
            {"type": "terminal", "profile": "prod"},
        )


if __name__ == "__main__":
    unittest.main()
