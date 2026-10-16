"""A terminal pane gives back exactly the session references it took.

Before, the pane released one reference on shutdown whatever it held:

* a layout-preset terminal (``MainWindow._preset_make_terminal_pane``)
  took no reference when it borrowed a file pane's live session, yet
  its shutdown released one - closing the terminal disconnected the
  file pane's session under it;
* every start or Restart that went through ``ConnectionManager.connect``
  took one more reference, also when the session had no shell transport
  (a Telnet profile, say), and shutdown released only one - the session
  stayed open until exit.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.connection_manager import ConnectionManager  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402


class _FakeTransport:
    def __init__(self) -> None:
        self.active = True

    def is_active(self) -> bool:
        return self.active


class _FakeSSHSession:
    """Shaped like SSHSession: ``connected`` follows the transport."""

    def __init__(self) -> None:
        self.transport = _FakeTransport()
        self.disconnects = 0

    @property
    def connected(self) -> bool:
        return self.transport.active

    def disconnect(self) -> None:
        self.disconnects += 1
        self.transport.active = False


class _FakeShellLessSession:
    """A backend without a shell transport (Telnet, FTP ...)."""

    def __init__(self) -> None:
        self.connected = True
        self.disconnects = 0

    def disconnect(self) -> None:
        self.disconnects += 1
        self.connected = False


class _FakeShell:
    def __init__(self, transport, suppress_history=True) -> None:
        self.transport = transport
        self.is_active = False

    def start(self) -> None:
        self.is_active = True

    def close(self) -> None:
        self.is_active = False

    def read(self) -> bytes:
        return b""

    def write(self, data: bytes) -> None:
        pass


class _Base(unittest.TestCase):
    session_factory = _FakeSSHSession

    @classmethod
    def setUpClass(cls) -> None:
        from PyQt6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.created: list = []

        def create(_cm, _resolved, *_a, **_kw):
            session = self.session_factory()
            self.created.append(session)
            return session

        for patcher in (
            mock.patch.object(ConnectionManager, "_create_session", create),
            mock.patch("ui.terminal_pane.SSHTerminalSession", _FakeShell),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.cm = ConnectionManager()
        self.profile = ConnectionProfile(
            name="p", protocol="sftp", host="files.example", port=22, proxy_mode="none"
        )

    def _pane(self, **kw):
        from ui.terminal_pane import TerminalPaneWidget

        pane = TerminalPaneWidget(
            label="t", profile=self.profile, connection_manager=self.cm, **kw
        )
        self.addCleanup(pane.deleteLater)
        return pane


class BorrowedSessionTest(_Base):
    def test_sad_preset_terminal_close_keeps_the_file_pane_session(self) -> None:
        file_session = self.cm.connect(self.profile)  # the file pane
        term = self._pane()  # preset-style: no reference taken outside
        term.shutdown()
        self.assertEqual(file_session.disconnects, 0)
        self.cm.release(self.profile)  # the file pane closes
        self.assertEqual(file_session.disconnects, 1)

    def test_happy_terminal_outlives_the_file_pane(self) -> None:
        file_session = self.cm.connect(self.profile)
        term = self._pane(transport=file_session.transport)
        self.cm.release(self.profile)  # file pane closes first
        self.assertEqual(file_session.disconnects, 0)
        term.shutdown()
        self.assertEqual(file_session.disconnects, 1)

    def test_edge_shutdown_twice_releases_once(self) -> None:
        file_session = self.cm.connect(self.profile)
        term = self._pane()
        term.shutdown()
        term.shutdown()
        self.assertEqual(file_session.disconnects, 0)

    def test_edge_restart_on_a_live_session_takes_no_extra_reference(self) -> None:
        term = self._pane()  # connects: one reference
        term._restart_session()
        term._restart_session()
        term.shutdown()
        self.assertEqual([s.disconnects for s in self.created], [1])


class ShellLessSessionTest(_Base):
    session_factory = _FakeShellLessSession

    def test_sad_restarts_without_a_transport_leak_no_reference(self) -> None:
        term = self._pane()
        term._restart_session()
        term._restart_session()
        term.shutdown()
        self.assertTrue(self.created)
        self.assertEqual(self.cm.active_sessions(), [])


class MainWindowPathsTest(_Base):
    def setUp(self) -> None:
        super().setUp()
        from ui import main_window as MW

        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home, ignore_errors=True)
        with mock.patch("pathlib.Path.home", return_value=Path(home)):
            self.win = MW.MainWindow()
        self.addCleanup(self.win.deleteLater)
        self.addCleanup(self.win.close)
        self.win._connection_manager = self.cm

    def test_happy_embedded_terminal_and_file_pane_release_once_each(self) -> None:
        file_session = self.cm.connect(self.profile)
        self.win._embed_terminal_pane(file_session.transport, "SSH: p", self.profile, None)
        term = self.win._terminal_panes[-1]
        self.win._close_terminal_pane(term)
        self.assertEqual(file_session.disconnects, 0)
        self.cm.release(self.profile)
        self.assertEqual(file_session.disconnects, 1)

    def test_sad_preset_terminal_close_keeps_the_file_pane_session(self) -> None:
        file_session = self.cm.connect(self.profile)
        with mock.patch.object(self.win._profile_manager, "get", return_value=self.profile):
            term = self.win._preset_make_terminal_pane("p")
        self.win._close_terminal_pane(term)
        self.assertEqual(file_session.disconnects, 0)


if __name__ == "__main__":
    unittest.main()
