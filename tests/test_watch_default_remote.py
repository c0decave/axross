"""Auto-refresh is on by default for local folders only.

A remote backend has no push notification here, so core.watch falls back
to PollingWatcher: the pane listed the remote folder again every 2 seconds
for as long as it was open - on S3 or a cloud drive a paid, rate-limited
LIST call, on SFTP a round trip the server logs - although nobody had asked
for it (ui/file_pane.py set the toggle on for every pane). Now a remote
pane starts with auto-refresh off; one click turns it on for that pane.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import watch as W  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402


class SSHSession(LocalFS):
    """Stands in for an SFTP connection: core.watch resolves the protocol
    from the class name (backend_registry), listing stays local."""


class FtpSession(LocalFS):
    """Stands in for an FTP connection."""


class _PaneBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        Path(self.tmp, "a.txt").write_text("a")
        self.started: list[tuple[str, str]] = []

        def fake_watch(backend, path, callback, interval=2.0, initial_entries=None, **_kw):
            self.started.append((type(backend).__name__, path))
            return mock.MagicMock()

        patcher = mock.patch.object(W, "watch", fake_watch)
        patcher.start()
        self.addCleanup(patcher.stop)

    def pane(self, backend):
        from ui.file_pane import FilePaneWidget

        p = FilePaneWidget(backend)
        self.addCleanup(p.deleteLater)
        p.navigate(self.tmp)
        return p


# --- happy ----------------------------------------------------------------


class HappyTests(_PaneBase):
    def test_happy_a_local_pane_refreshes_by_itself(self) -> None:
        p = self.pane(LocalFS())
        self.assertTrue(p._btn_watch.isChecked())
        self.assertIn(("LocalFS", self.tmp), self.started)

    def test_happy_a_remote_pane_does_not_poll_by_default(self) -> None:
        p = self.pane(SSHSession())
        self.assertFalse(p._btn_watch.isChecked())
        self.assertEqual(self.started, [])

    def test_happy_one_click_turns_it_on_for_that_pane_e2e(self) -> None:
        p = self.pane(SSHSession())
        p.show()
        QTest.mouseClick(p._btn_watch, Qt.MouseButton.LeftButton)
        self.assertTrue(p._btn_watch.isChecked())
        self.assertEqual(self.started, [("SSHSession", self.tmp)])


# --- sad ------------------------------------------------------------------


class SadTests(_PaneBase):
    def test_sad_navigating_a_remote_pane_starts_no_watcher(self) -> None:
        p = self.pane(FtpSession())
        sub = Path(self.tmp, "sub")
        sub.mkdir()
        p.navigate(str(sub))
        p.navigate(self.tmp)
        self.assertEqual(self.started, [])

    def test_sad_turning_it_off_in_a_local_pane_stops_watching(self) -> None:
        p = self.pane(LocalFS())
        self.started.clear()
        p._btn_watch.setChecked(False)
        p.navigate(self.tmp)
        self.assertEqual(self.started, [])


# --- edge -----------------------------------------------------------------


class EdgeTests(_PaneBase):
    def test_edge_in_process_backends_count_as_local(self) -> None:
        # Listing RamFS is a dict lookup; nothing goes over a network.
        self.assertTrue(W.auto_refresh_by_default(RamFsSession()))
        self.assertTrue(W.auto_refresh_by_default(LocalFS()))

    def test_edge_remote_protocols_do_not_by_default(self) -> None:
        self.assertFalse(W.auto_refresh_by_default(SSHSession()))
        self.assertFalse(W.auto_refresh_by_default(FtpSession()))
        self.assertFalse(W.auto_refresh_by_default(object()))  # unknown: do not poll

    def test_edge_a_registered_push_watcher_turns_it_on(self) -> None:
        # A protocol with push notifications costs nothing while idle.
        with mock.patch.dict(W._WATCHER_FACTORIES, {"ftp": lambda *a, **k: None}):
            self.assertTrue(W.auto_refresh_by_default(FtpSession()))

    def test_edge_a_reconnect_keeps_the_users_choice(self) -> None:
        p = self.pane(SSHSession())
        p._btn_watch.setChecked(True)
        self.started.clear()
        p.set_backend(SSHSession(), self.tmp)
        p.navigate(self.tmp)
        self.assertTrue(p._btn_watch.isChecked())
        self.assertIn(("SSHSession", self.tmp), self.started)

    def test_edge_the_tooltip_says_why_remote_is_off(self) -> None:
        p = self.pane(SSHSession())
        self.assertIn("remote", p._btn_watch.toolTip().lower())


if __name__ == "__main__":
    unittest.main()
