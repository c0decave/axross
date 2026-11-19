"""The terminal dock's Start of a local shell that cannot start.

Measured before: Start on a local entry called the session's start()
unguarded (only the SSH branch had a try). A pty that could not be opened
(all ptys in use, a shell that is gone) went to the application's error
dialog, and the entry kept a session object that never ran.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")
from PyQt6.QtWidgets import QApplication  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def test_sad_a_local_shell_that_cannot_start_is_told_in_the_dock(app):
    from ui import terminal_widget as TW

    dock = TW.TerminalDock()
    try:
        closed = []
        with mock.patch.object(TW.LocalTerminalSession, "start",
                               side_effect=OSError(24, "out of pty devices")), \
                mock.patch.object(TW.LocalTerminalSession, "close",
                                  lambda self: closed.append(self)):
            dock._start_session()  # raised into the error dialog before
        tab = dock._tabs[dock._current_key()]
        assert tab.session is None
        assert len(closed) == 1
        assert dock._btn_start.isEnabled()
        assert not dock._btn_stop.isEnabled()
        assert any("out of pty devices" in line for line in dock._terminal.screen.screen_lines())
    finally:
        dock.shutdown()
        dock.deleteLater()


def test_happy_a_local_shell_starts(app):
    from ui import terminal_widget as TW

    dock = TW.TerminalDock()
    try:
        dock._start_session()
        tab = dock._tabs[dock._current_key()]
        assert tab.session is not None and tab.session.is_active
        assert not dock._btn_start.isEnabled()
    finally:
        dock.shutdown()
        dock.deleteLater()
