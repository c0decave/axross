"""A terminal dock tab keeps its output once: on its screen.

Review 2026-11-20 (terminal round 2): every tab of the terminal dock
appended all of its output to ``_TerminalTab.buffer`` as well, a string
of up to 32 MiB (TERMINAL_BUFFER_CAP_BYTES) that nothing ever showed -
the screen and its scrollback are what the widget draws. Ten busy tabs
held hundreds of megabytes for nothing, and each overflow copied the
whole string. The tab now keeps only its screen (bounded scrollback).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])

from test_terminal_output_drain import FakeSession  # noqa: E402


def _big_strings(obj, limit=100_000):
    return [name for name, value in vars(obj).items()
            if isinstance(value, (str, bytes, bytearray)) and len(value) > limit]


def test_sad_a_background_tab_keeps_no_second_copy_of_its_output():
    from ui.terminal_widget import TerminalDock

    dock = TerminalDock()
    try:
        dock._session_combo.addItem("two")
        pieces = [(f"line {i} " + "x" * 200 + "\r\n").encode() for i in range(2000)]
        dock._get_or_create_tab("two").session = FakeSession(pieces)
        dock._get_or_create_tab("Local Shell").session = FakeSession()
        for _ in range(50):
            dock._poll_output()
        tab = dock._tabs["two"]
        assert "line 1999" in "\n".join(tab.screen.screen_lines())
        assert _big_strings(tab) == []
    finally:
        dock.shutdown()
        dock.deleteLater()


def test_happy_a_session_that_ends_in_the_background_says_so_on_its_screen():
    from ui.terminal_widget import TerminalDock

    dock = TerminalDock()
    try:
        dock._session_combo.addItem("two")
        session = FakeSession([b"bye\r\n"])
        dock._get_or_create_tab("two").session = session
        dock._poll_output()
        session.is_active = False
        dock._poll_output()
        text = "\n".join(dock._tabs["two"].screen.screen_lines())
        assert "bye" in text and "Session ended" in text
    finally:
        dock.shutdown()
        dock.deleteLater()
