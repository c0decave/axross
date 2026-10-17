"""The Agent dock's transcript is readable in every theme.

Found while taking screenshots: "You:" and "Agent:" lines were black on
the dark theme's background. They carried ``style="color:inherit"``; Qt's
rich text knows no ``inherit`` and paints an invalid colour, which is
black. Normal lines now carry no colour (the palette's text colour
applies); notes from axross and tool calls stay grey.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtGui import QTextCursor  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import llm_profiles as LP  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _dock():
    from ui.agent_dock import AgentDock

    settings = LP.LLMSettings([LP.LLMProfile(name="local", provider="lmstudio")], "local")
    import tempfile

    from core.agent_session import SessionStore

    dock = AgentDock(settings_loader=lambda: settings, settings_saver=lambda s: None,
                     key_lookup=lambda n: "", root_provider=lambda: "/tmp",
                     session_store=SessionStore(Path(tempfile.mkdtemp()) / "sessions"))
    # The transcript belongs to the tab.
    dock._append = dock.current_tab()._append
    dock._on_event = dock.current_tab()._on_event
    return dock


def _brush(dock, block: int, column: int = 8):
    cursor = QTextCursor(dock.transcript.document().findBlockByNumber(block))
    cursor.movePosition(QTextCursor.MoveOperation.Right, n=column)
    return cursor.charFormat().foreground()


def test_happy_your_and_the_agents_lines_use_the_palette_colour():
    dock = _dock()
    dock._append("You:", "read Notes.md")
    dock._on_event({"type": "assistant", "text": "It lists three tasks."})
    for block in (0, 1):
        brush = _brush(dock, block)
        assert brush.style() == Qt.BrushStyle.NoBrush, (block, brush.color().name())
    dock.deleteLater()


def test_sad_notes_and_tool_calls_stay_grey():
    dock = _dock()
    dock._append("axross:", "No LLM profile is active.", muted=True)
    dock._on_event({"type": "tool_call", "name": "read_file", "args": {"path": "/tmp/x"}})
    for block in (0, 1):
        brush = _brush(dock, block, column=4)
        assert brush.style() == Qt.BrushStyle.SolidPattern
        assert brush.color().isValid() and brush.color().name() == "#888888"
    dock.deleteLater()


def test_edge_markup_in_a_line_is_still_text():
    dock = _dock()
    dock._append("You:", '<span style="color:red">x</span>')
    assert '<span style="color:red">x</span>' in dock.transcript.toPlainText()
    assert _brush(dock, 0, column=6).style() == Qt.BrushStyle.NoBrush
    dock.deleteLater()
