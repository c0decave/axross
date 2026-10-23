"""No button needs an emoji font.

Reported: on a host without an emoji font (a plain Linux install has none;
``fc-list ':charset=1f500'`` finds nothing) the terminal pane's pin button,
the Agent dock's microphone and speaker buttons and the Media Player's
shuffle/repeat/mute showed an empty box. Their labels were emoji - 📌 🎤 🔊
🔀 - beyond U+FFFF. They now show icons drawn from embedded SVG.

The source scan is the class guard: no button label or setText in ui/ or
the bundled extensions uses a character beyond U+FFFF, written literally or
as a ``\\U0001xxxx`` escape.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])

ROOT = Path(__file__).resolve().parents[1]
SOURCES = [*sorted((ROOT / "ui").rglob("*.py")), *sorted((ROOT / "resources" / "extensions").glob("*.py"))]
_LABEL_CALL = re.compile(r"(?:QPushButton|QToolButton|setText)\((.*)")
_ESCAPE = re.compile(r"\\U0001[0-9a-fA-F]{4}")


def astral_labels(text: str) -> list[str]:
    """Button labels / setText arguments in *text* that need a character
    beyond U+FFFF (literal or ``\\U0001xxxx``)."""
    found = []
    for line in text.splitlines():
        match = _LABEL_CALL.search(line)
        if not match:
            continue
        code = match.group(1).split("#", 1)[0]
        if any(ord(c) > 0xFFFF for c in code) or _ESCAPE.search(code):
            found.append(line.strip())
    return found


# --- happy ----------------------------------------------------------------


def test_happy_the_terminal_pin_button_shows_an_icon_and_no_text():
    from ui.terminal_pane import TerminalPaneWidget

    class _Channel:
        closed = False

        def recv_ready(self):
            return False

        def exit_status_ready(self):
            return False

        def get_pty(self, *a, **kw):
            pass

        def invoke_shell(self):
            pass

        def settimeout(self, *_a):
            pass

        def close(self):
            self.closed = True

        def resize_pty(self, *a, **kw):
            pass

        def send(self, data):
            return len(data)

    class _Transport:
        def is_active(self):
            return True

        def open_session(self):
            return _Channel()

    pane = TerminalPaneWidget(transport=_Transport(), label="box")
    try:
        assert pane._btn_pin.text() == ""
        assert not pane._btn_pin.icon().isNull()
        assert pane._btn_pin.toolTip()
    finally:
        pane.close()
        pane.deleteLater()


def test_happy_the_agent_dock_mic_and_speaker_show_icons_and_no_text(tmp_path):
    from tests.test_agent_tabs import Env

    env = Env(tmp_path)
    env.fake("hello")
    try:
        tab = env.dock().current_tab()
        for name in ("mic_button", "speaker_button"):
            button = getattr(tab, name)
            assert button.text() == "", (name, button.text())
            assert not button.icon().isNull(), name
            assert button.toolTip() or name == "mic_button", name
    finally:
        env.close()


# --- sad ------------------------------------------------------------------


def test_sad_no_button_label_in_the_sources_needs_an_emoji_font():
    offenders = []
    for path in SOURCES:
        for line in astral_labels(path.read_text(encoding="utf-8")):
            offenders.append(f"{path.relative_to(ROOT)}: {line}")
    assert not offenders, offenders


def test_sad_the_scan_sees_literal_and_escaped_emoji():
    assert astral_labels('b = QPushButton("\U0001f4cc")\n')
    assert astral_labels('b = QPushButton("\\U0001f4cc")  # pin\n')
    assert astral_labels('    self.mic.setText("🎤")\n')


# --- edge -----------------------------------------------------------------


def test_edge_bmp_symbols_and_comments_are_not_flagged():
    assert astral_labels('b = QPushButton("\\u2715")  # ✕ \U0001f4cc in a comment\n') == []
    assert astral_labels('label.setText(tr("Mute (M)"))\n') == []


def test_edge_the_new_icons_exist_with_a_colour():
    from ui import icon_provider as IP

    for name in ("pin", "mic", "speaker"):
        assert IP.has_icon(name), name
        assert IP._ICON_COLORS.get(name), name
