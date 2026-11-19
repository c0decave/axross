"""Qt's own Markdown parser (md4c) - the fallback when markdown-it-py is not
installed (it is optional in axross), and the release notes' renderer
(ui.update_ui.ReleaseNotesView). Both escape every "<" before parsing and
take the marks out afterwards (ui.markdown_safe._escape_html / _unmark).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])

#: Characters beyond the BMP before a "<": two UTF-16 units each in Qt,
#: one character in Python.
WIDE = "# Release 👍 𝔸\n\nUse <kbd>Ctrl</kbd>+<kbd>C</kbd> if x < y 🎉 and a < b.\n"


def test_sad_the_marks_go_and_nothing_else_after_emoji_in_qts_own_parser():
    """_unmark took Python's character indices for Qt's positions (UTF-16
    units): after an emoji it deleted the wrong characters."""
    from ui import markdown_view as MV

    view = MV.MarkdownView(None)
    view.full = False  # (Qt's own parser, as without markdown-it-py)
    try:
        view.render(WIDE)
        text = view.browser.toPlainText()
        assert "Release 👍 𝔸" in text
        # (<kbd> is the code it means - fallback_text - the "<" of prose stays)
        assert "Use Ctrl+C if x < y 🎉 and a < b." in text
        assert "\u2060" not in text and "\\<" not in text
    finally:
        view.deleteLater()


def test_sad_the_release_notes_keep_their_text_after_emoji():
    from ui.update_ui import ReleaseNotesView

    view = ReleaseNotesView()
    try:
        view.set_notes(WIDE + "\n```\n🎉 <tag> x < y\n```\n")
        text = view.toPlainText()
        assert "Use <kbd>Ctrl</kbd>+<kbd>C</kbd> if x < y 🎉 and a < b." in text
        assert "🎉 <tag> x < y" in text
        assert "\u2060" not in text and "\\<" not in text
    finally:
        view.deleteLater()
