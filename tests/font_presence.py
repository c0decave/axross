"""Whether Qt has a real font to measure and draw text with.

A host without any font file (a bare container: no fontconfig configuration,
no fonts) still runs Qt, but every glyph is an empty box of one width - 12 px
at 9 pt, as wide as DejaVu Sans at about 16 pt - and no text is drawn. A test
that holds the window to a pixel budget set by the text in it (the smallest
window width with its docks and title bars) means nothing there; it skips
with :func:`no_font_reason`. Only that: with any font installed it runs.
"""

from __future__ import annotations


def no_font_reason() -> str:
    """Why text cannot be measured here, or "" when a real font is in use."""
    from PyQt6.QtGui import QFontInfo
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance()
    if app is None or QFontInfo(app.font()).family():
        return ""
    return "no font installed: Qt measures every glyph as an empty box (12 px at 9 pt)"


__all__ = ["no_font_reason"]
