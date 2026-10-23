"""The window's preferences in ``session.json`` and the one way to read them.

They live in the ``window`` object of session.json next to the layout
(keys unchanged since they were introduced, so old files load as they
are). The file is hand-editable: every value is checked, and anything that
is not a valid value of its key reads as that key's default. Before this
module the start and the layout restore each parsed the keys themselves,
and they had drifted apart (``compact: "yes"`` was off on start but on
after a restore; ``monochrome_icons: "no"`` was on in both).
"""

from __future__ import annotations

from dataclasses import dataclass

from ui import themes

THEME_KEY = "ui_theme"
COMPACT_KEY = "compact"
MONOCHROME_KEY = "monochrome_icons"
SHOW_HIDDEN_KEY = "show_hidden"
HIGHLIGHT_HIDDEN_KEY = "highlight_hidden"
HIDDEN_COLOR_KEY = "hidden_color"
RESTORE_ON_START_KEY = "restore_layout_on_start"
FONT_SIZE_KEY = "font_size"

#: Zoom range of the application font, in points.
MIN_FONT_SIZE = 6
MAX_FONT_SIZE = 24


def valid_font_size(value: object) -> bool:
    return type(value) is int and MIN_FONT_SIZE <= value <= MAX_FONT_SIZE


@dataclass(frozen=True)
class WindowPrefs:
    #: None: not stored - the window keeps the theme it has.
    theme: str | None = None
    compact: bool = False
    monochrome_icons: bool = False
    show_hidden: bool = True
    highlight_hidden: bool = True
    #: ``#rrggbb`` (lower case), or None for the theme's muted colour.
    hidden_color: str | None = None
    restore_layout_on_start: bool = True
    #: Points, or None: not stored - the desktop's font size.
    font_size: int | None = None


def parse(window: object) -> WindowPrefs:
    """The preferences of a session's ``window`` object (anything else,
    or a missing object, gives the defaults)."""
    if not isinstance(window, dict):
        return WindowPrefs()
    theme = window.get(THEME_KEY)
    colour = window.get(HIDDEN_COLOR_KEY)
    size = window.get(FONT_SIZE_KEY)
    return WindowPrefs(
        # Any value present is a choice; an unknown one is the default theme.
        theme=themes.normalize(theme) if theme else None,
        # On only when stored as true: "yes", 1 or "no" are not a choice.
        compact=window.get(COMPACT_KEY) is True,
        monochrome_icons=window.get(MONOCHROME_KEY) is True,
        # Off only when stored as false.
        show_hidden=window.get(SHOW_HIDDEN_KEY) is not False,
        highlight_hidden=window.get(HIGHLIGHT_HIDDEN_KEY) is not False,
        hidden_color=colour.lower() if themes.is_hex_colour(colour) else None,
        restore_layout_on_start=window.get(RESTORE_ON_START_KEY) is not False,
        font_size=size if valid_font_size(size) else None,
    )


__all__ = [
    "COMPACT_KEY",
    "FONT_SIZE_KEY",
    "HIDDEN_COLOR_KEY",
    "HIGHLIGHT_HIDDEN_KEY",
    "MAX_FONT_SIZE",
    "MIN_FONT_SIZE",
    "MONOCHROME_KEY",
    "RESTORE_ON_START_KEY",
    "SHOW_HIDDEN_KEY",
    "THEME_KEY",
    "WindowPrefs",
    "parse",
    "valid_font_size",
]
