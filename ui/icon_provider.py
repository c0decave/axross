"""Embedded SVG icon set and QIcon factory.

Why embedded SVG instead of ``QIcon.fromTheme`` or PNG assets?

* **Theme-agnostic**: SVGs stroke with ``currentColor``, which Qt
  resolves against the widget's palette. A single icon renders
  dark on a light theme and light on a dark theme automatically —
  no per-theme asset duplication.
* **Distro-portable**: ``QIcon.fromTheme`` looks up the user's
  desktop icon theme, which on a headless test host or a
  non-standard distro is missing or incomplete. Embedded SVG is
  self-contained.
* **HiDPI-clean**: SVG scales losslessly; PNG at 48×48 and 96×96
  would still ship less crisply than one 24×24-viewBox SVG.

Icons are Feather-style (24×24 viewBox, 2-px stroke, round caps
and joins) — MIT-licensed patterns we've re-authored here so
the module has no external runtime dep.

Naming convention: ``lower-kebab-case``. A caller who wants the
generic fallback uses ``icon("bookmark")`` which is guaranteed
to exist.

Usage::

    from ui.icon_provider import icon
    btn.setIcon(icon("quick-connect"))

Unknown names fall back to a grey question-mark icon so a missing
entry lands on screen as a visible placeholder instead of a
silent blank.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Iterable

from PyQt6.QtCore import QByteArray, QSize, Qt
from PyQt6.QtGui import QIcon, QPainter, QPixmap
from PyQt6.QtSvg import QSvgRenderer


# --------------------------------------------------------------------------
# SVG string table. Each entry is a ``<svg>…</svg>`` snippet we can feed
# into QSvgRenderer. Paths use ``currentColor`` so Qt colours them from
# the active palette. Keep the strings tight — a 10 KB icon module
# isn't a problem, but multi-line indenting bloats imports.
# --------------------------------------------------------------------------

_SVG_OPEN = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" '
    'fill="none" stroke="currentColor" stroke-width="2" '
    'stroke-linecap="round" stroke-linejoin="round">'
)

_SVG_CLOSE = "</svg>"


def _svg(*paths: str) -> str:
    return _SVG_OPEN + "".join(paths) + _SVG_CLOSE


# Icon category: tool actions (toolbar / menubar verbs).
# Each entry is (name, svg-body-without-wrapper).
_TOOL_ICONS = {
    # Connection / session verbs.
    "quick-connect": _svg(
        # lightning bolt
        '<path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>',
    ),
    "connection-manager": _svg(
        # grid of four squares
        '<rect x="3" y="3" width="7" height="7"/>'
        '<rect x="14" y="3" width="7" height="7"/>'
        '<rect x="3" y="14" width="7" height="7"/>'
        '<rect x="14" y="14" width="7" height="7"/>',
    ),
    "shell": _svg(
        # terminal prompt
        '<polyline points="4 17 10 11 4 5"/>'
        '<line x1="12" y1="19" x2="20" y2="19"/>',
    ),

    # Pane / layout verbs.
    "split-h": _svg(
        '<rect x="3" y="3" width="18" height="18" rx="2"/>'
        '<line x1="3" y1="12" x2="21" y2="12"/>',
    ),
    "split-v": _svg(
        '<rect x="3" y="3" width="18" height="18" rx="2"/>'
        '<line x1="12" y1="3" x2="12" y2="21"/>',
    ),
    "close-pane": _svg(
        '<rect x="3" y="3" width="18" height="18" rx="2"/>'
        '<line x1="9" y1="9" x2="15" y2="15"/>'
        '<line x1="15" y1="9" x2="9" y2="15"/>',
    ),
    "toggle-layout": _svg(
        # h/v swap arrows
        '<polyline points="17 3 21 7 17 11"/>'
        '<line x1="3" y1="7" x2="21" y2="7"/>'
        '<polyline points="7 21 3 17 7 13"/>'
        '<line x1="21" y1="17" x2="3" y2="17"/>',
    ),
    "equalize": _svg(
        # two equal bars
        '<line x1="3" y1="9" x2="21" y2="9"/>'
        '<line x1="3" y1="15" x2="21" y2="15"/>',
    ),
    "extract-pane": _svg(
        '<path d="M15 3h6v6"/>'
        '<path d="M10 14L21 3"/>'
        '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
    ),

    # File transfer verbs.
    "copy-right": _svg(
        '<rect x="9" y="9" width="13" height="13" rx="2"/>'
        '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
    ),
    "move-right": _svg(
        '<line x1="5" y1="12" x2="19" y2="12"/>'
        '<polyline points="12 5 19 12 12 19"/>',
    ),
    "refresh": _svg(
        '<polyline points="23 4 23 10 17 10"/>'
        '<polyline points="1 20 1 14 7 14"/>'
        '<path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
    ),
}


# Icon category: bookmark / sidebar icons. Users pick one per
# bookmark from the edit dialog.
_BOOKMARK_ICONS = {
    "bookmark": _svg(
        '<path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"/>',
    ),
    "star": _svg(
        '<polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 '
        '17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>',
    ),
    "heart": _svg(
        '<path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 '
        '5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 '
        '5.5 0 0 0 0-7.78z"/>',
    ),
    "flag": _svg(
        '<path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/>'
        '<line x1="4" y1="22" x2="4" y2="15"/>',
    ),
    "tag": _svg(
        '<path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 '
        '8.59a2 2 0 0 1 0 2.82z"/>'
        '<line x1="7" y1="7" x2="7.01" y2="7"/>',
    ),

    # Device classes.
    "home": _svg(
        '<path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2h-4a2 2 0 0 1-2-2v-6h-2v6a2 '
        '2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
    ),
    "computer": _svg(
        '<rect x="2" y="3" width="20" height="14" rx="2"/>'
        '<line x1="8" y1="21" x2="16" y2="21"/>'
        '<line x1="12" y1="17" x2="12" y2="21"/>',
    ),
    "laptop": _svg(
        '<rect x="3" y="4" width="18" height="12" rx="2"/>'
        '<line x1="1" y1="20" x2="23" y2="20"/>',
    ),
    "phone": _svg(
        '<rect x="7" y="2" width="10" height="20" rx="2"/>'
        '<line x1="11" y1="18" x2="13" y2="18"/>',
    ),
    "tablet": _svg(
        '<rect x="5" y="3" width="14" height="18" rx="2"/>'
        '<line x1="11" y1="18" x2="13" y2="18"/>',
    ),
    "server": _svg(
        '<rect x="2" y="4" width="20" height="6" rx="1"/>'
        '<rect x="2" y="14" width="20" height="6" rx="1"/>'
        '<line x1="6" y1="7" x2="6" y2="7"/>'
        '<line x1="6" y1="17" x2="6" y2="17"/>',
    ),
    "database": _svg(
        '<ellipse cx="12" cy="5" rx="9" ry="3"/>'
        '<path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>'
        '<path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>',
    ),
    "usb": _svg(
        '<rect x="6" y="9" width="12" height="12" rx="1"/>'
        '<line x1="12" y1="2" x2="12" y2="9"/>'
        '<polyline points="8 5 12 2 16 5"/>',
    ),

    # Network / cloud.
    "router": _svg(
        '<rect x="2" y="13" width="20" height="8" rx="2"/>'
        '<line x1="6" y1="17" x2="6.01" y2="17"/>'
        '<line x1="10" y1="17" x2="10.01" y2="17"/>'
        '<path d="M12 13V7"/>'
        '<path d="M8 7a4 4 0 0 1 8 0"/>',
    ),
    "wifi": _svg(
        '<path d="M5 12.55a11 11 0 0 1 14.08 0"/>'
        '<path d="M1.42 9a16 16 0 0 1 21.16 0"/>'
        '<path d="M8.53 16.11a6 6 0 0 1 6.95 0"/>'
        '<line x1="12" y1="20" x2="12.01" y2="20"/>',
    ),
    "cloud": _svg(
        '<path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/>',
    ),
    "globe": _svg(
        '<circle cx="12" cy="12" r="10"/>'
        '<line x1="2" y1="12" x2="22" y2="12"/>'
        '<path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 '
        '0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
    ),
    "vpn": _svg(
        '<rect x="3" y="11" width="18" height="11" rx="2"/>'
        '<path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    ),

    # Data / content.
    "folder": _svg(
        '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 '
        '3h9a2 2 0 0 1 2 2z"/>',
    ),
    "file": _svg(
        '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>'
        '<polyline points="14 2 14 8 20 8"/>',
    ),
    "code": _svg(
        '<polyline points="16 18 22 12 16 6"/>'
        '<polyline points="8 6 2 12 8 18"/>',
    ),
    "image": _svg(
        '<rect x="3" y="3" width="18" height="18" rx="2"/>'
        '<circle cx="8.5" cy="8.5" r="1.5"/>'
        '<polyline points="21 15 16 10 5 21"/>',
    ),
    "music": _svg(
        '<path d="M9 18V5l12-2v13"/>'
        '<circle cx="6" cy="18" r="3"/>'
        '<circle cx="18" cy="16" r="3"/>',
    ),
    "video": _svg(
        '<polygon points="23 7 16 12 23 17 23 7"/>'
        '<rect x="1" y="5" width="15" height="14" rx="2"/>',
    ),
    "archive": _svg(
        '<polyline points="21 8 21 21 3 21 3 8"/>'
        '<rect x="1" y="3" width="22" height="5"/>'
        '<line x1="10" y1="12" x2="14" y2="12"/>',
    ),
    "lock": _svg(
        '<rect x="3" y="11" width="18" height="11" rx="2"/>'
        '<path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    ),
    "key": _svg(
        '<path d="M21 2l-9.6 9.6a5.5 5.5 0 1 1-2-2L19 2z"/>'
        '<line x1="15" y1="6" x2="18" y2="9"/>',
    ),
    "shield": _svg(
        '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    ),

    # Tool / work categories.
    "terminal": _svg(
        '<polyline points="4 17 10 11 4 5"/>'
        '<line x1="12" y1="19" x2="20" y2="19"/>',
    ),
    "tools": _svg(
        '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 '
        '6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 '
        '7.94-7.94l-3.76 3.76z"/>',
    ),
    "briefcase": _svg(
        '<rect x="2" y="7" width="20" height="14" rx="2"/>'
        '<path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/>',
    ),
    "inbox": _svg(
        '<polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/>'
        '<path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 '
        '2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>',
    ),
    "download": _svg(
        '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>'
        '<polyline points="7 10 12 15 17 10"/>'
        '<line x1="12" y1="15" x2="12" y2="3"/>',
    ),
    "upload": _svg(
        '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>'
        '<polyline points="17 8 12 3 7 8"/>'
        '<line x1="12" y1="3" x2="12" y2="15"/>',
    ),
    "settings": _svg(
        '<circle cx="12" cy="12" r="3"/>'
        '<path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 '
        '2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 '
        '1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 '
        '1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 '
        '1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 '
        '2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 '
        '0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 '
        '1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 '
        '1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 '
        '2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 '
        '0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
    ),
    "plus": _svg(
        '<line x1="12" y1="5" x2="12" y2="19"/>'
        '<line x1="5" y1="12" x2="19" y2="12"/>',
    ),
    "edit": _svg(
        '<path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>'
        '<path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>',
    ),
    "trash": _svg(
        '<polyline points="3 6 5 6 21 6"/>'
        '<path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 '
        '2 0 0 1 2 2v2"/>',
    ),

    # Fallback for unknown names.
    "unknown": _svg(
        '<circle cx="12" cy="12" r="10"/>'
        '<path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/>'
        '<line x1="12" y1="17" x2="12.01" y2="17"/>',
    ),
}


# Final merged table — all icons share the same lookup + render path.
ICONS: dict[str, str] = {**_TOOL_ICONS, **_BOOKMARK_ICONS}


# --------------------------------------------------------------------------
# Per-icon colour palette (default: colourful). Monochrome mode forces
# every icon to ``currentColor`` so the palette adapts to the theme.
# --------------------------------------------------------------------------

# Hand-picked, semantically sorted colour table. Keeps the icons
# readable on both light AND dark themes by choosing medium-saturation
# values that contrast against #1e1e2e and #ffffff alike. Tool-verb
# icons (the toolbar) deliberately stay uncoloured (``None``) so they
# follow the theme's foreground — makes the toolbar feel like a native
# part of the menubar chrome.
_ICON_COLORS: dict[str, str | None] = {
    # Tool verbs — semantically coloured too (original V1 left them
    # as ``None`` for theme-match; user wanted colour across the
    # whole surface). Values picked to stay distinguishable without
    # being chaotic: blue for connect / copy / manage, green for
    # shell / move / refresh (go), gold for quick-connect (lightning
    # + speed), red for close, purple for layout-rearrangement
    # verbs, cyan for pane-splits, orange for toggle-layout.
    "quick-connect": "#f5a623",        # gold lightning
    "connection-manager": "#3498db",   # blue grid
    "shell": "#2ecc71",                # terminal green
    "split-h": "#00bcd4",              # cyan
    "split-v": "#00bcd4",              # cyan
    "close-pane": "#e74c3c",           # red
    "toggle-layout": "#e67e22",        # orange rotate
    "equalize": "#9b59b6",             # violet
    "extract-pane": "#9b59b6",         # violet
    "copy-right": "#3498db",           # blue
    "move-right": "#27ae60",           # green arrow
    "refresh": "#16a085",              # teal

    # Markers — warm accents.
    "bookmark": "#4a90e2",     # blue
    "star": "#f39c12",         # gold
    "heart": "#e74c3c",        # red
    "flag": "#c0392b",         # crimson
    "tag": "#16a085",          # teal

    # Devices.
    "home": "#3498db",         # blue
    "computer": "#5dade2",     # light blue
    "laptop": "#5dade2",       # light blue
    "phone": "#27ae60",        # green
    "tablet": "#27ae60",       # green
    "server": "#546e7a",       # slate
    "database": "#d35400",     # burnt orange
    "usb": "#8e44ad",          # purple

    # Network.
    "router": "#2ecc71",       # green
    "wifi": "#3498db",         # blue
    "cloud": "#85c1e9",        # sky
    "globe": "#1abc9c",        # turquoise
    "vpn": "#9b59b6",          # violet

    # Data / content.
    "folder": "#f5a623",       # amber
    "file": "#95a5a6",         # slate grey
    "code": "#6c5ce7",         # indigo
    "image": "#ec407a",        # pink
    "music": "#ff6b6b",        # coral
    "video": "#e74c3c",        # red
    "archive": "#8d6e63",      # brown

    # Security.
    "lock": "#27ae60",         # green
    "key": "#f1c40f",          # yellow
    "shield": "#2980b9",       # blue

    # Work tools.
    "terminal": "#2ecc71",     # green
    "tools": "#7f8c8d",        # grey
    "briefcase": "#795548",    # brown
    "inbox": "#3498db",        # blue
    "download": "#27ae60",     # green
    "upload": "#e67e22",       # orange
    "settings": "#7f8c8d",     # grey
    "plus": "#27ae60",         # green
    "edit": "#f39c12",         # gold
    "trash": "#e74c3c",        # red

    # Fallback placeholder.
    "unknown": "#888888",
}


# Monochrome mode — module-level so both the icon() factory and the
# cache key observe the same flag. The settings UI flips it via
# ``set_monochrome`` which also clears the cache so the next icon()
# call re-renders. Default: colourful.
_monochrome: bool = False


def set_monochrome(flag: bool) -> None:
    """Switch the icon provider between colourful (``False``, default)
    and monochrome (``True``, every icon rendered with
    ``currentColor`` to match the active theme). The render cache
    is cleared so subsequent ``icon()`` calls re-rasterise with the
    new setting."""
    global _monochrome
    new_value = bool(flag)
    if new_value == _monochrome:
        return
    _monochrome = new_value
    _render_icon.cache_clear()


def is_monochrome() -> bool:
    return _monochrome


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


@lru_cache(maxsize=512)
def _render_icon(name: str, size: int = 32) -> QIcon:
    """Render the named SVG into a QIcon. Cached by (name, size) so
    repeated toolbar / sidebar builds don't re-parse the XML.

    Colour substitution: when ``_monochrome`` is False (default), the
    stroke colour from ``_ICON_COLORS`` replaces ``currentColor`` in
    the SVG source. When monochrome OR the icon has no colour entry,
    ``currentColor`` stays and Qt renders the icon in the theme's
    foreground palette.

    The cache is NOT keyed on ``_monochrome`` explicitly — when the
    flag flips, ``set_monochrome`` calls ``cache_clear`` so the next
    ``icon()`` call re-rasterises fresh.
    """
    svg_src = ICONS.get(name) or ICONS["unknown"]
    if not _monochrome:
        colour = _ICON_COLORS.get(name)
        if colour:
            # Every SVG string uses ``stroke="currentColor"`` from
            # ``_SVG_OPEN``; substituting there swaps the palette-
            # based render to the explicit colour.
            svg_src = svg_src.replace(
                'stroke="currentColor"', f'stroke="{colour}"',
            )
    renderer = QSvgRenderer(QByteArray(svg_src.encode("utf-8")))
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    try:
        renderer.render(painter)
    finally:
        painter.end()
    return QIcon(pixmap)


def icon(name: str, size: int = 32) -> QIcon:
    """Return a QIcon for *name*. Unknown names resolve to the
    ``unknown`` placeholder so missing entries land on screen as a
    visible question mark instead of a silent blank.
    """
    return _render_icon(name, size)


def available_icons() -> list[str]:
    """All icon names in canonical display order: tool icons first
    (for toolbar consistency), then bookmark icons (for the edit
    dialog's grid picker). ``unknown`` is excluded — it's the
    internal fallback, not user-pickable."""
    out: list[str] = []
    for name in _TOOL_ICONS:
        out.append(name)
    for name in _BOOKMARK_ICONS:
        if name == "unknown":
            continue
        out.append(name)
    return out


def bookmark_icon_names() -> list[str]:
    """The subset of icons meaningful for bookmarks (devices,
    data categories, misc). Excludes toolbar-verb icons like
    ``split-h`` which wouldn't make semantic sense as a bookmark
    label."""
    return [n for n in _BOOKMARK_ICONS if n != "unknown"]


def has_icon(name: str) -> bool:
    return name in ICONS


__all__ = [
    "ICONS",
    "available_icons",
    "bookmark_icon_names",
    "has_icon",
    "icon",
    "is_monochrome",
    "set_monochrome",
]
