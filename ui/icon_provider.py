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

import re
from functools import lru_cache

from PyQt6.QtCore import QByteArray, Qt
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
    # File analysis: with / without an LLM.
    "bot": _svg(
        '<rect x="4" y="8" width="16" height="12" rx="2"/>'
        '<path d="M12 8V5"/><circle cx="12" cy="3.5" r="1.5"/>'
        '<path d="M9 13v2M15 13v2M2 14h2M20 14h2"/>',
    ),
    "bot-off": _svg(
        '<rect x="4" y="8" width="16" height="12" rx="2"/>'
        '<path d="M12 8V5"/><circle cx="12" cy="3.5" r="1.5"/>'
        '<path d="M9 13v2M15 13v2M2 14h2M20 14h2"/>'
        '<path d="M3 3l18 18"/>',
    ),
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
        '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>',
    ),
    # Pane / layout verbs.
    # The divider drawn in each glyph must match the layout its action
    # produces, NOT the name's axis. "Split Horizontal" hands
    # Qt.Orientation.Horizontal to _split_pane, and a horizontal
    # QSplitter lays its children out left-to-right — so the resulting
    # panes sit SIDE BY SIDE and the seam between them is VERTICAL.
    # These two bodies were swapped, so both toolbar buttons showed the
    # opposite of what they do.
    "split-h": _svg(
        # side-by-side panes -> vertical seam
        '<rect x="3" y="3" width="18" height="18" rx="2"/><line x1="12" y1="3" x2="12" y2="21"/>',
    ),
    "split-v": _svg(
        # stacked panes -> horizontal seam
        '<rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="12" x2="21" y2="12"/>',
    ),
    "close-pane": _svg(
        '<rect x="3" y="3" width="18" height="18" rx="2"/>'
        '<line x1="9" y1="9" x2="15" y2="15"/>'
        '<line x1="15" y1="9" x2="9" y2="15"/>',
    ),
    # "close every panel in this dock area" — the single-close glyph
    # with a second panel stacked behind it, so the two buttons read as
    # one-vs-many at a glance instead of relying on the tooltip.
    "close-all-panes": _svg(
        '<path d="M3 16V5a2 2 0 0 1 2-2h11"/>'
        '<rect x="7" y="7" width="14" height="14" rx="2"/>'
        '<line x1="11" y1="11" x2="17" y2="17"/>'
        '<line x1="17" y1="11" x2="11" y2="17"/>',
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
        '<line x1="3" y1="9" x2="21" y2="9"/><line x1="3" y1="15" x2="21" y2="15"/>',
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
        '<line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>',
    ),
    "x": _svg(
        '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
    ),
    # Window corner, left of the [x]: maximize (corners out), restore (corners in).
    "window-maximize": _svg(
        '<path d="M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3'
        'm0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3"/>',
    ),
    "window-restore": _svg(
        '<path d="M8 3v3a2 2 0 0 1-2 2H3m18 0h-3a2 2 0 0 1-2-2V3'
        'm0 18v-3a2 2 0 0 1 2-2h3M3 16h3a2 2 0 0 1 2 2v3"/>',
    ),
    # Pause / resume an extension panel's updates.
    "pause": _svg(
        '<rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>',
    ),
    "play": _svg('<polygon points="6 4 20 12 6 20 6 4"/>'),
    "refresh": _svg(
        '<polyline points="23 4 23 10 17 10"/>'
        '<polyline points="1 20 1 14 7 14"/>'
        '<path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
    ),
    # Duplicate Finder: two identical documents, the second one marked "=".
    "duplicates": _svg(
        '<rect x="3" y="3" width="11" height="14" rx="1.5"/>'
        '<rect x="10" y="7" width="11" height="14" rx="1.5"/>'
        '<line x1="13" y1="12" x2="18" y2="12"/><line x1="13" y1="16" x2="18" y2="16"/>',
    ),
    # Four tiles, one with a mountain: the thumbnail view.
    "thumbnails": _svg(
        '<rect x="3" y="3" width="8" height="8" rx="1.5"/>'
        '<rect x="13" y="3" width="8" height="8" rx="1.5"/>'
        '<rect x="3" y="13" width="8" height="8" rx="1.5"/>'
        '<rect x="13" y="13" width="8" height="8" rx="1.5"/>'
        '<polyline points="4.5 9.5 6.5 7 9.5 9.5"/>',
    ),
    # A picture frame with a play triangle: the media viewer.
    "media-view": _svg(
        '<rect x="2" y="4" width="20" height="16" rx="2"/>'
        '<polygon points="10 8.5 15.5 12 10 15.5 10 8.5"/>',
    ),
    # A magnifier over list lines: search the offline index.
    "find-index": _svg(
        '<line x1="3" y1="5" x2="13" y2="5"/><line x1="3" y1="9" x2="9" y2="9"/>'
        '<line x1="3" y1="13" x2="7" y2="13"/>'
        '<circle cx="15" cy="14" r="4"/><line x1="18" y1="17" x2="21" y2="20"/>',
    ),
    # Two columns with arrows between them: compare panes.
    "compare": _svg(
        '<rect x="2" y="3" width="7" height="18" rx="1.5"/>'
        '<rect x="15" y="3" width="7" height="18" rx="1.5"/>'
        '<polyline points="11 9 13 7 11 5"/><line x1="10" y1="7" x2="13" y2="7"/>'
        '<polyline points="13 19 11 17 13 15"/><line x1="11" y1="17" x2="14" y2="17"/>',
    ),
    # A pie chart: disk usage.
    "disk-usage": _svg(
        '<path d="M21.2 15.9A10 10 0 1 1 8 2.8"/><path d="M22 12A10 10 0 0 0 12 2v10z"/>',
    ),
    # An "i" in a circle: show metadata.
    "metadata": _svg(
        '<circle cx="12" cy="12" r="10"/>'
        '<line x1="12" y1="16" x2="12" y2="11"/><line x1="12" y1="7.5" x2="12" y2="7.5"/>',
    ),
    # A box with an arrow into it: pack.
    "pack": _svg(
        '<path d="M21 8v12a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V8"/>'
        '<rect x="2" y="4" width="20" height="4" rx="1"/>'
        '<polyline points="9 13 12 16 15 13"/><line x1="12" y1="10" x2="12" y2="16"/>',
    ),
    # The tools of the toolbar's last group.
    # A speech bubble with a spark: the Agent dock.
    "agent": _svg(
        '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>'
        '<path d="M12 6.5v6M9 9.5h6"/>',
    ),
    # A magnifier over bars: the Analysis dock (sift).
    "analysis": _svg(
        '<circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16" y2="16"/>'
        '<path d="M8.5 13.5v-2M11 13.5V8.5M13.5 13.5v-3.5"/>',
    ),
    # A page with a magnifier: Find Files.
    "find-files": _svg(
        '<path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h5"/><polyline points="13 2 13 8 19 8"/>'
        '<path d="M19 8v2"/><circle cx="16" cy="16" r="3"/><line x1="18.2" y1="18.2" x2="21" y2="21"/>',
    ),
    # A page with a play mark: the Scripts dock.
    "scripts": _svg(
        '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>'
        '<polyline points="14 2 14 8 20 8"/><polygon points="10 11 15 14 10 17 10 11"/>',
    ),
    # A window with a ">>" prompt: the Python console, axross's scripting
    # engine (the terminal beside it is ">_" without a frame).
    "console": _svg(
        '<rect x="2" y="4" width="20" height="16" rx="2"/>'
        '<polyline points="6 9 9 12 6 15"/><polyline points="11 9 14 12 11 15"/>'
        '<line x1="16" y1="15" x2="18" y2="15"/>',
    ),
    # Equalizer sliders: the Media Player.
    "media-player": _svg(
        '<path d="M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3"/>'
        '<path d="M1 14h6M9 8h6M17 16h6"/>',
    ),
    # Tiles of different sizes: the Folder Treemap.
    "treemap": _svg(
        '<rect x="3" y="3" width="18" height="18" rx="2"/>'
        '<path d="M12 3v18M3 12h9M12 15h9M16.5 15v6"/>',
    ),
    # A drive: the Drives Overview.
    "drives": _svg(
        '<line x1="22" y1="12" x2="2" y2="12"/>'
        '<path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89'
        'A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>'
        '<line x1="6" y1="16" x2="6.01" y2="16"/><line x1="10" y1="16" x2="10.01" y2="16"/>',
    ),
    # Three tiles and a check: Help > Features (installed or not).
    "features": _svg(
        '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/>'
        '<rect x="3" y="14" width="7" height="7" rx="1"/><polyline points="14 17.5 16.5 20 21 15"/>',
    ),
    # A puzzle piece: extensions.
    "extensions": _svg(
        '<path d="M4 7h4a2 2 0 1 1 4 0h4v4a2 2 0 1 1 0 4v4h-4a2 2 0 1 0-4 0H4v-4a2 2 0 1 0 0-4z"/>',
    ),
    # The toolbar's overflow button (more buttons than fit).
    "chevrons-right": _svg('<polyline points="13 17 18 12 13 7"/><polyline points="6 17 11 12 6 7"/>'),
    # Buttons that once were emoji (no emoji font on a plain Linux install).
    "pin": _svg('<line x1="12" y1="17" x2="12" y2="22"/>'
                '<path d="M5 17h14v-1.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1v4.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24z"/>'),
    "mic": _svg('<path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"/>'
                '<path d="M19 10v2a7 7 0 0 1-14 0v-2"/><line x1="12" y1="19" x2="12" y2="23"/>'
                '<line x1="8" y1="23" x2="16" y2="23"/>'),
    "speaker": _svg('<polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/>'
                    '<path d="M19.07 4.93a10 10 0 0 1 0 14.14M15.54 8.46a5 5 0 0 1 0 7.07"/>'),
}

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
        "5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 "
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
        '<rect x="3" y="4" width="18" height="12" rx="2"/><line x1="1" y1="20" x2="23" y2="20"/>',
    ),
    "phone": _svg(
        '<rect x="7" y="2" width="10" height="20" rx="2"/><line x1="11" y1="18" x2="13" y2="18"/>',
    ),
    "tablet": _svg(
        '<rect x="5" y="3" width="14" height="18" rx="2"/><line x1="11" y1="18" x2="13" y2="18"/>',
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
        '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    ),
    # Data / content.
    "folder": _svg(
        '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>',
    ),
    "file": _svg(
        '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>'
        '<polyline points="14 2 14 8 20 8"/>',
    ),
    "code": _svg(
        '<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>',
    ),
    "image": _svg(
        '<rect x="3" y="3" width="18" height="18" rx="2"/>'
        '<circle cx="8.5" cy="8.5" r="1.5"/>'
        '<polyline points="21 15 16 10 5 21"/>',
    ),
    "music": _svg(
        '<path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/>',
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
        '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    ),
    "key": _svg(
        '<path d="M21 2l-9.6 9.6a5.5 5.5 0 1 1-2-2L19 2z"/><line x1="15" y1="6" x2="18" y2="9"/>',
    ),
    "shield": _svg(
        '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    ),
    # Tool / work categories.
    "terminal": _svg(
        '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>',
    ),
    "tools": _svg(
        '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 '
        "6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 "
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
        "2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 "
        "1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 "
        "1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 "
        "1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 "
        "2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 "
        "0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 "
        "1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 "
        "1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 "
        "2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 "
        '0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
    ),
    "plus": _svg(
        '<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>',
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
# Emoji-style icons, hand-drawn in the same line style as the rest so they
# follow tints and per-bookmark colours. (Real emoji characters are
# deliberately NOT used: they render differently on every platform and
# ignore the theme.)
_EMOJI_ICONS = {
    "smile": _svg(
        '<circle cx="12" cy="12" r="10"/>'
        '<path d="M8 14s1.5 2 4 2 4-2 4-2"/>'
        '<line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/>',
    ),
    "sad": _svg(
        '<circle cx="12" cy="12" r="10"/>'
        '<path d="M16 16s-1.5-2-4-2-4 2-4 2"/>'
        '<line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/>',
    ),
    "sun": _svg(
        '<circle cx="12" cy="12" r="5"/>'
        '<line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/>'
        '<line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/>'
        '<line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>'
        '<line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/>'
        '<line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/>'
        '<line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>',
    ),
    "moon": _svg('<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>'),
    "coffee": _svg(
        '<path d="M18 8h1a4 4 0 0 1 0 8h-1"/>'
        '<path d="M2 8h16v9a4 4 0 0 1-4 4H6a4 4 0 0 1-4-4V8z"/>'
        '<line x1="6" y1="1" x2="6" y2="4"/><line x1="10" y1="1" x2="10" y2="4"/>'
        '<line x1="14" y1="1" x2="14" y2="4"/>',
    ),
    "gift": _svg(
        '<polyline points="20 12 20 22 4 22 4 12"/><rect x="2" y="7" width="20" height="5"/>'
        '<line x1="12" y1="22" x2="12" y2="7"/>'
        '<path d="M12 7H7.5a2.5 2.5 0 0 1 0-5C11 2 12 7 12 7z"/>'
        '<path d="M12 7h4.5a2.5 2.5 0 0 0 0-5C13 2 12 7 12 7z"/>',
    ),
    "award": _svg(
        '<circle cx="12" cy="8" r="7"/>'
        '<polyline points="8.21 13.89 7 23 12 20 17 23 15.79 13.88"/>',
    ),
    "anchor": _svg(
        '<circle cx="12" cy="5" r="3"/><line x1="12" y1="22" x2="12" y2="8"/>'
        '<path d="M5 12H2a10 10 0 0 0 20 0h-3"/>',
    ),
    "bell": _svg(
        '<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>'
        '<path d="M13.73 21a2 2 0 0 1-3.46 0"/>',
    ),
    "camera": _svg(
        '<path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3'
        'h4a2 2 0 0 1 2 2z"/>'
        '<circle cx="12" cy="13" r="4"/>',
    ),
    "book": _svg(
        '<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/>'
        '<path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>',
    ),
    "headphones": _svg(
        '<path d="M3 18v-6a9 9 0 0 1 18 0v6"/>'
        '<path d="M21 19a2 2 0 0 1-2 2h-1a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2h3z"/>'
        '<path d="M3 19a2 2 0 0 0 2 2h1a2 2 0 0 0 2-2v-3a2 2 0 0 0-2-2H3z"/>',
    ),
    "gamepad": _svg(
        '<rect x="2" y="6" width="20" height="12" rx="3"/>'
        '<line x1="6" y1="12" x2="10" y2="12"/><line x1="8" y1="10" x2="8" y2="14"/>'
        '<line x1="15" y1="13" x2="15.01" y2="13"/><line x1="18" y1="11" x2="18.01" y2="11"/>',
    ),
    "umbrella": _svg(
        '<path d="M23 12a11.05 11.05 0 0 0-22 0z"/><path d="M18 19a3 3 0 0 1-6 0v-7"/>',
    ),
    "droplet": _svg('<path d="M12 2.69l5.66 5.66a8 8 0 1 1-11.31 0z"/>'),
    "leaf": _svg(
        '<path d="M11 20A7 7 0 0 1 9.8 6.1C15.5 5 17 4.48 19 2c1 2 2 4.18 2 8 '
        '0 5.5-4.78 10-10 10z"/>'
        '<path d="M2 21c0-3 1.85-5.36 5.08-6C9.5 14.52 12 13 13 12"/>',
    ),
    "flame": _svg(
        '<path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 '
        "2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3"
        'a2.5 2.5 0 0 0 2.5 2.5z"/>',
    ),
    "rocket": _svg(
        '<path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91'
        'a2.18 2.18 0 0 0-2.91-.09z"/>'
        '<path d="M12 15l-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 '
        '7.5-6 11a22.35 22.35 0 0 1-4 2z"/>'
        '<path d="M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0"/>'
        '<path d="M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5"/>',
    ),
    "bug": _svg(
        '<path d="M8 2l1.88 1.88"/><path d="M14.12 3.88L16 2"/>'
        '<path d="M9 7.13v-1a3.003 3.003 0 1 1 6 0v1"/>'
        '<path d="M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6"/>'
        '<path d="M12 20v-9"/><path d="M6.53 9C4.6 8.8 3 7.1 3 5"/><path d="M6 13H2"/>'
        '<path d="M3 21c0-2.1 1.7-3.9 3.8-4"/><path d="M20.97 5c0 2.1-1.6 3.8-3.5 4"/>'
        '<path d="M22 13h-4"/><path d="M17.2 17c2.1.1 3.8 1.9 3.8 4"/>',
    ),
    "skull": _svg(
        '<circle cx="9" cy="12" r="1"/><circle cx="15" cy="12" r="1"/>'
        '<path d="M8 20v2h8v-2"/><path d="M12.5 17l-.5-1-.5 1h1z"/>'
        '<path d="M16 20a2 2 0 0 0 1.56-3.25 8 8 0 1 0-11.12 0A2 2 0 0 0 8 20"/>',
    ),
    "ghost": _svg(
        '<path d="M12 2a8 8 0 0 0-8 8v12l3-3 2.5 2.5L12 19l2.5 2.5L17 19l3 3V10a8 8 0 0 0-8-8z"/>'
        '<line x1="9" y1="10" x2="9.01" y2="10"/><line x1="15" y1="10" x2="15.01" y2="10"/>',
    ),
    "paw": _svg(
        '<circle cx="5" cy="11" r="2"/><circle cx="9" cy="6" r="2"/>'
        '<circle cx="15" cy="6" r="2"/><circle cx="19" cy="11" r="2"/>'
        '<path d="M12 12c-3 0-6 3-6 6 0 2 2 3 4 2.5 1.2-.3 2.8-.3 4 0 2 .5 4-.5 '
        '4-2.5 0-3-3-6-6-6z"/>',
    ),
    "gem": _svg(
        '<path d="M6 3h12l4 6-10 13L2 9z"/><path d="M11 3L8 9l4 13 4-13-3-6"/>'
        '<line x1="2" y1="9" x2="22" y2="9"/>',
    ),
    "crown": _svg('<path d="M3 19l-1-12 5 5 5-8 5 8 5-5-1 12z"/>'),
    "trophy": _svg(
        '<path d="M6 9H4.5a2.5 2.5 0 0 1 0-5H6"/><path d="M18 9h1.5a2.5 2.5 0 0 0 0-5H18"/>'
        '<line x1="4" y1="22" x2="20" y2="22"/>'
        '<path d="M10 14.66V17c0 .55-.47.98-.97 1.21C7.85 18.75 7 20.24 7 22"/>'
        '<path d="M14 14.66V17c0 .55.47.98.97 1.21C16.15 18.75 17 20.24 17 22"/>'
        '<path d="M18 2H6v7a6 6 0 0 0 12 0V2z"/>',
    ),
    "target": _svg(
        '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/>'
        '<circle cx="12" cy="12" r="2"/>',
    ),
    "compass": _svg(
        '<circle cx="12" cy="12" r="10"/>'
        '<polygon points="16.24 7.76 14.12 14.12 7.76 16.24 9.88 9.88 16.24 7.76"/>',
    ),
    "map-pin": _svg(
        '<path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/>',
    ),
}

# Terminal-style glyphs for the tinted (Hacker / Amber) themes: the
# folder carries a prompt, the file a few "digital rain" dots. They are
# not user-pickable, so they stay out of ``available_icons``.
_THEME_ICONS = {
    "folder-matrix": _svg(
        '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>'
        '<polyline points="7 11 10 14 7 17"/><line x1="12" y1="17" x2="17" y2="17"/>',
    ),
    "file-matrix": _svg(
        '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>'
        '<polyline points="14 2 14 8 20 8"/>'
        '<line x1="8" y1="12" x2="16" y2="12" stroke-dasharray="0.1 3.4"/>'
        '<line x1="8" y1="16" x2="16" y2="16" stroke-dasharray="0.1 3.4"/>'
        '<line x1="8" y1="20" x2="12" y2="20" stroke-dasharray="0.1 3.4"/>',
    ),
}

ICONS: dict[str, str] = {**_TOOL_ICONS, **_BOOKMARK_ICONS, **_EMOJI_ICONS, **_THEME_ICONS}


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
    "chevrons-right": "#95a5a6",
    "pin": "#e67e22",
    "mic": "#e74c3c",
    "speaker": "#3498db",
    # Tool verbs — semantically coloured too (original V1 left them
    # as ``None`` for theme-match; user wanted colour across the
    # whole surface). Values picked to stay distinguishable without
    # being chaotic: blue for connect / copy / manage, green for
    # shell / move / refresh (go), gold for quick-connect (lightning
    # + speed), red for close, purple for layout-rearrangement
    # verbs, cyan for pane-splits, orange for toggle-layout.
    "quick-connect": "#f5a623",  # gold lightning
    "connection-manager": "#3498db",  # blue grid
    "shell": "#2ecc71",  # terminal green
    "split-h": "#00bcd4",  # cyan
    "split-v": "#00bcd4",  # cyan
    "close-pane": "#e74c3c",  # red
    "close-all-panes": "#e74c3c",  # red — same verb, wider scope
    "toggle-layout": "#e67e22",  # orange rotate
    "equalize": "#9b59b6",  # violet
    "extract-pane": "#9b59b6",  # violet
    "copy-right": "#3498db",  # blue
    "move-right": "#27ae60",  # green arrow
    "refresh": "#16a085",  # teal
    "duplicates": "#5dade2",  # light blue; had none and drew black on dark themes
    "thumbnails": "#ec407a",  # pink, like a photo
    "media-view": "#e67e22",  # orange play
    "find-index": "#4a90e2",  # blue search
    "compare": "#6c5ce7",  # indigo, between the layout violets and the copy blue
    "disk-usage": "#f1c40f",  # yellow pie
    "pause": "#e67e22",  # orange: held
    "play": "#27ae60",  # green: running again
    "metadata": "#1abc9c",  # turquoise info
    "pack": "#d35400",  # burnt orange box
    "extensions": "#8e44ad",  # purple puzzle
    # The tool group; each reads on dark (#1e1e2e, >= 3:1) and light themes
    # (tests/test_toolbar_tool_buttons.py measures it).
    "agent": "#00b894",  # mint speech bubble
    "analysis": "#0984e3",  # blue magnifier
    "find-files": "#2e86de",  # blue, beside the index search
    "scripts": "#8c7ae6",  # lavender
    "console": "#f0932b",  # orange, beside the lavender scripts
    "media-player": "#ff6b6b",  # coral, like the music icon
    "treemap": "#e1b12c",  # mustard tiles
    "drives": "#4b9ce2",  # sky blue
    "features": "#00a8a8",  # teal
    "x": "#95a5a6",  # neutral grey close cross
    "window-maximize": "#95a5a6",  # same grey as the [x] beside it
    "window-restore": "#95a5a6",
    # Markers — warm accents.
    "bookmark": "#4a90e2",  # blue
    "star": "#f39c12",  # gold
    "heart": "#e74c3c",  # red
    "flag": "#c0392b",  # crimson
    "tag": "#16a085",  # teal
    # Devices.
    "home": "#3498db",  # blue
    "computer": "#5dade2",  # light blue
    "laptop": "#5dade2",  # light blue
    "phone": "#27ae60",  # green
    "tablet": "#27ae60",  # green
    "server": "#546e7a",  # slate
    "database": "#d35400",  # burnt orange
    "usb": "#8e44ad",  # purple
    # Network.
    "router": "#2ecc71",  # green
    "wifi": "#3498db",  # blue
    "cloud": "#85c1e9",  # sky
    "globe": "#1abc9c",  # turquoise
    "vpn": "#9b59b6",  # violet
    # Data / content.
    "folder": "#f5a623",  # amber
    "file": "#95a5a6",  # slate grey
    "code": "#6c5ce7",  # indigo
    "image": "#ec407a",  # pink
    "music": "#ff6b6b",  # coral
    "video": "#e74c3c",  # red
    "archive": "#8d6e63",  # brown
    # Security.
    "lock": "#27ae60",  # green
    "key": "#f1c40f",  # yellow
    "shield": "#2980b9",  # blue
    # Work tools.
    "terminal": "#2ecc71",  # green
    "tools": "#7f8c8d",  # grey
    "briefcase": "#795548",  # brown
    "inbox": "#3498db",  # blue
    "download": "#27ae60",  # green
    "upload": "#e67e22",  # orange
    "settings": "#7f8c8d",  # grey
    "plus": "#27ae60",  # green
    "edit": "#f39c12",  # gold
    "trash": "#e74c3c",  # red
    # Emoji set.
    "smile": "#f1c40f",
    "sad": "#5dade2",
    "sun": "#f39c12",
    "moon": "#9fa8da",
    "coffee": "#a1887f",
    "gift": "#ec407a",
    "award": "#f1c40f",
    "anchor": "#2980b9",
    "bell": "#f39c12",
    "camera": "#7f8c8d",
    "book": "#8d6e63",
    "headphones": "#9b59b6",
    "gamepad": "#6c5ce7",
    "umbrella": "#3498db",
    "droplet": "#3498db",
    "leaf": "#2ecc71",
    "flame": "#e67e22",
    "rocket": "#e74c3c",
    "bug": "#27ae60",
    "skull": "#bdc3c7",
    "ghost": "#bdc3c7",
    "paw": "#d35400",
    "gem": "#1abc9c",
    "crown": "#f1c40f",
    "trophy": "#f39c12",
    "target": "#e74c3c",
    "compass": "#16a085",
    "map-pin": "#e74c3c",
    # Fallback placeholder.
    "unknown": "#888888",
}


# Colours offered for per-bookmark / per-group tinting (name, #rrggbb).
BOOKMARK_COLORS: tuple[tuple[str, str], ...] = (
    ("Red", "#e74c3c"),
    ("Orange", "#e67e22"),
    ("Yellow", "#f1c40f"),
    ("Green", "#2ecc71"),
    ("Teal", "#1abc9c"),
    ("Cyan", "#00bcd4"),
    ("Blue", "#3498db"),
    ("Indigo", "#6c5ce7"),
    ("Purple", "#9b59b6"),
    ("Pink", "#ec407a"),
    ("Brown", "#8d6e63"),
    ("Grey", "#95a5a6"),
)

_HEX_COLOR = re.compile(r"#[0-9a-fA-F]{6}")


def _valid_color(value: object) -> str | None:
    """``#rrggbb`` (lower-cased) or ``None``. The value is spliced into
    SVG source, so anything else is dropped."""
    if isinstance(value, str) and _HEX_COLOR.fullmatch(value):
        return value.lower()
    return None


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


# Theme tint — a single colour that overrides every other colour choice
# (per-name palette AND monochrome). The Hacker and Amber themes set it
# so toolbar, sidebar, dock and file-list icons all read as one colour.
# In monochrome mode on a themed palette the window sets it to the
# palette's text colour, because ``currentColor`` renders black in a
# pixmap (QSvgRenderer has no widget palette to resolve it against).
_tint: str | None = None


def set_tint(colour: str | None) -> None:
    """Colour every icon with *colour* (``None`` restores the default).
    Clears the render cache when the value changes."""
    global _tint
    if colour == _tint:
        return
    _tint = colour or None
    _render_icon.cache_clear()


def get_tint() -> str | None:
    return _tint


def entry_icon(is_dir: bool, size: int = 32) -> QIcon:
    """Icon for a file-list row: our own folder / file glyph (never the
    desktop's system icon, which ignores the theme). Under a tint the
    terminal-style variant is used."""
    base = "folder" if is_dir else "file"
    return _render_icon(f"{base}-matrix" if _tint else base, size)


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


@lru_cache(maxsize=512)
def _render_icon(name: str, size: int = 32, color: str | None = None) -> QIcon:
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
    if color:
        # An explicit per-bookmark colour beats the theme tint: telling
        # entries apart is the point of choosing one.
        svg_src = svg_src.replace('stroke="currentColor"', f'stroke="{color}"')
    elif _tint:
        svg_src = svg_src.replace('stroke="currentColor"', f'stroke="{_tint}"')
    elif not _monochrome:
        colour = _ICON_COLORS.get(name)
        if colour:
            # Every SVG string uses ``stroke="currentColor"`` from
            # ``_SVG_OPEN``; substituting there swaps the palette-
            # based render to the explicit colour.
            svg_src = svg_src.replace(
                'stroke="currentColor"',
                f'stroke="{colour}"',
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


def icon(name: str, size: int = 32, color: str | None = None) -> QIcon:
    """Return a QIcon for *name*. Unknown names resolve to the
    ``unknown`` placeholder so missing entries land on screen as a
    visible question mark instead of a silent blank. *color* is an
    optional ``#rrggbb`` override; invalid values are ignored.
    """
    return _render_icon(name, size, _valid_color(color))


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
    out.extend(_EMOJI_ICONS)
    return out


def bookmark_icon_names() -> list[str]:
    """The subset of icons meaningful for bookmarks (devices,
    data categories, misc). Excludes toolbar-verb icons like
    ``split-h`` which wouldn't make semantic sense as a bookmark
    label."""
    return [n for n in _BOOKMARK_ICONS if n != "unknown"] + list(_EMOJI_ICONS)


def has_icon(name: str) -> bool:
    return name in ICONS


__all__ = [
    "BOOKMARK_COLORS",
    "ICONS",
    "available_icons",
    "bookmark_icon_names",
    "entry_icon",
    "get_tint",
    "has_icon",
    "icon",
    "is_monochrome",
    "set_monochrome",
    "set_tint",
]
