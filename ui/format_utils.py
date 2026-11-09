"""Shared display formatting for the UI layer.

Byte counts are rendered in two places that must agree — the properties
sheet and the disk-usage view — so the formatter lives here rather than
being copied into each. ``core.dashboard`` carries its own private
``_human_bytes`` for its text/markdown renderers; that one serves the
CLI/MCP output and is deliberately not imported across the layer
boundary.
"""

from __future__ import annotations

_UNITS = ("B", "KB", "MB", "GB", "TB", "PB")


def human_bytes(n: int) -> str:
    """Short human-readable byte count (``1536`` -> ``1.5 KB``).

    Negative input is formatted rather than rejected: a backend that
    reports nonsense should show up as nonsense in one cell, not take
    the whole dialog down.
    """
    from core.i18n import format_decimal

    value = float(n)
    for unit in _UNITS:
        if abs(value) < 1024.0 or unit == _UNITS[-1]:
            if unit == "B":
                return f"{int(value)} B"
            return f"{format_decimal(value)} {unit}"
        value /= 1024.0
    return f"{format_decimal(value)} {_UNITS[-1]}"


def format_size(n: int) -> str:
    """Exact byte count, plus the human form once it adds information.

    Below 1 KB the two are the same number, so the suffix is omitted. The
    count has the language's thousands separator and the word its plural
    ("1 byte", "1.536 Bytes (1,5 KB)" in German).
    """
    from core.i18n import DEFAULT_LANGUAGE, active, format_count, tr_n

    # English keeps the bare number ("2048 bytes"), as before.
    count = str(n) if active().language == DEFAULT_LANGUAGE else format_count(n)
    exact = tr_n(n, "{count} byte", "{count} bytes", count=count)
    if abs(n) < 1024:
        return exact
    return f"{exact} ({human_bytes(n)})"


def measured_bytes(n: int, incomplete: bool = False) -> str:
    """``human_bytes`` of a measured folder size, with "≥" when part of the
    folder could not be measured (the size is a lower bound). Shared by
    the pane's Size column and the Calculate Size table."""
    return ("≥ " if incomplete else "") + human_bytes(n)


def backend_label(name: str) -> str:
    """A backend's name for display. The local file system's name stays
    "Local" in core (bookmarks, tags and sessions key on it); the pane
    shows it in the interface language. Remote names ("user@host") are
    data and shown as they are."""
    from core.i18n import tr

    return tr("Local") if name == "Local" else name


#: The sandbox profiles axross ships (core.agent_sandbox.default_profiles)
#: and its levels: stored under these English names, shown translated.
SANDBOX_WORDS = {"lax": "Lax", "normal": "Normal", "high": "High", "paranoid": "Paranoid"}


def sandbox_label(name: str) -> str:
    """A sandbox profile's (or level's) name for display: the shipped
    "Lax", "Normal", "High" and "Paranoid" in the interface language (they
    were English in German - UX review round 7); a name the user gave
    stays as written. The stored name - the profile's id - is unchanged."""
    from core.i18n import tr

    word = SANDBOX_WORDS.get(str(name).casefold())
    return tr(word) if word is not None and str(name) in (word, word.lower()) else name


def ui_locale():
    """The QLocale of the interface language, for a widget that formats
    numbers itself (a QDoubleSpinBox showed "1.00 s" in German; UX review
    round 8). Set per widget: a default QLocale would outlive a switch."""
    from PyQt6.QtCore import QLocale

    from core import i18n

    locale = QLocale(i18n.active().language)
    locale.setNumberOptions(QLocale.NumberOption.OmitGroupSeparator)
    return locale


__all__ = ["backend_label", "format_size", "human_bytes", "measured_bytes", "sandbox_label",
           "ui_locale"]
