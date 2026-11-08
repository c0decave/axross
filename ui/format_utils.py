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


__all__ = ["backend_label", "format_size", "human_bytes", "measured_bytes"]
