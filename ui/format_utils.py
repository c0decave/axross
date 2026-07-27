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
    value = float(n)
    for unit in _UNITS:
        if abs(value) < 1024.0 or unit == _UNITS[-1]:
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} {_UNITS[-1]}"


def format_size(n: int) -> str:
    """Exact byte count, plus the human form once it adds information.

    Below 1 KB the two are the same number, so the suffix is omitted.
    """
    if abs(n) < 1024:
        return f"{n} bytes"
    return f"{n} bytes ({human_bytes(n)})"


__all__ = ["format_size", "human_bytes"]
