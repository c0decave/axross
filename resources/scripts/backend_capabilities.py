"""backend_capabilities.py — emit a capability matrix across every
registered backend.

Reads the ``BackendCapabilities`` declared in
:mod:`core.backend_registry` and renders a tab-separated matrix —
useful for "does this protocol support server-side copy?" without
opening the source. Rows are protocol IDs; columns are capability
flags.

Usage::

    print(matrix())
    write_csv("/tmp/axross-capabilities.csv")
"""
from __future__ import annotations

import csv
import io
from dataclasses import fields

from core import backend_registry as _br


def _columns() -> list[str]:
    """Capability flag names, in declaration order."""
    return [f.name for f in fields(_br.BackendCapabilities)]


def matrix() -> str:
    """Render every registered backend × capability as a tab-separated
    table that fits on a terminal."""
    # The registry is populated lazily by GUI / MCP entry points;
    # ensure it's loaded for headless / --script invocations.
    if not _br.all_backends():
        _br.init_registry()
    cols = _columns()
    out = io.StringIO()
    out.write("protocol\t" + "\t".join(cols) + "\n")
    for info in _br.all_backends():
        cells = [info.protocol_id]
        caps = info.capabilities
        for name in cols:
            value = getattr(caps, name, None)
            cells.append(
                "x" if value is True else
                ("." if value is False else str(value))
            )
        out.write("\t".join(cells) + "\n")
    return out.getvalue()


def write_csv(path: str) -> int:
    """Same matrix, but as a real CSV — easier to import into a
    spreadsheet for review meetings."""
    if not _br.all_backends():
        _br.init_registry()
    cols = _columns()
    rows = []
    for info in _br.all_backends():
        row = {"protocol": info.protocol_id, "available": info.available}
        for name in cols:
            row[name] = getattr(info.capabilities, name, None)
        rows.append(row)
    buf = io.StringIO()
    fieldnames = ["protocol", "available", *cols]
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    axross.write_text(axross.localfs(), path, buf.getvalue())
    return len(rows)
