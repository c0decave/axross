"""Persisted column-header preferences for the file pane.

Stores width per column index and the set of hidden columns in a
small JSON file at ``~/.config/axross/column_prefs.json``. One file
shared across panes — the file table layout is identical everywhere
so per-pane persistence would be ceremony for no benefit.

API kept tiny: load() reads the file (or returns a fresh defaults
struct on any error), save(prefs) writes it atomically. Callers
adjust the dataclass fields and call save when something changes.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path

log = logging.getLogger("ui.column_prefs")

DEFAULT_PATH = Path.home() / ".config" / "axross" / "column_prefs.json"


# In-process lock around load+modify+save. Multiple FilePane instances
# in the same app could otherwise race on read-modify-write and lose
# one's edits. Per-PATH locks (we may have multiple instances
# pointing at different test files in tests) are kept in a small map.
_PATH_LOCKS: dict[str, threading.Lock] = {}
_PATH_LOCKS_GUARD = threading.Lock()


def _lock_for(path: Path) -> threading.Lock:
    """Return the lock that serialises load+save against *path*.
    One lock per unique on-disk file, created on first use."""
    key = str(path)
    with _PATH_LOCKS_GUARD:
        lock = _PATH_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _PATH_LOCKS[key] = lock
    return lock


@dataclass
class ColumnPrefs:
    """Persisted layout for the file-pane header.

    ``widths`` maps column index → pixel width. Missing entries fall
    back to the default the pane sets when the column is first shown.
    ``hidden`` is the set of column indices the user has hidden.
    """
    widths: dict[int, int] = field(default_factory=dict)
    hidden: set[int] = field(default_factory=set)


def load(path: Path | None = None) -> ColumnPrefs:
    """Read prefs from disk. Any failure returns a fresh default
    struct rather than raising — bad UI prefs should never block the
    pane from rendering."""
    p = path or DEFAULT_PATH
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        log.debug("column_prefs.load(%s) → defaults (%s)", p, exc)
        return ColumnPrefs()
    if not isinstance(raw, dict):
        return ColumnPrefs()
    # JSON keys are always strings; coerce back to int and drop any
    # entry that doesn't survive coercion.
    widths_raw = raw.get("widths", {})
    widths: dict[int, int] = {}
    if isinstance(widths_raw, dict):
        for k, v in widths_raw.items():
            try:
                widths[int(k)] = int(v)
            except (TypeError, ValueError):
                continue
    hidden_raw = raw.get("hidden", [])
    hidden: set[int] = set()
    if isinstance(hidden_raw, list):
        for h in hidden_raw:
            try:
                hidden.add(int(h))
            except (TypeError, ValueError):
                continue
    return ColumnPrefs(widths=widths, hidden=hidden)


def save(prefs: ColumnPrefs, path: Path | None = None) -> None:
    """Write prefs to disk. Atomic via temp+rename so a crashed
    write can't leave half a JSON file behind."""
    p = path or DEFAULT_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "widths": {str(k): int(v) for k, v in prefs.widths.items()},
        "hidden": sorted(int(h) for h in prefs.hidden),
    }
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    # ``os.replace`` overwrites atomically on every supported platform.
    # Path.replace differs subtly on Windows (older Python versions
    # fail when the destination exists), so we use os.replace for
    # portability — same byte sequence wraps the same syscall.
    os.replace(str(tmp), str(p))


def update(mutator, path: Path | None = None) -> ColumnPrefs:
    """Atomic read-modify-write: load → call mutator(prefs) → save.

    Holds the per-path lock for the entire cycle so two concurrent
    callers can't lose each other's edits. *mutator* must mutate
    ``prefs`` in place (return value ignored). Returns the prefs
    object that was finally written so the caller can update its
    cached copy."""
    p = path or DEFAULT_PATH
    with _lock_for(p):
        prefs = load(p)
        mutator(prefs)
        save(prefs, p)
        return prefs


__all__ = ["ColumnPrefs", "DEFAULT_PATH", "load", "save", "update"]
