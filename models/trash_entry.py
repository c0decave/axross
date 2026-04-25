"""Record for a single entry in a backend's universal trash.

The universal trash (core/trash.py) moves files into
``<root>/.axross-trash/<uuid>`` and writes a sidecar
``<uuid>.meta.json`` describing where the entry came from.
Each sidecar is parsed into one of these.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class TrashEntry:
    """One item currently sitting in the trash."""

    trash_id: str
    original_path: str
    trashed_at: datetime = field(default_factory=datetime.now)
    size: int = 0
    is_dir: bool = False
    label: str = ""
