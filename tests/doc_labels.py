"""A UI label as a handbook names it: the German handbook (USAGE_de.md)
names the label the German window shows (resources/i18n/de.json), the
others the English one. Markdown emphasis around the label stays."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@lru_cache(maxsize=1)
def _german() -> dict:
    return json.loads((ROOT / "resources/i18n/de.json").read_text(encoding="utf-8"))


def on_screen(guide: str, label: str) -> str:
    """*label* (maybe in ``*…*`` / ``**…**``) as *guide* should write it."""
    if not str(guide).endswith("_de.md"):
        return label
    bare = label.strip("*")
    return label.replace(bare, _german().get(bare, bare).replace("&", ""))


__all__ = ["on_screen"]
