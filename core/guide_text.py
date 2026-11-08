"""The text side of the in-app guides: reading a guide file, its headings
and GitHub's anchors for them.

Help > Scripting Guide (ui.scripting_guide) and Help > Handbook
(ui.handbook) show Markdown files of docs/; both need the same answers -
which headings a file has outside fenced code, what a heading looks like
rendered, and which ``#anchor`` GitHub gives it (the guides link to their
own sections that way). Plain Python, no Qt: core.handbook maps help
topics to sections with it, and tests read the files without a window.
"""

from __future__ import annotations

import os
import re
import unicodedata

#: Largest guide file read (the real ones are 10 KB to 150 KB).
MAX_GUIDE_BYTES = 1024 * 1024

FENCE = re.compile(r"^\s*(```|~~~)")
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")


def read_guide(path: str) -> str | None:
    """The text of the guide at *path*, or None: missing, not a file,
    larger than :data:`MAX_GUIDE_BYTES`, unreadable or not UTF-8."""
    try:
        if not os.path.isfile(path) or os.path.getsize(path) > MAX_GUIDE_BYTES:
            return None
        with open(path, encoding="utf-8") as fh:
            text = fh.read(MAX_GUIDE_BYTES + 1)
    except (OSError, UnicodeDecodeError):
        return None
    return text if len(text) <= MAX_GUIDE_BYTES else None


def plain_heading(heading: str) -> str:
    """A heading as the rendered document shows it: without the backticks."""
    return heading.replace("`", "").strip()


def github_slug(heading: str) -> str:
    """GitHub's anchor for a Markdown heading: lower case, punctuation
    dropped (letters, digits, "-", "_" and spaces stay), spaces to "-"."""
    text = heading.strip().lower()
    out = []
    for ch in text:
        if ch in " -_" or unicodedata.category(ch)[0] in "LN":
            out.append(ch)
    return "".join(out).replace(" ", "-")


def headings(markdown: str) -> list[tuple[int, str]]:
    """``(level, text)`` of every ATX heading outside fenced code."""
    out: list[tuple[int, str]] = []
    in_fence = False
    for line in markdown.splitlines():
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        match = HEADING.match(line)
        if match:
            out.append((len(match.group(1)), match.group(2)))
    return out


__all__ = [
    "FENCE",
    "HEADING",
    "MAX_GUIDE_BYTES",
    "github_slug",
    "headings",
    "plain_heading",
    "read_guide",
]
