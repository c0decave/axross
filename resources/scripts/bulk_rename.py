"""bulk_rename.py — regex-based rename across a directory.

Walk PATH on BACKEND and rename every file whose basename matches
the regex PATTERN to the same path with the basename rewritten via
``re.sub(PATTERN, REPLACEMENT, basename)``.

Use ``dry_run=True`` to preview without touching anything (default).
"""
from __future__ import annotations

import posixpath
import re


def bulk_rename(backend, root: str, pattern: str, replacement: str,
                dry_run: bool = True) -> list[tuple[str, str]]:
    rx = re.compile(pattern)
    renames: list[tuple[str, str]] = []
    for entry, is_dir in _walk(backend, root):
        if is_dir:
            continue
        base = posixpath.basename(entry)
        new_base = rx.sub(replacement, base)
        if new_base == base:
            continue
        new_path = backend.join(posixpath.dirname(entry), new_base)
        renames.append((entry, new_path))
        if not dry_run:
            backend.rename(entry, new_path)
    return renames


def _walk(backend, root: str):
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            items = backend.list_dir(current)
        except OSError:
            continue
        yield current, True
        for it in items:
            child = backend.join(current, it.name)
            if it.is_dir:
                stack.append(child)
            else:
                yield child, False
