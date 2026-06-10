"""bulk_rename.py — regex-based rename across a directory.

Walk PATH on BACKEND and rename every file whose basename matches
the regex PATTERN to the same path with the basename rewritten via
``re.sub(PATTERN, REPLACEMENT, basename)``.

Use ``dry_run=True`` to preview without touching anything (default).
"""

from __future__ import annotations

import posixpath
import re

MAX_REGEX_CHARS = 512
MAX_WALK_ENTRIES = 100_000
_DANGEROUS_REGEX_RE = re.compile(
    r"\((?:[^()\\]|\\.){0,256}[+*](?:[^()\\]|\\.){0,256}\)"
    r"\s*(?:[+*]|\{\d*,?\d*\})"
)


def bulk_rename(
    backend,
    root: str,
    pattern: str,
    replacement: str,
    dry_run: bool = True,
    *,
    max_entries: int = MAX_WALK_ENTRIES,
) -> list[tuple[str, str]]:
    rx = _compile_safe_regex(pattern)
    renames: list[tuple[str, str]] = []
    planned_targets: set[str] = set()
    for entry, is_dir in _walk(backend, root, max_entries=max_entries):
        if is_dir:
            continue
        base = posixpath.basename(entry)
        new_base = rx.sub(replacement, base)
        if new_base == base:
            continue
        new_path = backend.join(posixpath.dirname(entry), new_base)
        if new_path in planned_targets:
            raise ValueError(f"bulk rename target collision: {new_path}")
        planned_targets.add(new_path)
        renames.append((entry, new_path))
    if not dry_run:
        for _entry, new_path in renames:
            if backend.exists(new_path):
                raise FileExistsError(f"bulk rename target already exists: {new_path}")
        for entry, new_path in renames:
            backend.rename(entry, new_path)
    return renames


def _compile_safe_regex(pattern: str):
    if not isinstance(pattern, str):
        raise TypeError("pattern must be a string")
    if len(pattern) > MAX_REGEX_CHARS:
        raise ValueError(f"regex is too long; limit is {MAX_REGEX_CHARS} chars")
    if _DANGEROUS_REGEX_RE.search(pattern):
        raise ValueError("regex rejected: nested quantified groups are unsafe")
    return re.compile(pattern)


def _walk(backend, root: str, *, max_entries: int):
    if max_entries < 1:
        raise ValueError("max_entries must be >= 1")
    stack = [root]
    seen: set[str] = set()
    yielded = 0
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        yielded += 1
        if yielded > max_entries:
            raise RuntimeError(f"walk exceeded max_entries={max_entries}")
        try:
            items = backend.list_dir(current)
        except OSError:
            continue
        yield current, True
        for it in items:
            child = backend.join(current, it.name)
            yielded += 1
            if yielded > max_entries:
                raise RuntimeError(f"walk exceeded max_entries={max_entries}")
            if it.is_dir:
                stack.append(child)
            else:
                yield child, False
