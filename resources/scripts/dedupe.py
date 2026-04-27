"""dedupe.py — find duplicate files by content hash.

Walks PATH on BACKEND, hashes every file (small files only — caps at
8 MiB per file so a million-file scan stays bounded), and returns
``{sha256: [path, path, ...]}`` for every group with at least 2
members.

Usage::

    dups = find_duplicates(axross.localfs(), "/srv/share")
    for digest, paths in sorted(dups.items()):
        print(digest, paths)
"""
from __future__ import annotations

import hashlib

MAX_BYTES_PER_FILE = 8 * 1024 * 1024


def find_duplicates(backend, root: str) -> dict[str, list[str]]:
    by_hash: dict[str, list[str]] = {}
    for entry, is_dir in _walk(backend, root):
        if is_dir:
            continue
        try:
            with backend.open_read(entry) as fh:
                data = fh.read(MAX_BYTES_PER_FILE)
        except OSError:
            continue
        digest = hashlib.sha256(data).hexdigest()
        by_hash.setdefault(digest, []).append(entry)
    return {h: paths for h, paths in by_hash.items() if len(paths) > 1}


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
