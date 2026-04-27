"""du.py — disk-usage tree across any backend, sorted by size.

Walks PATH on BACKEND and aggregates byte counts per subdirectory.
Returns ``[(path, total_bytes), ...]`` sorted descending — drop-in
analogue of ``du -sh`` but works against S3, WebDAV, SFTP, anything.

Usage::

    sizes = du(axross.localfs(), "/var/log")
    for path, total in sizes[:10]:
        print(f"{total:>12d}  {path}")
"""
from __future__ import annotations


def du(backend, root: str) -> list[tuple[str, int]]:
    sizes: dict[str, int] = {}

    def _accumulate(current: str, total: int) -> int:
        try:
            items = backend.list_dir(current)
        except OSError:
            return 0
        own = 0
        for it in items:
            child = backend.join(current, it.name)
            if it.is_dir:
                own += _accumulate(child, 0)
            else:
                own += int(it.size or 0)
        sizes[current] = own
        return own

    _accumulate(root, 0)
    return sorted(sizes.items(), key=lambda kv: kv[1], reverse=True)
