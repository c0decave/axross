"""gopher_archive.py — recursively download a Gopher hole.

Walks every directory of a gopher:// URL and writes every fetched
text/binary item to a local mirror dir. Bounded by MAX_DEPTH (the
Gopher backend itself caps at 32 — we cap lower so a friendly
script doesn't accidentally hammer a small server).

Usage::

    archive("gopher://gopher.floodgap.com/", "/tmp/floodgap")
"""
from __future__ import annotations

import os

MAX_DEPTH = 8
MAX_FILES = 500


def archive(gopher_url: str, dst_dir: str) -> dict:
    src = axross.open_url(gopher_url)
    local = axross.localfs()
    fetched = skipped = 0

    def _walk(path: str, depth: int) -> None:
        nonlocal fetched, skipped
        if depth > MAX_DEPTH or fetched >= MAX_FILES:
            skipped += 1
            return
        try:
            items = src.list_dir(path)
        except OSError:
            skipped += 1
            return
        os.makedirs(local.join(dst_dir, path.lstrip("/")), exist_ok=True)
        for it in items:
            child = src.join(path, it.name)
            if it.is_dir:
                _walk(child, depth + 1)
            elif fetched < MAX_FILES:
                try:
                    data = axross.read_bytes(src, child)
                except OSError:
                    skipped += 1
                    continue
                target = local.join(dst_dir, child.lstrip("/"))
                os.makedirs(os.path.dirname(target), exist_ok=True)
                axross.write_bytes(local, target, data)
                fetched += 1

    _walk("/", 0)
    src.close()
    return {"fetched": fetched, "skipped": skipped}
