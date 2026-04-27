"""s3_inventory.py — content-type histogram + top-N largest objects.

Walks every key under PATH on an S3 backend (S3-compatible: AWS,
MinIO, Wasabi, Backblaze B2 with S3 compat layer) and reports::

  - total object count + total bytes
  - top-N largest objects
  - histogram of file extensions (proxy for content type)

Usage::

    sess = axross.open("audit-s3")
    report = inventory(sess, "/mybucket")
"""
from __future__ import annotations

import collections
import posixpath


def inventory(backend, root: str = "/", top_n: int = 10) -> dict:
    items: list[tuple[str, int]] = []
    ext_hist: dict[str, int] = collections.Counter()
    total_bytes = 0

    for entry, is_dir in _walk(backend, root):
        if is_dir:
            continue
        try:
            info = backend.stat(entry)
        except OSError:
            continue
        size = int(info.size or 0)
        total_bytes += size
        items.append((entry, size))
        ext = posixpath.splitext(entry)[1].lstrip(".").lower() or "(none)"
        ext_hist[ext] += 1

    items.sort(key=lambda kv: kv[1], reverse=True)
    return {
        "object_count": len(items),
        "total_bytes": total_bytes,
        "top_largest": items[:top_n],
        "extension_histogram": dict(ext_hist.most_common()),
    }


def _walk(backend, root: str):
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            kids = backend.list_dir(current)
        except OSError:
            continue
        yield current, True
        for it in kids:
            child = backend.join(current, it.name)
            if it.is_dir:
                stack.append(child)
            else:
                yield child, False
