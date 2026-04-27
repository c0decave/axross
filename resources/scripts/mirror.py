"""mirror.py — incremental mirror between two backends.

Walks SRC_PATH on the source backend and copies anything missing or
changed (sha256 mismatch) to DST_PATH on the destination backend.
Skips files whose hashes already match — so re-running a mirror is
cheap.

Usage from the REPL or via ``axross --script``::

    src = axross.open("backup-source")
    dst = axross.open("backup-target")
    main(src, "/var/log", dst, "/mirror/var/log")

Or invoke from CLI::

    axross --script resources/scripts/mirror.py
    # then in the script's __main__ block edit the SRC_/DST_ vars.
"""
from __future__ import annotations


def main(src_backend, src_root: str, dst_backend, dst_root: str,
         skip_unchanged: bool = True) -> dict:
    """Recursive mirror. Returns ``{copied, skipped, deleted}`` counts.
    Does not delete on the destination by default — pass
    ``mirror_delete=True`` (separate function) when you want a strict
    one-way sync."""
    copied = skipped = 0
    for src_path, is_dir in _walk(src_backend, src_root):
        rel = src_path[len(src_root):].lstrip("/")
        # Use the dst backend's own join so OS path conventions stay right.
        dst_path = dst_backend.join(dst_root, rel) if rel else dst_root
        if is_dir:
            if not dst_backend.exists(dst_path):
                dst_backend.mkdir(dst_path)
            continue
        if skip_unchanged and dst_backend.exists(dst_path):
            try:
                if axross.checksum(src_backend, src_path) == axross.checksum(dst_backend, dst_path):
                    skipped += 1
                    continue
            except OSError:
                # Either backend can't checksum — fall through to copy.
                pass
        axross.copy(src_backend, src_path, dst_backend, dst_path)
        copied += 1
    return {"copied": copied, "skipped": skipped, "deleted": 0}


def _walk(backend, root: str):
    """Yield (path, is_dir) pairs for every entry under ``root``."""
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
