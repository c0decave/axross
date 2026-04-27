"""sqlite_export.py — pack a directory tree into a single SQLite file.

Walks PATH on BACKEND and writes every entry into a new SQLite-FS
session. The result is a single ``.sqlite`` file that contains the
whole tree — easy to ship, version, encrypt as one blob, mount via
the SqliteFsSession backend later.

Usage::

    src = axross.open("source-server")
    pack(src, "/var/log/2024", "/tmp/logs-2024.sqlite")
"""
from __future__ import annotations


def pack(src, src_root: str, dst_sqlite_path: str) -> dict:
    dst = axross.open_url(f"sqlite:///{dst_sqlite_path}")
    n_files = n_dirs = 0
    for entry, is_dir in _walk(src, src_root):
        rel = entry[len(src_root):].lstrip("/")
        if not rel:
            continue
        target = "/" + rel
        if is_dir:
            dst.mkdir(target)
            n_dirs += 1
        else:
            try:
                data = axross.read_bytes(src, entry)
            except OSError:
                continue
            axross.write_bytes(dst, target, data)
            n_files += 1
    dst.close()
    return {"files": n_files, "dirs": n_dirs, "out": dst_sqlite_path}


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
