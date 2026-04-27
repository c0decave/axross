"""fingerprint_diff.py — sha256-diff two backend trees.

Walks both trees, computes / fetches sha256 for each file, and
returns ``{added, removed, changed, unchanged}`` lists of paths.
Useful for verifying a migration finished correctly.

Usage::

    src = axross.open("source-vault")
    dst = axross.open("target-vault")
    diff = compare(src, "/", dst, "/")
    print(f"added={len(diff['added'])} changed={len(diff['changed'])}")
"""
from __future__ import annotations


def _hashes(backend, root: str) -> dict[str, str]:
    out: dict[str, str] = {}

    def _walk(current: str) -> None:
        try:
            items = backend.list_dir(current)
        except OSError:
            return
        for it in items:
            child = backend.join(current, it.name)
            rel = child[len(root):].lstrip("/")
            if it.is_dir:
                _walk(child)
            else:
                try:
                    out[rel] = axross.checksum(backend, child)
                except OSError:
                    out[rel] = "(error)"

    _walk(root)
    return out


def compare(src, src_root: str, dst, dst_root: str) -> dict[str, list[str]]:
    src_h = _hashes(src, src_root)
    dst_h = _hashes(dst, dst_root)
    added = sorted(p for p in dst_h if p not in src_h)
    removed = sorted(p for p in src_h if p not in dst_h)
    changed = sorted(p for p in src_h if p in dst_h and src_h[p] != dst_h[p])
    unchanged = sorted(p for p in src_h if p in dst_h and src_h[p] == dst_h[p])
    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "unchanged": unchanged,
    }
