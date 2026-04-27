"""atomic_replace.py — safe in-place rewrite via core.atomic_io.

Uses ``core.atomic_io.atomic_write`` so the destination either holds
the OLD content or the NEW content but never a half-written
intermediate. On backends with native atomic upload (S3, Azure
Blob, Dropbox, GDrive, OneDrive, IMAP) the underlying write is
already atomic; on the rest atomic_io stages a temp sibling and
renames on commit.

Use case: rotate a config / manifest file on a remote server
without ever leaving the file in a corrupt state.

Usage::

    backend = axross.open("prod-config")
    rewrite(backend, "/etc/app/manifest.json", '{"version": 42}')
"""
from __future__ import annotations

# Direct internal-API import — bypasses the curated axross.* surface
# so this script demonstrates how core modules are used.
from core.atomic_io import atomic_write


def rewrite(backend, path: str, new_content: str | bytes,
            encoding: str = "utf-8") -> int:
    """Replace ``path`` on ``backend`` with ``new_content`` atomically.
    Returns the number of bytes written."""
    if isinstance(new_content, str):
        data = new_content.encode(encoding)
    else:
        data = new_content
    atomic_write(backend, path, data)
    return len(data)
