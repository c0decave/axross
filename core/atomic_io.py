"""Backend-agnostic atomic write helper.

Writes bytes to ``path`` on ``backend`` so that concurrent readers
either observe the old content or the new content — never a partial
or mixed state. Implementation strategy depends on what the backend
supports:

* **Native-atomic backends** (S3, Azure Blob, Azure Files, Dropbox,
  GDrive, OneDrive, IMAP): a single PUT / upload is server-side
  atomic; the previous object is replaced exactly at response-commit
  time. Strategy → plain ``open_write`` + ``close``.

* **Rename-capable backends** (LocalFS, SFTP, NFS, iSCSI, SMB,
  WebDAV, FTP, FTPS, Rsync, Telnet, SCP): write to a sibling temp
  file, then atomic rename into place. Strategy →
  ``open_write(tmp)`` + ``close`` + ``rename(tmp, path)``. If the
  rename fails the temp file is removed so no garbage is left.

The decision is read from :class:`BackendCapabilities`, so new
backends get a sensible default without touching this module.
"""
from __future__ import annotations

import logging
import os
import secrets
from typing import TYPE_CHECKING

from core import backend_registry

if TYPE_CHECKING:  # pragma: no cover
    from core.backend import FileBackend

log = logging.getLogger(__name__)


# Backends whose SINGLE open_write -> close is already atomic at the
# protocol level — so temp-file-then-rename is wasteful and sometimes
# not even possible (no rename semantics).
_NATIVE_ATOMIC_PROTOCOLS = frozenset({
    "s3",
    "azure_blob",
    "azure_files",
    "dropbox",
    "gdrive",
    "onedrive",
    "sharepoint",
    "imap",
    "rsync",  # rsync itself uses temp + rename internally
})


def _is_native_atomic(backend) -> bool:
    """Ask the registry whether writes to this backend class are
    already atomic without help from us."""
    class_name = type(backend).__name__
    for info in backend_registry.all_backends():
        if info.class_name == class_name:
            return info.protocol_id in _NATIVE_ATOMIC_PROTOCOLS
    # Unknown backend: assume we need rename-safety
    return False


def _temp_sibling(backend, path: str) -> str:
    """Return a sibling temp path in the same dir as *path*, using the
    backend's own separator conventions.

    The name is deliberately generic (``.tmp-<hex>.tmp``) so server-side
    observers can't attribute it back to Axross specifically. The hex
    suffix is still long enough (``secrets.token_hex(6)`` = 12 chars)
    to uniquely identify the write, and ``atomic_recovery`` matches
    that exact 12-hex shape plus an older ``.axross-atomic-`` prefix
    for backward compatibility with pre-scrub installs.
    """
    parent = backend.parent(path) if hasattr(backend, "parent") else os.path.dirname(path)
    suffix = secrets.token_hex(6)
    name = f".tmp-{suffix}.tmp"
    if hasattr(backend, "join"):
        return backend.join(parent, name)
    return os.path.join(parent, name)


def atomic_write(backend, path: str, data: bytes) -> None:
    """Write *data* to *path* atomically.

    Raises :class:`OSError` on I/O failure. On failure the target path
    is left untouched (either its previous content or non-existent).
    """
    if _is_native_atomic(backend):
        with backend.open_write(path) as f:
            f.write(data)
        log.debug("atomic_write: native atomic path for %s", path)
        return

    tmp = _temp_sibling(backend, path)
    try:
        with backend.open_write(tmp) as f:
            f.write(data)
        backend.rename(tmp, path)
        log.debug("atomic_write: rename-based commit for %s", path)
    except BaseException:
        # Best-effort cleanup — if the write didn't complete, remove the
        # temp so we don't leak. Swallow errors from the cleanup
        # itself; the original exception is re-raised below.
        try:
            if backend.exists(tmp):
                backend.remove(tmp)
        except Exception as cleanup_exc:
            log.debug(
                "atomic_write: cleanup of %s failed: %s", tmp, cleanup_exc,
            )
        raise
