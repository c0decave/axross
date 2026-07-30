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
  file, then finalize it into place. Strategy →
  ``open_write(tmp)`` + ``close`` + rollback-safe finalization. If
  the backend cannot overwrite via ``rename`` directly, the existing
  destination is backed up, the temp is moved into place, and the
  backup is restored on commit failure.

The decision is read from :class:`BackendCapabilities`, so new
backends get a sensible default without touching this module.
"""

from __future__ import annotations

import logging
import os
import secrets
from typing import TYPE_CHECKING

from core import backend_registry
from core.path_policy import safe_join

if TYPE_CHECKING:  # pragma: no cover
    pass

log = logging.getLogger(__name__)


# Backends whose SINGLE open_write -> close is already atomic at the
# protocol level — so temp-file-then-rename is wasteful and sometimes
# not even possible (no rename semantics).
_NATIVE_ATOMIC_PROTOCOLS = frozenset(
    {
        "s3",
        "azure_blob",
        "azure_files",
        "dropbox",
        "gdrive",
        "onedrive",
        "sharepoint",
        "imap",
        "rsync",  # rsync itself uses temp + rename internally
    }
)


def _is_native_atomic(backend) -> bool:
    """Ask the registry whether writes to this backend class are
    already atomic without help from us."""
    try:
        from core.db_fs_base import DbFsBackend

        if isinstance(backend, DbFsBackend):
            return True
    except Exception:
        pass
    class_name = type(backend).__name__
    for info in backend_registry.all_backends():
        if info.class_name == class_name:
            return info.protocol_id in _NATIVE_ATOMIC_PROTOCOLS
    # Unknown backend: assume we need rename-safety
    return False


def _finish_journal(op_id: str, operation: str, **fields) -> None:
    if not op_id:
        return
    try:
        from core.operation_journal import finish_operation

        finish_operation(op_id, operation, **fields)
    except Exception as exc:  # noqa: BLE001
        log.debug("%s: journal finish failed: %s", operation, exc)


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
        return safe_join(backend, parent, name)
    return os.path.join(parent, name)


def _existing_mode(backend, path: str) -> int | None:
    """The target's permission bits, or ``None``.

    ``None`` covers both "the file is new" (it should get the default
    mode, not an inherited one) and "this backend does not report a
    mode" — S3, IMAP and the cloud stores have no such concept, and
    inventing one would be worse than leaving it alone.
    """
    try:
        info = backend.stat(path)
    except OSError:
        return None
    mode = getattr(info, "permissions", 0)
    return int(mode) & 0o7777 if mode else None


def _restore_mode(backend, path: str, mode: int) -> None:
    """Best effort: a backend without chmod must not fail the save."""
    try:
        backend.chmod(path, mode)
    except (OSError, AttributeError, NotImplementedError) as exc:
        log.debug("atomic_write: could not restore mode %04o on %s: %s", mode, path, exc)


def atomic_write(backend, path: str, data: bytes) -> None:
    """Write *data* to *path* atomically.

    Raises :class:`OSError` on I/O failure. On failure the target path
    is left untouched (either its previous content or non-existent).
    """
    op_id = ""
    try:
        from core.operation_journal import start_operation

        op_id = start_operation(
            "atomic_write",
            dest=path,
            backend=getattr(backend, "name", type(backend).__name__),
            bytes_total=len(data),
        )
    except Exception as exc:  # noqa: BLE001
        log.debug("atomic_write: journal start failed: %s", exc)
    if _is_native_atomic(backend):
        try:
            with backend.open_write(path) as f:
                f.write(data)
            log.debug("atomic_write: native atomic path for %s", path)
            _finish_journal(
                op_id,
                "atomic_write",
                status="done",
                dest=path,
                bytes_total=len(data),
                bytes_done=len(data),
            )
        except BaseException as exc:
            _finish_journal(
                op_id,
                "atomic_write",
                status="error",
                dest=path,
                bytes_total=len(data),
                error=str(exc),
            )
            raise
        return

    tmp = _temp_sibling(backend, path)
    # The commit below renames a FRESH file over the target, so the
    # target's mode does not survive on its own — the replacement
    # carries whatever the umask gave the temp file. For an executable
    # that is not cosmetic: saving ~/.xinitrc at 0755 handed it back as
    # 0644 and the next X session would not start.
    previous_mode = _existing_mode(backend, path)
    try:
        with backend.open_write(tmp) as f:
            f.write(data)
        if previous_mode is not None:
            _restore_mode(backend, tmp, previous_mode)
        from core.server_ops import _finalize_temp_destination

        _finalize_temp_destination(backend, tmp, path)
        log.debug("atomic_write: rename-based commit for %s", path)
        _finish_journal(
            op_id,
            "atomic_write",
            status="done",
            dest=path,
            bytes_total=len(data),
            bytes_done=len(data),
            details={"temp": tmp},
        )
    except BaseException:
        # Best-effort cleanup — if the write didn't complete, remove the
        # temp so we don't leak. Swallow errors from the cleanup
        # itself; the original exception is re-raised below.
        try:
            if backend.exists(tmp):
                backend.remove(tmp)
        except Exception as cleanup_exc:
            log.debug(
                "atomic_write: cleanup of %s failed: %s",
                tmp,
                cleanup_exc,
            )
        _finish_journal(
            op_id,
            "atomic_write",
            status="error",
            dest=path,
            bytes_total=len(data),
            error="write failed",
            details={"temp": tmp},
        )
        raise


def atomic_write_stream(
    backend,
    path: str,
    reader,
    *,
    chunk_size: int = 1024 * 1024,
    on_chunk=None,
) -> int:
    """Atomically stream bytes from ``reader`` into ``path``.

    ``reader`` must expose ``read(size)``. Returns bytes written. The
    optional ``on_chunk(bytes_done)`` callback is invoked after each
    successful chunk write.
    """
    bytes_done = 0
    if _is_native_atomic(backend):
        with backend.open_write(path) as f:
            while True:
                chunk = reader.read(chunk_size)
                if not chunk:
                    break
                f.write(chunk)
                bytes_done += len(chunk)
                if on_chunk:
                    on_chunk(bytes_done)
        return bytes_done

    tmp = _temp_sibling(backend, path)
    try:
        with backend.open_write(tmp) as f:
            while True:
                chunk = reader.read(chunk_size)
                if not chunk:
                    break
                f.write(chunk)
                bytes_done += len(chunk)
                if on_chunk:
                    on_chunk(bytes_done)
        from core.server_ops import _finalize_temp_destination

        _finalize_temp_destination(backend, tmp, path)
        return bytes_done
    except BaseException:
        try:
            if backend.exists(tmp):
                backend.remove(tmp)
        except Exception as cleanup_exc:
            log.debug(
                "atomic_write_stream: cleanup of %s failed: %s",
                tmp,
                cleanup_exc,
            )
        raise
