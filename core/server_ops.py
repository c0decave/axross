"""Server-side copy / move helpers with automatic fallback.

Call these from the transfer engine or UI instead of ``backend.copy``
or ``backend.rename`` directly — they prefer the backend's native
operation when available (S3 CopyObject, WebDAV COPY, shell ``cp``,
etc.) and fall back to a read/write stream copy only when the
protocol doesn't offer a native shortcut. The resulting behaviour is
always correct; the difference is bandwidth + latency.
"""

from __future__ import annotations

import errno
import logging
import tempfile
import uuid
from typing import TYPE_CHECKING

from core.path_policy import safe_join

if TYPE_CHECKING:  # pragma: no cover
    pass

log = logging.getLogger(__name__)


_UNSUPPORTED_RENAME_MARKERS = (
    "not support",
    "not implemented",
    "unsupported",
    "no rename",
    "has no rename",
    "does not support rename",
)

_UNSUPPORTED_COPY_MARKERS = (
    "not support",
    "not implemented",
    "unsupported",
    "no copy",
    "no native copy",
    "no server-side copy",
    "has no server-side copy",
    "native copy unavailable",
    "server-side copy unavailable",
    "does not support copy",
)

_DESTINATION_EXISTS_MARKERS = (
    "already exists",
    "destination exists",
    "file exists",
    "target exists",
    "over-existing",
    "over existing",
    "overwrite existing",
    "exists:",
)


def _discard_or_close_writer(writer, *, completed: bool) -> None:
    if completed:
        writer.close()
        return
    try:
        if hasattr(writer, "discard"):
            writer.discard()
        elif hasattr(writer, "_buf"):
            writer._buf.close()
        else:
            log.warning(
                "Stream copy failed before completion, but writer %s lacks "
                "discard(); closing it may commit partial destination data.",
                type(writer).__name__,
            )
            writer.close()
    except Exception:
        log.debug("Failed to discard incomplete stream-copy output", exc_info=True)


def _known_backend_capabilities(backend):
    try:
        from core.local_fs import LocalFS

        if isinstance(backend, LocalFS) and type(backend).rename is LocalFS.rename:
            from core.backend_registry import POSIX_CAPS

            return POSIX_CAPS
    except Exception:
        pass
    try:
        from core.db_fs_base import DbFsBackend

        if isinstance(backend, DbFsBackend):
            from core.backend_registry import DBFS_CAPS

            return DBFS_CAPS
    except Exception:
        pass
    try:
        from core import backend_registry

        class_name = type(backend).__name__
        for info in backend_registry.all_backends():
            if info.class_name == class_name:
                return info.capabilities
    except Exception:
        log.debug("server_ops: capability lookup failed", exc_info=True)
    return None


def _copy_fallback_allowed(backend, exc: BaseException) -> bool:
    """Return True only when native server-side copy is unavailable."""
    if isinstance(exc, NotImplementedError):
        return True
    caps = _known_backend_capabilities(backend)
    if caps is not None and not bool(getattr(caps, "can_server_side_copy", False)):
        return True
    message = str(exc).lower()
    return any(marker in message for marker in _UNSUPPORTED_COPY_MARKERS)


def _rename_fallback_allowed(backend, exc: BaseException) -> bool:
    """Return True only when rename itself appears unavailable.

    A plain ``OSError`` can mean "target exists", "permission denied",
    "cross-device link", or "protocol has no rename". Only the last
    category should become copy+delete; otherwise we may turn a refused
    move into a destructive overwrite.
    """
    if isinstance(exc, NotImplementedError):
        return True
    caps = _known_backend_capabilities(backend)
    if caps is not None and not bool(getattr(caps, "can_rename", True)):
        return True
    message = str(exc).lower()
    return any(marker in message for marker in _UNSUPPORTED_RENAME_MARKERS)


def _supports_temp_destination(backend) -> bool:
    needed = ("parent", "join", "separator", "rename", "remove", "exists", "is_dir")
    if not all(hasattr(backend, name) for name in needed):
        return False
    try:
        from core.local_fs import LocalFS

        if isinstance(backend, LocalFS) and type(backend).rename is not LocalFS.rename:
            return False
    except Exception:
        pass
    try:
        caps = _known_backend_capabilities(backend)
        if caps is None:
            return False
        return bool(caps.can_stream_write and caps.can_rename and caps.rename_atomic)
    except Exception:
        log.debug("stream copy: capability lookup failed", exc_info=True)
        return False


def _temp_destination_path(backend, dst: str) -> str:
    parent = backend.parent(dst)
    separator = backend.separator()
    name = dst.rsplit(separator, 1)[-1] if separator in dst else dst
    return safe_join(backend, parent, f".{name}.copy-{uuid.uuid4().hex}.tmp")


def _replacement_backup_path(backend, dst: str) -> str:
    parent = backend.parent(dst)
    separator = backend.separator()
    name = dst.rsplit(separator, 1)[-1] if separator in dst else dst
    return safe_join(backend, parent, f".{name}.replace-{uuid.uuid4().hex}.bak")


def _cleanup_temp_destination(backend, temp_path: str | None) -> None:
    if not temp_path:
        return
    try:
        if backend.exists(temp_path):
            backend.remove(temp_path)
    except Exception:
        log.debug("stream copy: cleanup of temp destination failed", exc_info=True)


def _exists_true(backend, path: str) -> bool:
    """Return True only for an explicit boolean ``exists`` result."""
    if not hasattr(backend, "exists"):
        return False
    return backend.exists(path) is True


def _snapshot_direct_destination(backend, dst: str):
    """Return ``(existed, snapshot)`` before an unsafe direct write.

    Some backends cannot create a sibling temp and commit via rename.
    If their writer also writes directly, a read/write error can leave
    ``dst`` half-updated. For those paths we keep a local snapshot of an
    existing destination so error handling can restore it. The snapshot
    is intentionally only used when temp+rename is unavailable.
    """
    try:
        existed = _exists_true(backend, dst)
    except Exception as exc:
        raise OSError(
            f"Cannot safely stream to destination without probing whether it exists: {dst}"
        ) from exc
    if not existed:
        return False, None
    if not hasattr(backend, "open_read"):
        raise OSError(
            f"Cannot safely overwrite existing destination without read-back support: {dst}"
        )
    snapshot = tempfile.SpooledTemporaryFile(max_size=16 * 1024 * 1024)
    try:
        with backend.open_read(dst) as rf:
            while True:
                chunk = rf.read(1024 * 1024)
                if not chunk:
                    break
                snapshot.write(chunk)
        snapshot.seek(0)
        return True, snapshot
    except BaseException:
        snapshot.close()
        raise


def _restore_direct_destination(backend, dst: str, snapshot) -> None:
    try:
        snapshot.seek(0)
        wf = backend.open_write(dst)
        completed = False
        try:
            while True:
                chunk = snapshot.read(1024 * 1024)
                if not chunk:
                    break
                wf.write(chunk)
            completed = True
        finally:
            _discard_or_close_writer(wf, completed=completed)
    except Exception:
        log.error(
            "stream copy: failed to restore destination after write error: %s",
            dst,
            exc_info=True,
        )


def _remove_direct_partial_destination(backend, dst: str) -> None:
    if not hasattr(backend, "exists") or not hasattr(backend, "remove"):
        return
    try:
        if _exists_true(backend, dst):
            if hasattr(backend, "is_dir") and backend.is_dir(dst) is True:
                return
            backend.remove(dst)
    except Exception:
        log.warning(
            "stream copy: failed to remove partial destination: %s",
            dst,
            exc_info=True,
        )


def _rollback_direct_destination(
    backend,
    dst: str,
    *,
    destination_existed: bool,
    destination_snapshot,
) -> None:
    if destination_existed and destination_snapshot is not None:
        _restore_direct_destination(backend, dst, destination_snapshot)
        return
    if not destination_existed:
        _remove_direct_partial_destination(backend, dst)


def _is_destination_exists_error(exc: OSError) -> bool:
    if isinstance(exc, FileExistsError):
        return True
    if getattr(exc, "errno", None) in (errno.EEXIST, errno.ENOTEMPTY):
        return True
    msg = str(exc).lower()
    return any(marker in msg for marker in _DESTINATION_EXISTS_MARKERS)


def _finalize_temp_destination(backend, temp_path: str, dst: str) -> None:
    try:
        backend.rename(temp_path, dst)
    except OSError as first_rename_exc:
        if not _is_destination_exists_error(first_rename_exc):
            raise first_rename_exc
        try:
            destination_is_file = backend.exists(dst) and not backend.is_dir(dst)
        except Exception:
            raise first_rename_exc
        if not destination_is_file:
            raise first_rename_exc
        backup = _replacement_backup_path(backend, dst)
        backup_created = False
        try:
            backend.rename(dst, backup)
            backup_created = True
            backend.rename(temp_path, dst)
        except BaseException:
            if backup_created:
                try:
                    if not backend.exists(dst):
                        backend.rename(backup, dst)
                except Exception:
                    log.error(
                        "stream copy finalize rollback failed for %s from %s",
                        dst,
                        backup,
                        exc_info=True,
                    )
            raise
        try:
            if backend.exists(backup):
                backend.remove(backup)
        except Exception:
            log.warning(
                "stream copy finalize left replacement backup behind: %s",
                backup,
                exc_info=True,
            )


def stream_copy_between_backends(
    src_backend,
    src: str,
    dst_backend,
    dst: str,
    *,
    buffer_size: int = 1024 * 1024,
) -> int:
    """Copy bytes across backend instances with partial-output cleanup.

    When the destination backend supports a normal temp-file + rename
    workflow, stream into a sibling temp path and only replace the final
    destination after the source has been read completely. Backends with
    buffered upload writers still rely on ``discard()``.
    """
    target = dst
    temp_path: str | None = None
    if _supports_temp_destination(dst_backend):
        temp_path = _temp_destination_path(dst_backend, dst)
        target = temp_path
    destination_existed = False
    destination_snapshot = None
    if temp_path is None:
        destination_existed, destination_snapshot = _snapshot_direct_destination(
            dst_backend,
            dst,
        )

    transferred = 0
    try:
        with src_backend.open_read(src) as rf:
            wf = dst_backend.open_write(target)
            completed = False
            try:
                while True:
                    chunk = rf.read(buffer_size)
                    if not chunk:
                        break
                    wf.write(chunk)
                    transferred += len(chunk)
                completed = True
            finally:
                _discard_or_close_writer(wf, completed=completed)
        if temp_path is not None:
            _finalize_temp_destination(dst_backend, temp_path, dst)
        return transferred
    except BaseException:
        _cleanup_temp_destination(dst_backend, temp_path)
        if temp_path is None:
            _rollback_direct_destination(
                dst_backend,
                dst,
                destination_existed=destination_existed,
                destination_snapshot=destination_snapshot,
            )
        raise
    finally:
        if destination_snapshot is not None:
            destination_snapshot.close()


def copy_via_stream(backend, src: str, dst: str) -> None:
    """Fallback copy: read src, write dst. O(bytes) client roundtrip.

    Used when the backend has no native copy. Does NOT do integrity
    verification here — that is the transfer engine's job.
    """
    stream_copy_between_backends(backend, src, backend, dst)


def server_side_copy(
    backend,
    src: str,
    dst: str,
    *,
    overwrite: bool = True,
) -> None:
    """Copy src to dst on the same backend. Prefers the backend's
    native ``copy()``; falls back to stream copy when the native
    method raises or isn't present.

    We try-then-catch instead of consulting BackendCapabilities
    because test doubles / overlay backends subclass LocalFS etc.
    and the capability registry only knows the canonical class
    names. Try-then-catch is correct for both real and test
    backends.

    When ``overwrite`` is false, an existing destination is refused.
    When ``overwrite`` is true and a non-temp native copy refuses an
    existing destination, the helper falls back to the guarded stream
    path so buffered/direct-writer rollback semantics are still used.

    Raises :class:`OSError` only when the selected copy strategy fails.
    """
    if not overwrite and hasattr(backend, "exists"):
        try:
            if _exists_true(backend, dst):
                raise FileExistsError(f"copy target already exists: {dst}")
        except FileExistsError:
            raise
        except Exception as exc:
            raise OSError(f"copy target existence check failed: {dst}") from exc
    if hasattr(backend, "copy"):
        target = dst
        temp_path: str | None = None
        if _supports_temp_destination(backend):
            temp_path = _temp_destination_path(backend, dst)
            target = temp_path
        try:
            backend.copy(src, target)
            if temp_path is not None:
                if not overwrite and _exists_true(backend, dst):
                    raise FileExistsError(
                        f"copy target already exists: {dst}",
                    )
                _finalize_temp_destination(backend, temp_path, dst)
            log.debug("server_side_copy: native path used for %s -> %s", src, dst)
            return
        except (OSError, NotImplementedError) as exc:
            _cleanup_temp_destination(backend, temp_path)
            overwrite_collision = False
            if overwrite and temp_path is None and isinstance(exc, OSError):
                try:
                    overwrite_collision = (
                        _is_destination_exists_error(exc)
                        and hasattr(backend, "exists")
                        and _exists_true(backend, dst)
                    )
                except Exception:
                    overwrite_collision = False
            if not overwrite_collision and not _copy_fallback_allowed(backend, exc):
                log.debug(
                    "server_side_copy: native copy failed (%s); not falling "
                    "back because this does not look like unsupported copy",
                    exc,
                )
                raise
            log.debug(
                "server_side_copy: backend.copy raised (%s); falling back to stream copy",
                exc,
            )
    copy_via_stream(backend, src, dst)


def server_side_move(
    backend,
    src: str,
    dst: str,
    *,
    overwrite: bool = False,
) -> None:
    """Move src to dst on the same backend. Prefers rename() (which is
    already the backend's move primitive for all backends that
    implement it). Falls back to copy-then-delete only when rename is
    unavailable for this backend/protocol. Operational rename failures
    like destination collisions or permissions are propagated as-is.

    By default this refuses an existing destination even on POSIX-like
    backends whose native rename would overwrite, because higher-level
    UI/MCP/scripting operations treat rename as "move to a free name".
    """
    if not overwrite and hasattr(backend, "exists"):
        try:
            if _exists_true(backend, dst):
                raise FileExistsError(f"move target already exists: {dst}")
        except FileExistsError:
            raise
        except Exception as exc:
            raise OSError(f"move target existence check failed: {dst}") from exc
    try:
        backend.rename(src, dst)
        return
    except (OSError, NotImplementedError) as exc:
        if not _rename_fallback_allowed(backend, exc):
            log.debug(
                "server_side_move: rename failed (%s); not falling back "
                "because this does not look like unsupported rename",
                exc,
            )
            raise
        log.debug(
            "server_side_move: rename raised (%s); falling back to copy + delete",
            exc,
        )
    # Fallback: copy then delete source. If remove fails, the caller
    # would otherwise have both src and dst, so undo the copy before
    # surfacing the failure.
    if _exists_true(backend, dst):
        raise OSError(f"move target already exists: {dst}")
    server_side_copy(backend, src, dst)
    try:
        backend.remove(src)
    except OSError as exc:
        log.warning(
            "server_side_move: copied %s -> %s but remove(src) failed: %s -- undoing destination",
            src,
            dst,
            exc,
        )
        try:
            backend.remove(dst)
        except OSError as undo_exc:
            log.error(
                "server_side_move: undo failed after source remove failure; "
                "duplicate data may remain at %s: %s",
                dst,
                undo_exc,
            )
        raise OSError(
            f"move partially completed: copy succeeded but remove of source {src} failed: {exc}"
        ) from exc
