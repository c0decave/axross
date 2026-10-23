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
import os
import shutil
import stat as stat_module
import tempfile
import uuid
from typing import TYPE_CHECKING

from core.path_policy import hidden_sibling_name, safe_join

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
    move into a destructive overwrite. (A local cross-device rename takes
    its own non-overwriting path, see :func:`_move_across_devices`.)
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
    return safe_join(
        backend, parent, hidden_sibling_name(name, f".copy-{uuid.uuid4().hex}.tmp")
    )


def _replacement_backup_path(backend, dst: str) -> str:
    parent = backend.parent(dst)
    separator = backend.separator()
    name = dst.rsplit(separator, 1)[-1] if separator in dst else dst
    return safe_join(
        backend, parent, hidden_sibling_name(name, f".replace-{uuid.uuid4().hex}.bak")
    )


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


# Writers that buffer locally and replace the object in ONE commit at close:
# s3transfer aborts a failed multipart upload (tasks.py, abort_multipart_
# upload cleanup), Azure Blob commits its block list as the last step. A
# failed upload therefore leaves the old object untouched. Deliberately
# narrower than atomic_io._NATIVE_ATOMIC_PROTOCOLS: Azure Files writes ranges
# as it goes, IMAP "overwrites" by appending a new message.
_COMMIT_ON_CLOSE_PROTOCOLS = frozenset({"s3", "azure_blob"})


def _commits_on_close(backend) -> bool:
    from core import backend_registry

    name = type(backend).__name__
    return any(
        info.class_name == name and info.protocol_id in _COMMIT_ON_CLOSE_PROTOCOLS
        for info in backend_registry.all_backends()
    )


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
    if _commits_on_close(backend):
        # Nothing is replaced before the writer's close succeeds, so a
        # failed upload leaves the old object — no copy needed.
        return True, None
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


def source_size(backend, path: str) -> int | None:
    """The size *backend* reports for *path* now, to tell afterwards whether
    it changed while it was copied. ``None`` when it cannot tell (no stat,
    a failed one) and for a symlink, whose own size is the length of its
    target's path."""
    try:
        item = backend.stat(path)
    except Exception as exc:  # noqa: BLE001 - no size: nothing to compare later
        log.debug("cannot read the size of %s: %s", path, exc)
        return None
    if item is None or getattr(item, "is_link", False):
        return None
    try:
        return int(getattr(item, "size", 0) or 0)
    except (TypeError, ValueError):
        return None


def _file_size(backend, path: str) -> int | None:
    """The size of the regular file *path*; None for a folder, a link or
    when it cannot be read."""
    try:
        item = backend.stat(path)
    except Exception as exc:  # noqa: BLE001 - no size: nothing to compare
        log.debug("cannot read the size of %s: %s", path, exc)
        return None
    if item is None or getattr(item, "is_dir", False) or getattr(item, "is_link", False):
        return None
    try:
        return int(getattr(item, "size", 0) or 0)
    except (TypeError, ValueError):
        return None


def refuse_short_copy(path: str, size_before: int | None, written: int | None,
                      copy_path: str) -> None:
    """Raise :class:`OSError` when fewer bytes were written to *copy_path*
    than *path* had before it was copied: a move must not delete a source
    whose copy came out short. A source stream may end early without an
    error, and a destination without a comparable checksum (FTP) cannot
    object afterwards. More written than the size from before is left to
    :func:`refuse_changed_source` (the source grew), and so is a size some
    backends only report as 0."""
    if size_before is None or written is None or written >= size_before:
        return
    raise OSError(
        f"only {written} of {size_before} bytes of {path} were copied to {copy_path}; "
        "the source was kept, the copy is incomplete"
    )


def refuse_changed_source(backend, path: str, size_before: int | None, copy_path: str) -> None:
    """Raise :class:`OSError` when *path* no longer has *size_before*, the
    size it had before it was copied to *copy_path*.

    A move deletes its source after the copy; data written to the source
    meanwhile (a log line appended after the copy read the end) would then
    be in neither place. A source whose size cannot be read now counts as
    changed: a kept source costs a second copy, a wrong delete costs data.
    Without a size from before there is nothing to compare.
    """
    if size_before is None:
        return
    size_after = source_size(backend, path)
    if size_after == size_before:
        return
    now = "an unknown size" if size_after is None else f"{size_after} bytes"
    raise OSError(
        f"{path} changed while it was copied ({size_before} bytes before, {now} now); "
        f"it was not removed, the copy at {copy_path} misses the change"
    )


def _local_tree_sizes(path: str) -> dict[str, tuple[bool, int]]:
    """Every entry of the local entry *path* (itself as ``""``, a folder's
    contents below it, links not followed) as ``(is_folder, size)``; a
    folder's own size is not compared, it varies with the file system."""
    st = os.lstat(path)
    if not stat_module.S_ISDIR(st.st_mode):
        return {"": (False, st.st_size)}
    entries: dict[str, tuple[bool, int]] = {"": (True, 0)}
    for root, dirs, files in os.walk(path):
        for name in dirs + files:
            full = os.path.join(root, name)
            try:
                child = os.lstat(full)
            except FileNotFoundError:
                continue  # gone meanwhile: the other snapshot shows it
            folder = stat_module.S_ISDIR(child.st_mode)
            entries[os.path.relpath(full, path)] = (folder, 0 if folder else child.st_size)
    return entries


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


def _is_cross_device(backend, exc: BaseException) -> bool:
    """EXDEV from a backend whose paths are this machine's paths."""
    if getattr(exc, "errno", None) != errno.EXDEV:
        return False
    from core.local_fs import LocalFS

    return isinstance(backend, LocalFS)


def _move_across_devices(src: str, dst: str, rename_exc: BaseException) -> None:
    """Move a local entry to another file system: copy, then remove.

    What ``mv`` does where rename(2) answers EXDEV. A folder keeps its
    symlinks as links, a link is moved as the link. The destination must
    be free -- rename would have replaced a file, a copy is not allowed
    to. A failed copy removes what it wrote and leaves the source as it
    was; a source that cannot be removed afterwards is reported, and for
    a single file the copy is taken back so there is one, not two.
    """
    if os.path.lexists(dst):
        raise rename_exc
    is_tree = os.path.isdir(src) and not os.path.islink(src)
    # Compared after the copy: what is written to the source meanwhile
    # would otherwise be removed with it and be in neither place.
    before = _local_tree_sizes(src)
    try:
        if is_tree:
            shutil.copytree(src, dst, symlinks=True)
        elif os.path.islink(src):
            os.symlink(os.readlink(src), dst)
        else:
            shutil.copy2(src, dst, follow_symlinks=False)
        if _local_tree_sizes(src) != before:
            raise OSError(
                f"{src} changed while it was copied; it was not moved to {dst}"
            )
    except BaseException as exc:
        try:
            if is_tree and os.path.isdir(dst) and not os.path.islink(dst):
                shutil.rmtree(dst)
            elif os.path.lexists(dst):
                os.remove(dst)
        except OSError as cleanup_exc:
            log.error("move across devices: could not remove the partial copy %s: %s",
                      dst, cleanup_exc)
        if isinstance(exc, shutil.Error):
            raise OSError(f"cannot move {src} to {dst}: {exc}") from exc
        raise
    try:
        if is_tree:
            shutil.rmtree(src)
        else:
            os.remove(src)
    except OSError as exc:
        if not is_tree:
            try:
                os.remove(dst)
            except OSError:
                log.error("move across devices: %s copied to %s but neither removed", src, dst)
            raise
        # The copy is complete; part of the source may already be gone,
        # so the copy is the one to keep.
        raise OSError(
            f"moved {src} to {dst}, but the source could not be removed completely: {exc}"
        ) from exc
    log.debug("server_side_move: %s -> %s across devices (copy + remove)", src, dst)


def _leaf_name(backend, path: str) -> str:
    separator = backend.separator()
    return path.rsplit(separator, 1)[-1] if separator in path else path


def is_case_only_rename(backend, src: str, dst: str) -> bool:
    """Whether *dst* differs from *src* only in letter case, in the same folder."""
    if src == dst:
        return False
    try:
        if backend.parent(src) != backend.parent(dst):
            return False
        src_leaf, dst_leaf = _leaf_name(backend, src), _leaf_name(backend, dst)
    except Exception:  # noqa: BLE001 - not a question this backend can answer
        return False
    return src_leaf != dst_leaf and src_leaf.casefold() == dst_leaf.casefold()


def rename_target_taken(backend, src: str, dst: str) -> bool:
    """Whether renaming *src* to *dst* would hit another, existing entry.

    ``exists(dst)`` alone also answers True on a case-insensitive file
    system (APFS, NTFS, most SMB shares) when *dst* only re-cases *src*:
    it finds the source itself. For such a case-only rename the folder
    listing decides - only an entry spelled exactly like *dst* is another
    file (a case-sensitive folder holding both spellings).
    """
    if not _exists_true(backend, dst):
        return False
    if not is_case_only_rename(backend, src, dst):
        return True
    leaf = _leaf_name(backend, dst)
    try:
        listing = backend.list_dir(backend.parent(dst))
    except OSError:
        raise
    except Exception as exc:  # noqa: BLE001 - callers handle OSError
        raise OSError(f"could not list the folder of {dst}: {exc}") from exc
    return any(item.name == leaf for item in listing)


def _rename_via_temp_name(backend, src: str, dst: str) -> None:
    """Case-only rename on a case-insensitive backend, in two steps.

    Some servers accept ``rename("a", "A")`` and change nothing, so the
    name goes through a free temporary name first. When the second step
    fails, the first is undone and the error raised.
    """
    temp = safe_join(
        backend,
        backend.parent(src),
        hidden_sibling_name(_leaf_name(backend, src), f".case-{uuid.uuid4().hex[:12]}.tmp"),
    )
    if _exists_true(backend, temp):
        raise FileExistsError(f"temporary rename name already exists: {temp}")
    backend.rename(src, temp)
    try:
        backend.rename(temp, dst)
    except BaseException:
        try:
            backend.rename(temp, src)
        except Exception as undo_exc:  # noqa: BLE001 - the original error matters more
            log.error(
                "case-only rename: could not put %s back after a failure; it is at %s: %s",
                src,
                temp,
                undo_exc,
            )
        raise


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
            if rename_target_taken(backend, src, dst):
                raise FileExistsError(f"move target already exists: {dst}")
        except FileExistsError:
            raise
        except Exception as exc:
            raise OSError(f"move target existence check failed: {dst}") from exc
    if _exists_true(backend, dst) and is_case_only_rename(backend, src, dst):
        # The "existing" dst is src itself (rename_target_taken said so).
        _rename_via_temp_name(backend, src, dst)
        return
    try:
        backend.rename(src, dst)
        return
    except (OSError, NotImplementedError) as exc:
        if _is_cross_device(backend, exc):
            # Two local file systems (a USB stick and the home with the
            # trash): rename cannot cross them, a move can.
            _move_across_devices(src, dst, exc)
            return
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
    size_before = source_size(backend, src)
    server_side_copy(backend, src, dst)
    try:
        # The copy's own size: a server-side copy reports no byte count.
        # Files only - a new folder's own size says nothing about its content.
        refuse_short_copy(src, size_before, _file_size(backend, dst), dst)
        refuse_changed_source(backend, src, size_before, dst)
        backend.remove(src)
    except OSError as exc:
        log.warning(
            "server_side_move: copied %s -> %s but the source was not removed: %s "
            "-- undoing destination",
            src,
            dst,
            exc,
        )
        try:
            backend.remove(dst)
        except OSError as undo_exc:
            log.error(
                "server_side_move: undo failed after the source was not removed; "
                "duplicate data may remain at %s: %s",
                dst,
                undo_exc,
            )
        raise OSError(f"move not completed: the source {src} was not removed: {exc}") from exc
