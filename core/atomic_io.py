"""Backend-agnostic atomic write helper.

Writes bytes to ``path`` on ``backend`` so that concurrent readers
either observe the old content or the new content — never a partial
or mixed state. Implementation strategy depends on what the backend
supports:

* **Native-atomic backends** (S3, Azure Blob, Dropbox, GDrive,
  OneDrive, IMAP): a single PUT / upload is server-side atomic; the
  previous object is replaced exactly at response-commit time.
  Strategy → plain ``open_write`` + ``close``. Azure Files is NOT one:
  its upload resets the file (Create File) and then writes ranges.

* **Rename-capable backends** (LocalFS, SFTP, NFS, iSCSI, SMB,
  WebDAV, FTP, FTPS, Rsync, Telnet, SCP): write to a sibling temp
  file, then finalize it into place. Strategy →
  ``open_write(tmp)`` + ``close`` + rollback-safe finalization. If
  the backend cannot overwrite via ``rename`` directly, the existing
  destination is backed up, the temp is moved into place, and the
  backup is restored on commit failure.

* **Backends without rename** (TFTP): there is no temp-file route, so
  the write goes straight to the target - not atomic, because the
  protocol offers nothing that is. Read from the registry's
  ``can_rename``, so a new backend gets this without touching this
  module.

Unknown backend classes take the temp-file route.

A LOCAL file is written in place instead when a rename would lose
something the user did not ask to lose (vim's ``backupcopy=auto`` rule):
other hard links (they would keep the old text), a folder the user may
not create files in (the save would fail although the file is
writable), another owner, or extended attributes / a group the new file
cannot be given. In place keeps the old bytes recoverable - a backup
copy beside the file when the folder is writable, otherwise in memory -
and writes them back when the save fails part-way. It is not atomic
against a crash; that is the price of keeping the file's identity.
``atomic_write_stream`` (transfers, restores) keeps the rename route.
"""

from __future__ import annotations

import errno
import logging
import os
import secrets
import stat as stat_module
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
        # Not "azure_files": ShareFileClient.upload_file sends Create File
        # (the existing file reset to the new length, zero-filled) before
        # uploading ranges, so a failure part-way destroys the old file.
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


def _cannot_rename(backend) -> bool:
    """Whether the registry says this backend class has no rename (TFTP):
    there is no temp-file route, a single open_write is all the protocol
    offers - the transfer engine writes such backends directly too."""
    class_name = type(backend).__name__
    for info in backend_registry.all_backends():
        if info.class_name == class_name:
            return not info.capabilities.can_rename
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


#: Symlinks followed before a save gives up with ELOOP (Linux MAXSYMLINKS).
MAX_LINK_HOPS = 40


def _link_destination(backend, link: str, target: str) -> str:
    """The path a symlink at *link* with content *target* names. Not
    normalised: ``..`` must be resolved after the links, by the backend."""
    sep = backend.separator() if hasattr(backend, "separator") else "/"
    if target.startswith(sep) or (sep == os.sep and os.path.isabs(target)):
        return target
    parent = backend.parent(link) if hasattr(backend, "parent") else os.path.dirname(link)
    if hasattr(backend, "join"):
        return backend.join(parent, target)
    return os.path.join(parent, target)


def _resolve_destination(backend, path: str) -> tuple[str, int | None] | None:
    """The file a save to *path* replaces, and its permission bits.

    The temp-file route renames a fresh file over the destination. Over
    a symlink that replaced the LINK with a regular file, left the real
    target untouched and gave the new file the link's lstat mode (0777),
    so a symlink is followed to the file it names first.

    The mode is ``None`` both for "the file is new" (it should get the
    default mode, not an inherited one) and for "this backend does not
    report a mode" — S3, IMAP and the cloud stores have no such concept,
    and inventing one would be worse than leaving it alone.

    Returns ``None`` for a link the backend reports but cannot read; the
    caller writes through it then instead of replacing it. A chain longer
    than :data:`MAX_LINK_HOPS` (a loop) raises ``ELOOP``.
    """
    current = path
    for _hop in range(MAX_LINK_HOPS + 1):
        try:
            info = backend.stat(current)
        except OSError:
            return current, None
        # ``is not True``: FileItem.is_link is a bool; anything else
        # (a stand-in object) is no link to follow.
        if getattr(info, "is_link", False) is not True:
            mode = getattr(info, "permissions", 0)
            return current, (int(mode) & 0o7777 if mode else None)
        try:
            target = backend.readlink(current)
        except (OSError, AttributeError, NotImplementedError) as exc:
            log.debug("atomic_write: cannot read the link %s: %s", current, exc)
            return None
        if not target:
            return None
        current = _link_destination(backend, current, target)
    raise OSError(errno.ELOOP, os.strerror(errno.ELOOP), path)


def _restore_mode(backend, path: str, mode: int) -> None:
    """Best effort: a backend without chmod must not fail the save."""
    try:
        backend.chmod(path, mode)
    except (OSError, AttributeError, NotImplementedError) as exc:
        log.debug("atomic_write: could not restore mode %04o on %s: %s", mode, path, exc)


def _precreate_with_mode(backend, tmp: str, mode: int) -> None:
    """Create *tmp* empty and give it *mode* BEFORE any data lands.

    Chmod-after-write leaves a window in which a 0600 secret sits in a
    umask-mode (typically 0644) temp file next to its target. Truncating
    re-open keeps the mode the file already has.
    """
    with backend.open_write(tmp):
        pass
    _restore_mode(backend, tmp, mode)


#: Added to the temp file's mode while the data goes in: a read-only
#: target (0444) gave its temp 0444 before the write, and the write was
#: refused. Only the owner gains a bit; the final mode is restored after.
_OWNER_WRITE = 0o200


def _is_local(backend) -> bool:
    try:
        from core.local_fs import LocalFS
    except Exception:  # noqa: BLE001
        return False
    return isinstance(backend, LocalFS)


def _keep_identity_reason(backend, path: str) -> str | None:
    """Why a save to the local file *path* must write INTO the file
    instead of renaming a new one over it; ``None`` when a rename loses
    nothing. Paths of any other backend are not paths on this machine."""
    if not _is_local(backend):
        return None
    try:
        st = os.stat(path)
    except OSError:
        return None  # a new file: nothing to keep
    if not stat_module.S_ISREG(st.st_mode):
        return None
    if st.st_nlink > 1:
        return "the file has other hard links"
    folder = os.path.dirname(os.path.abspath(path))
    if not os.access(folder, os.W_OK):
        return "its folder is not writable"
    if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
        return "it belongs to another user"
    return None


def _carry_local_attributes(backend, src: str, dst: str) -> bool:
    """Give the local temp *dst* the group and extended attributes of
    *src*. False when one of them cannot be carried over: the rename
    would drop it, so the caller writes in place instead."""
    if not _is_local(backend):
        return True
    try:
        st_src, st_dst = os.stat(src), os.stat(dst)
    except OSError:
        return True  # a new file: nothing to carry
    if hasattr(os, "chown") and st_src.st_gid != st_dst.st_gid:
        try:
            os.chown(dst, -1, st_src.st_gid)
        except OSError as exc:
            log.debug("atomic_write: cannot give %s the group of %s: %s", dst, src, exc)
            return False
    if not hasattr(os, "listxattr"):
        return True
    try:
        names = os.listxattr(src)
    except OSError:
        return True  # the file system has no xattrs
    for name in names:
        try:
            value = os.getxattr(src, name)
            try:
                if os.getxattr(dst, name) == value:
                    continue  # e.g. the security label the folder gave it
            except OSError:
                pass
            os.setxattr(dst, name, value)
        except OSError as exc:
            log.debug("atomic_write: cannot carry xattr %s to %s: %s", name, dst, exc)
            return False
    return True


def _overwrite_local(path: str, data: bytes) -> None:
    """Write *data* into the existing local file *path* (same inode)."""
    with open(path, "r+b") as fh:
        fh.write(data)
        fh.truncate()
        fh.flush()
        os.fsync(fh.fileno())


def _write_in_place(path: str, data: bytes) -> None:
    """Overwrite the local file *path*, keeping inode, links, owner and
    attributes, with the old bytes recoverable until the write is done."""
    import shutil

    from core.path_policy import hidden_sibling_name

    if not os.access(path, os.W_OK):
        # Refused before anything is touched (a read-only file in a
        # read-only folder): the same error a direct open would give.
        raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), path)
    folder = os.path.dirname(os.path.abspath(path))
    backup = None
    old = None
    if os.access(folder, os.W_OK):
        backup = os.path.join(
            folder,
            hidden_sibling_name(os.path.basename(path), f".{secrets.token_hex(6)}.bak"),
        )
        shutil.copyfile(path, backup)
    else:
        with open(path, "rb") as fh:
            old = fh.read()
    try:
        _overwrite_local(path, data)
    except BaseException:
        try:
            if backup is not None:
                with open(backup, "rb") as fh:
                    old = fh.read()
            _overwrite_local(path, old)
        except Exception as undo_exc:  # noqa: BLE001 - the original error is raised
            kept = f"; the old content is in {backup}" if backup else ""
            log.error(
                "atomic_write: could not restore %s after a failed save%s: %s",
                path,
                kept,
                undo_exc,
            )
        else:
            if backup is not None:
                os.remove(backup)
        raise
    if backup is not None:
        os.remove(backup)


def _in_place_journaled(op_id: str, path: str, data: bytes, reason: str) -> None:
    log.info("atomic_write: writing %s in place: %s", path, reason)
    try:
        _write_in_place(path, data)
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
    _finish_journal(
        op_id,
        "atomic_write",
        status="done",
        dest=path,
        bytes_total=len(data),
        bytes_done=len(data),
        details={"in_place": reason},
    )


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
    direct = _is_native_atomic(backend) or _cannot_rename(backend)
    if not direct:
        try:
            resolved = _resolve_destination(backend, path)
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
        if resolved is None:
            # A link we cannot read: open_write follows it, renaming
            # over it would replace it.
            direct = True
        else:
            path, previous_mode = resolved
            reason = _keep_identity_reason(backend, path)
            if reason is not None:
                _in_place_journaled(op_id, path, data, reason)
                return
    if direct:
        try:
            with backend.open_write(path) as f:
                f.write(data)
            log.debug("atomic_write: direct write for %s", path)
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
    # 0644 and the next X session would not start. ``previous_mode``
    # comes from _resolve_destination, i.e. from the file, not a link.
    carried = True
    try:
        if previous_mode is not None:
            _precreate_with_mode(backend, tmp, previous_mode | _OWNER_WRITE)
        with backend.open_write(tmp) as f:
            f.write(data)
        if previous_mode is not None and not previous_mode & _OWNER_WRITE:
            _restore_mode(backend, tmp, previous_mode)
        carried = _carry_local_attributes(backend, path, tmp)
        if carried:
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
    if not carried:
        # The rename would drop the file's group or an extended attribute.
        try:
            backend.remove(tmp)
        except Exception as cleanup_exc:  # noqa: BLE001
            log.debug("atomic_write: cleanup of %s failed: %s", tmp, cleanup_exc)
        _in_place_journaled(op_id, path, data, "an attribute would not survive a rename")


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
    direct = _is_native_atomic(backend) or _cannot_rename(backend)
    previous_mode = None
    if not direct:
        resolved = _resolve_destination(backend, path)
        if resolved is None:
            direct = True  # a link we cannot read: write through it
        else:
            path, previous_mode = resolved
    if direct:
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
        if previous_mode is not None:
            _precreate_with_mode(backend, tmp, previous_mode | _OWNER_WRITE)
        with backend.open_write(tmp) as f:
            while True:
                chunk = reader.read(chunk_size)
                if not chunk:
                    break
                f.write(chunk)
                bytes_done += len(chunk)
                if on_chunk:
                    on_chunk(bytes_done)
        if previous_mode is not None and not previous_mode & _OWNER_WRITE:
            _restore_mode(backend, tmp, previous_mode)
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
