"""Universal trash for any FileBackend.

Most protocols (FTP, SMB, S3, ...) lack a native recycle bin. The
:func:`trash` helper gives the GUI a uniform "send to trash" primitive
on top of whatever the backend *does* support — typically
``rename()``. Items are moved into ``<root>/.axross-trash/<uuid>``
with a sidecar metadata file; :func:`restore` moves them back.

Why a per-entry sidecar and not one central manifest
----------------------------------------------------
A single manifest would require read-modify-write under races: two
clients trashing at once would clobber each other's entries. One
sidecar per entry means every trash/restore/empty is a single
rename + write_small_file, never a read-modify-write on shared
state.

Why not a generation counter / lock file
----------------------------------------
We target protocols that don't offer atomic compare-and-swap (FTP,
SMB, WebDAV). A locking scheme would be either best-effort or
protocol-specific. Per-entry sidecars sidestep the problem
entirely.

Trash root
----------
Defaults to ``<backend.home()>/.axross-trash``. Callers can pin a
different root via the ``root`` argument — useful for chroot'd
setups or when the backend has multiple writable trees (e.g.
multi-bucket S3 wrappers).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import uuid
from datetime import datetime

from core.path_policy import safe_join
from models.trash_entry import TrashEntry

log = logging.getLogger(__name__)

TRASH_DIRNAME = ".axross-trash"
META_SUFFIX = ".meta.json"

# Bound on sidecar JSON size — protects us from malicious actors who
# gain write access to the trash dir and plant a multi-MB "sidecar".
MAX_META_SIZE = 64 * 1024


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_root(backend, root: str | None) -> str:
    """Pick the trash root directory for this backend."""
    if root is not None:
        return root
    try:
        base = backend.home()
    except Exception:
        base = "/"
    if not base:
        base = "/"
    return safe_join(backend, base, TRASH_DIRNAME)


def _ensure_trash_dir(backend, trash_root: str) -> None:
    try:
        if not backend.exists(trash_root):
            backend.mkdir(trash_root)
    except OSError as exc:
        raise OSError(f"Cannot create trash directory {trash_root}: {exc}") from exc


def _meta_path(backend, trash_root: str, trash_id: str) -> str:
    return safe_join(backend, trash_root, trash_id + META_SUFFIX)


def _data_path(backend, trash_root: str, trash_id: str) -> str:
    return safe_join(backend, trash_root, trash_id)


def _write_meta(backend, meta_file: str, payload: dict) -> None:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    from core.atomic_io import atomic_write

    atomic_write(backend, meta_file, data)


def _read_meta(backend, meta_file: str) -> dict | None:
    try:
        handle = backend.open_read(meta_file)
    except OSError:
        return None
    # Pre-bind: if read() raises, the finally block runs and we return
    # None via the OSError branch; the later ``isinstance(raw, str)``
    # line is never reached, but pre-binding removes the linter warning
    # and guarantees no NameError if control flow changes later.
    raw: bytes | str = b""
    try:
        # Bound sidecar size. Legit sidecars are <1 KiB; 64 KiB is a
        # generous ceiling that stops an attacker who can write to the
        # trash dir from using a multi-MB sidecar to OOM the client.
        raw = handle.read(MAX_META_SIZE + 1)
    except OSError as exc:
        log.debug("trash: sidecar read(%s) failed: %s", meta_file, exc)
        return None
    finally:
        try:
            handle.close()
        except Exception as close_exc:
            log.debug("trash: sidecar handle close failed: %s", close_exc)
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if len(raw) > MAX_META_SIZE:
        log.warning("Corrupt trash sidecar %s: exceeds %d bytes", meta_file, MAX_META_SIZE)
        return None
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError) as exc:
        # ValueError covers UnicodeDecodeError; a sidecar nested deeper
        # than the decoder's stack raises RecursionError.
        log.warning("Corrupt trash sidecar %s: %s", meta_file, exc)
        return None
    if not isinstance(parsed, dict):
        log.warning("Corrupt trash sidecar %s: not a JSON object", meta_file)
        return None
    return parsed


def _stat_safely(backend, path: str):
    try:
        return backend.stat(path)
    except OSError:
        return None


def _finish_journal(op_id: str, operation: str, **fields) -> None:
    if not op_id:
        return
    try:
        from core.operation_journal import finish_operation

        finish_operation(op_id, operation, **fields)
    except Exception as exc:  # noqa: BLE001
        log.debug("%s: journal finish failed: %s", operation, exc)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def trash(backend, path: str, root: str | None = None, *, journal: bool = True) -> str:
    """Move *path* into the trash and return its ``trash_id``.

    The returned id is a UUID4 without dashes. After the call, the
    original *path* no longer exists; ``<root>/.axross-trash/<id>``
    (file or directory) and ``<id>.meta.json`` (sidecar) do.

    The move is attempted via :meth:`FileBackend.rename`. If rename
    across directories isn't supported by the backend, OSError
    propagates — callers can fall back to a copy + delete themselves.

    ``journal=False`` is for callers that journal the trashing as part
    of an operation of their own (undoing a metadata removal): a second,
    separate "trash" entry would be offered to the next Ctrl+Z.
    """
    op_id = ""
    # Every event carries the label, not just the start: undo reads a
    # bounded window of the journal, and a finish event whose start has
    # scrolled out must still name the connection it belongs to.
    label = getattr(backend, "name", "") or type(backend).__name__
    try:
        from core.operation_journal import start_operation

        if journal:
            op_id = start_operation(
                "trash",
                source=path,
                backend=label,
            )
    except Exception as exc:  # noqa: BLE001
        log.debug("trash: journal start failed: %s", exc)
    trash_root = _resolve_root(backend, root)
    try:
        _ensure_trash_dir(backend, trash_root)
    except OSError as exc:
        _finish_journal(
            op_id,
            "trash",
            backend=label,
            status="error",
            source=path,
            error=str(exc),
        )
        raise

    info = _stat_safely(backend, path)
    if info is None:
        err = f"trash: source does not exist: {path}"
        _finish_journal(op_id, "trash", backend=label, status="error", source=path, error=err)
        raise OSError(err)

    trash_id = uuid.uuid4().hex
    dst = _data_path(backend, trash_root, trash_id)
    meta = _meta_path(backend, trash_root, trash_id)

    try:
        from core.server_ops import server_side_move

        server_side_move(backend, path, dst)
    except OSError as exc:
        _finish_journal(op_id, "trash", backend=label, status="error", source=path, dest=dst, error=str(exc))
        raise OSError(f"trash: move {path} -> {dst} failed: {exc}") from exc

    payload = {
        "trash_id": trash_id,
        "original_path": path,
        "trashed_at": datetime.now().isoformat(timespec="seconds"),
        "size": int(getattr(info, "size", 0) or 0),
        "is_dir": bool(getattr(info, "is_dir", False)),
        "label": getattr(info, "name", "") or "",
    }
    try:
        _write_meta(backend, meta, payload)
    except OSError as exc:
        # Best-effort rollback: try to move the data back to avoid an
        # orphaned trash entry. If rollback also fails we re-raise the
        # original write error — users at least see *something* went
        # wrong and the data is still there under a known id.
        try:
            from core.server_ops import server_side_move

            server_side_move(backend, dst, path)
        except OSError:
            log.error(
                "trash: sidecar write failed AND rollback failed; data is at %s with no metadata",
                dst,
            )
        _finish_journal(op_id, "trash", backend=label, status="error", source=path, dest=dst, error=str(exc))
        raise OSError(f"trash: metadata write failed: {exc}") from exc

    _finish_journal(
        op_id, "trash", backend=label, status="done", source=path, dest=dst, details={"trash_id": trash_id}
    )
    return trash_id


def _is_local(backend) -> bool:
    from core.local_fs import LocalFS

    return isinstance(backend, LocalFS)


def _sha256_of(backend, path: str) -> str:
    digest = hashlib.sha256()
    handle = open(path, "rb") if _is_local(backend) else backend.open_read(path)  # noqa: SIM115
    try:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk.encode("utf-8") if isinstance(chunk, str) else chunk)
    finally:
        handle.close()
    return digest.hexdigest()


def _remove_quietly(backend, path: str) -> None:
    try:
        if backend.exists(path):
            backend.remove(path)
    except OSError as exc:
        log.warning("trash: could not remove %s: %s", path, exc)


def trash_copy(
    backend, path: str, *, local_source: str | None = None, root: str | None = None
) -> str:
    """Keep a copy of the file *path* in the trash and return its ``trash_id``.

    Unlike :func:`trash`, *path* stays where it is: this is the backup a
    caller takes right before it replaces the file atomically (removing a
    file's metadata in place), so the path is never missing in between.
    The entry lists and restores like any other; :func:`restore_over`
    puts it back over the replacement.

    On a local file system the copy is a hard link when the trash is on
    the same file system - the original bytes then cost nothing, and the
    atomic replace that follows leaves them with the trash alone. A
    remote file is uploaded from *local_source* (the caller's bounded
    local copy) when given, else streamed from the backend.

    Not journaled: the caller records its own operation.
    """
    info = _stat_safely(backend, path)
    if info is None or getattr(info, "is_dir", False):
        raise OSError(f"trash_copy: not a file: {path}")
    trash_root = _resolve_root(backend, root)
    _ensure_trash_dir(backend, trash_root)
    trash_id = uuid.uuid4().hex
    dst = _data_path(backend, trash_root, trash_id)
    meta = _meta_path(backend, trash_root, trash_id)
    from core.atomic_io import atomic_write_stream

    try:
        if local_source is None and _is_local(backend):
            try:
                os.link(path, dst, follow_symlinks=False)
            except OSError:
                shutil.copyfile(path, dst, follow_symlinks=False)
        elif local_source is not None:
            with open(local_source, "rb") as src:
                atomic_write_stream(backend, dst, src)
        else:
            with backend.open_read(path) as src:
                atomic_write_stream(backend, dst, src)
    except OSError as exc:
        _remove_quietly(backend, dst)
        raise OSError(f"trash_copy: cannot keep a copy of {path}: {exc}") from exc
    payload = {
        "trash_id": trash_id,
        "original_path": path,
        "trashed_at": datetime.now().isoformat(timespec="seconds"),
        "size": int(getattr(info, "size", 0) or 0),
        "is_dir": False,
        "label": getattr(info, "name", "") or "",
        "kept_copy": True,
    }
    try:
        _write_meta(backend, meta, payload)
    except OSError as exc:
        _remove_quietly(backend, dst)
        raise OSError(f"trash_copy: metadata write failed: {exc}") from exc
    return trash_id


def discard(backend, trash_id: str, root: str | None = None) -> None:
    """Remove one trash entry for good (a kept copy that is not needed after
    all, because the replacement it guarded never happened)."""
    trash_root = _resolve_root(backend, root)
    try:
        data_file = _data_path(backend, trash_root, trash_id)
        meta_file = _meta_path(backend, trash_root, trash_id)
    except ValueError as exc:
        raise OSError(f"discard: unsafe trash id {trash_id!r}: {exc}") from exc
    _remove_quietly(backend, data_file)
    _remove_quietly(backend, meta_file)


def restore_over(
    backend,
    trash_id: str,
    *,
    target: str,
    expected_sha256: str,
    root: str | None = None,
) -> str:
    """Put the kept copy *trash_id* back at *target*, replacing what is there.

    Only while *target* still holds exactly the content its replacement
    wrote (``expected_sha256``): anything else means it was edited since,
    and putting the original back would throw that edit away, so this
    raises and leaves both the file and the trash entry alone. A target
    that no longer exists is simply restored.

    Locally the kept copy is renamed over the target (atomic, and the
    original file - its inode and times - comes back as it was). On other
    backends it is streamed through :func:`core.atomic_io.atomic_write_stream`.
    """
    trash_root = _resolve_root(backend, root)
    try:
        meta_file = _meta_path(backend, trash_root, trash_id)
        data_file = _data_path(backend, trash_root, trash_id)
    except ValueError as exc:
        raise OSError(f"restore: unsafe trash id {trash_id!r}: {exc}") from exc
    if not backend.exists(data_file):
        raise OSError(f"restore: trash entry not found: {trash_id}")
    from core.remote_name import MAX_REMOTE_PATH_BYTES, RemoteNameError, validate_remote_name

    try:
        validate_remote_name(target, max_bytes=MAX_REMOTE_PATH_BYTES, allow_separators=True)
    except RemoteNameError as exc:
        raise OSError(f"restore: unsafe target {target!r}: {exc}") from exc
    if backend.exists(target):
        if _sha256_of(backend, target) != expected_sha256:
            raise OSError(
                f"{target} was changed after its metadata was removed; putting the "
                "original back would discard that change. The original is still in the trash."
            )
    if _is_local(backend):
        os.replace(data_file, target)
    else:
        from core.atomic_io import atomic_write_stream

        with backend.open_read(data_file) as src:
            atomic_write_stream(backend, target, src)
        _remove_quietly(backend, data_file)
    _remove_quietly(backend, meta_file)
    return target


def _text(value) -> str:
    return value if isinstance(value, str) else ""


def _size(value) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0
    if not 0 <= value < 2**63:  # also NaN and infinity
        return 0
    return int(value)


def _trashed_at(value) -> datetime:
    """The sidecar's timestamp as naive local time, which is what trash()
    writes; an aware one is converted so the listing can be sorted."""
    if isinstance(value, str) and value:
        try:
            when = datetime.fromisoformat(value)
        except ValueError:
            return datetime.now()
        if when.tzinfo is not None:
            when = when.astimezone().replace(tzinfo=None)
        return when
    return datetime.now()


def list_trash(backend, root: str | None = None) -> list[TrashEntry]:
    """Enumerate trash entries, newest first.

    Sidecars without a matching data object are treated as stale and
    logged but otherwise skipped — we don't auto-delete them to avoid
    turning a read-only browse into a silent cleanup.
    """
    trash_root = _resolve_root(backend, root)
    if not backend.exists(trash_root):
        return []
    try:
        items = backend.list_dir(trash_root)
    except OSError as exc:
        log.warning("list_trash: cannot list %s: %s", trash_root, exc)
        return []

    out: list[TrashEntry] = []
    known_ids: set[str] = set()
    # Data objects the listing already shows as plain entries need no
    # exists() round trip. Symlinks (the backend decides whether exists()
    # follows them) and names missing here (case-insensitive servers)
    # still ask, as before.
    plain_names = {
        getattr(it, "name", "") for it in items if not getattr(it, "is_link", False)
    }
    for it in items:
        name = getattr(it, "name", "") or ""
        if not name.endswith(META_SUFFIX):
            continue
        trash_id = name[: -len(META_SUFFIX)]
        try:
            meta_file = _meta_path(backend, trash_root, trash_id)
            data_file = _data_path(backend, trash_root, trash_id)
        except ValueError as exc:
            log.warning(
                "list_trash: skipping unsafe trash entry %r: %s",
                name,
                exc,
            )
            continue
        meta = _read_meta(backend, meta_file)
        if meta is None:
            continue
        if trash_id not in plain_names and not backend.exists(data_file):
            log.warning("list_trash: sidecar %s without data — skipped", meta_file)
            continue
        # A sidecar is data on the server, possibly written by someone
        # else: a field of the wrong type is shown as empty instead of
        # raising out of the listing and hiding every other entry.
        out.append(
            TrashEntry(
                trash_id=trash_id,
                original_path=_text(meta.get("original_path")),
                trashed_at=_trashed_at(meta.get("trashed_at")),
                size=_size(meta.get("size")),
                is_dir=bool(meta.get("is_dir", False)),
                label=_text(meta.get("label")),
            )
        )
        known_ids.add(trash_id)
    # Newest-first so UIs don't have to re-sort.
    out.sort(key=lambda e: e.trashed_at, reverse=True)
    return out


def restore(backend, trash_id: str, root: str | None = None, target: str | None = None) -> str:
    """Move a trashed entry back to its original path (or *target*).

    Returns the path where the entry now lives. If the destination
    already exists the caller's rename will fail; this is intentional
    — silently overwriting is surprising and hard to undo.
    """
    trash_root = _resolve_root(backend, root)
    try:
        meta_file = _meta_path(backend, trash_root, trash_id)
        data_file = _data_path(backend, trash_root, trash_id)
    except ValueError as exc:
        raise OSError(f"restore: unsafe trash id {trash_id!r}: {exc}") from exc

    if not backend.exists(data_file):
        raise OSError(f"restore: trash entry not found: {trash_id}")

    meta = _read_meta(backend, meta_file)
    if meta is None and target is None:
        raise OSError(f"restore: metadata missing for {trash_id}; pass an explicit target=")
    dst = target if target is not None else str(meta.get("original_path", ""))
    if not dst:
        raise OSError(f"restore: original path not recorded for {trash_id}")

    # Sidecars live alongside user data. An attacker who can write to
    # the trash directory (shared S3 bucket, collaborative WebDAV)
    # could plant a sidecar whose ``original_path`` contains NUL
    # bytes, bidi overrides, or path-traversal components — reuse the
    # central validator so the restore move never sees attacker-
    # controlled nastiness.
    from core.remote_name import (
        MAX_REMOTE_PATH_BYTES,
        RemoteNameError,
        validate_remote_name,
    )

    try:
        validate_remote_name(
            dst,
            max_bytes=MAX_REMOTE_PATH_BYTES,
            allow_separators=True,
        )
    except RemoteNameError as exc:
        raise OSError(f"restore: sidecar {trash_id} has an unsafe original_path: {exc}") from exc

    if backend.exists(dst):
        raise OSError(f"restore: target already exists: {dst}")

    try:
        from core.server_ops import server_side_move

        server_side_move(backend, data_file, dst)
    except OSError as exc:
        raise OSError(f"restore: move {data_file} -> {dst} failed: {exc}") from exc

    # Best-effort sidecar cleanup. A stale sidecar is survivable
    # (list_trash skips it) so we don't raise if it fails.
    try:
        backend.remove(meta_file)
    except OSError as exc:
        log.warning("restore: leftover sidecar %s: %s", meta_file, exc)

    return dst


def empty_trash(backend, root: str | None = None) -> int:
    """Permanently remove every trash entry. Returns count removed."""
    trash_root = _resolve_root(backend, root)
    if not backend.exists(trash_root):
        return 0
    try:
        items = backend.list_dir(trash_root)
    except OSError as exc:
        log.warning("empty_trash: cannot list %s: %s", trash_root, exc)
        return 0
    removed = 0
    for it in items:
        name = getattr(it, "name", "") or ""
        try:
            full = (
                _data_path(backend, trash_root, name)
                if not name.endswith(META_SUFFIX)
                else _meta_path(backend, trash_root, name[: -len(META_SUFFIX)])
            )
        except ValueError as exc:
            log.warning(
                "empty_trash: skipping unsafe trash entry %r: %s",
                name,
                exc,
            )
            continue
        is_dir = bool(getattr(it, "is_dir", False))
        try:
            backend.remove(full, recursive=True) if is_dir else backend.remove(full)
            # Count only the data entries (not sidecars) to give the
            # caller a useful "how many files did I empty" number.
            if not name.endswith(META_SUFFIX):
                removed += 1
        except OSError as exc:
            log.warning("empty_trash: remove %s failed: %s", full, exc)
    return removed
