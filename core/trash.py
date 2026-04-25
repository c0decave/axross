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

import json
import logging
import posixpath
import uuid
from datetime import datetime

from models.trash_entry import TrashEntry

log = logging.getLogger("core.trash")

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
    try:
        return backend.join(base, TRASH_DIRNAME)
    except Exception:
        return posixpath.join(base, TRASH_DIRNAME)


def _ensure_trash_dir(backend, trash_root: str) -> None:
    try:
        if not backend.exists(trash_root):
            backend.mkdir(trash_root)
    except OSError as exc:
        raise OSError(
            f"Cannot create trash directory {trash_root}: {exc}"
        ) from exc


def _meta_path(backend, trash_root: str, trash_id: str) -> str:
    try:
        return backend.join(trash_root, trash_id + META_SUFFIX)
    except Exception:
        return posixpath.join(trash_root, trash_id + META_SUFFIX)


def _data_path(backend, trash_root: str, trash_id: str) -> str:
    try:
        return backend.join(trash_root, trash_id)
    except Exception:
        return posixpath.join(trash_root, trash_id)


def _write_meta(backend, meta_file: str, payload: dict) -> None:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    handle = backend.open_write(meta_file)
    try:
        handle.write(data)
    finally:
        handle.close()


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
        log.warning("Corrupt trash sidecar %s: exceeds %d bytes",
                    meta_file, MAX_META_SIZE)
        return None
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
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


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def trash(backend, path: str, root: str | None = None) -> str:
    """Move *path* into the trash and return its ``trash_id``.

    The returned id is a UUID4 without dashes. After the call, the
    original *path* no longer exists; ``<root>/.axross-trash/<id>``
    (file or directory) and ``<id>.meta.json`` (sidecar) do.

    The move is attempted via :meth:`FileBackend.rename`. If rename
    across directories isn't supported by the backend, OSError
    propagates — callers can fall back to a copy + delete themselves.
    """
    trash_root = _resolve_root(backend, root)
    _ensure_trash_dir(backend, trash_root)

    info = _stat_safely(backend, path)
    if info is None:
        raise OSError(f"trash: source does not exist: {path}")

    trash_id = uuid.uuid4().hex
    dst = _data_path(backend, trash_root, trash_id)
    meta = _meta_path(backend, trash_root, trash_id)

    try:
        backend.rename(path, dst)
    except OSError as exc:
        raise OSError(f"trash: rename {path} -> {dst} failed: {exc}") from exc

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
            backend.rename(dst, path)
        except OSError:
            log.error(
                "trash: sidecar write failed AND rollback failed; "
                "data is at %s with no metadata", dst,
            )
        raise OSError(f"trash: metadata write failed: {exc}") from exc

    return trash_id


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
    for it in items:
        name = getattr(it, "name", "") or ""
        if not name.endswith(META_SUFFIX):
            continue
        trash_id = name[: -len(META_SUFFIX)]
        meta_file = _meta_path(backend, trash_root, trash_id)
        meta = _read_meta(backend, meta_file)
        if meta is None:
            continue
        data_file = _data_path(backend, trash_root, trash_id)
        if not backend.exists(data_file):
            log.warning(
                "list_trash: sidecar %s without data — skipped", meta_file
            )
            continue
        raw_when = meta.get("trashed_at") or ""
        try:
            when = datetime.fromisoformat(raw_when) if raw_when else datetime.now()
        except (TypeError, ValueError):
            when = datetime.now()
        out.append(TrashEntry(
            trash_id=trash_id,
            original_path=str(meta.get("original_path", "")),
            trashed_at=when,
            size=int(meta.get("size", 0) or 0),
            is_dir=bool(meta.get("is_dir", False)),
            label=str(meta.get("label", "")),
        ))
        known_ids.add(trash_id)
    # Newest-first so UIs don't have to re-sort.
    out.sort(key=lambda e: e.trashed_at, reverse=True)
    return out


def restore(backend, trash_id: str, root: str | None = None,
            target: str | None = None) -> str:
    """Move a trashed entry back to its original path (or *target*).

    Returns the path where the entry now lives. If the destination
    already exists the caller's rename will fail; this is intentional
    — silently overwriting is surprising and hard to undo.
    """
    trash_root = _resolve_root(backend, root)
    meta_file = _meta_path(backend, trash_root, trash_id)
    data_file = _data_path(backend, trash_root, trash_id)

    if not backend.exists(data_file):
        raise OSError(f"restore: trash entry not found: {trash_id}")

    meta = _read_meta(backend, meta_file)
    if meta is None and target is None:
        raise OSError(
            f"restore: metadata missing for {trash_id}; "
            f"pass an explicit target="
        )
    dst = target if target is not None else str(meta.get("original_path", ""))
    if not dst:
        raise OSError(f"restore: original path not recorded for {trash_id}")

    # Sidecars live alongside user data. An attacker who can write to
    # the trash directory (shared S3 bucket, collaborative WebDAV)
    # could plant a sidecar whose ``original_path`` contains NUL
    # bytes, bidi overrides, or path-traversal components — reuse the
    # central validator so ``backend.rename(data_file, dst)`` never
    # sees attacker-controlled nastiness.
    from core.remote_name import (
        MAX_REMOTE_PATH_BYTES, RemoteNameError, validate_remote_name,
    )
    try:
        validate_remote_name(
            dst, max_bytes=MAX_REMOTE_PATH_BYTES, allow_separators=True,
        )
    except RemoteNameError as exc:
        raise OSError(
            f"restore: sidecar {trash_id} has an unsafe original_path: {exc}"
        ) from exc

    try:
        backend.rename(data_file, dst)
    except OSError as exc:
        raise OSError(
            f"restore: rename {data_file} -> {dst} failed: {exc}"
        ) from exc

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
        full = _data_path(backend, trash_root, name) \
            if not name.endswith(META_SUFFIX) \
            else _meta_path(backend, trash_root, name[: -len(META_SUFFIX)])
        is_dir = bool(getattr(it, "is_dir", False))
        try:
            backend.remove(full, recursive=True) if is_dir \
                else backend.remove(full)
            # Count only the data entries (not sidecars) to give the
            # caller a useful "how many files did I empty" number.
            if not name.endswith(META_SUFFIX):
                removed += 1
        except OSError as exc:
            log.warning("empty_trash: remove %s failed: %s", full, exc)
    return removed
