"""RAM-only FileBackend (RamFS) — bytes live in process memory only.

Why this exists: some workflows benefit from a workspace that
**never** lands on disk: inspecting a decrypted ``.axenc`` blob,
staging a remote→remote transfer, holding tempfiles for
``core.atomic_io`` / archive extraction. RamFS gives a clean
FileBackend implementation backed by a per-instance dict so
nothing touches the filesystem.

Two close cousins live in :mod:`core.tmpfs_detect`:

* OS-level tmpfs paths (``/dev/shm``, ``/run/user/$UID``) —
  exposed as ``LocalFS`` mounts tagged ``[RAM]`` in the UI.
* This module — the **pure in-process** variant.

**RAM-pressure guard.** A misuse (or a malicious upload chain)
could pour gigabytes into RamFS and OOM the host. Two
independent caps prevent that:

1. **Per-instance cap** ``max_bytes`` (default 256 MiB) —
   set at construction time. Every write that would push
   ``RamFS.size_bytes`` past it raises ``OSError``.
2. **System-pressure guard** — before each write we check
   the OS-reported free memory. On Linux we parse
   ``/proc/meminfo`` directly (no dep). On other platforms we
   fall back to ``psutil`` if it happens to be installed; if
   neither path works the guard is skipped (logged once). If
   less than :data:`SYSTEM_RESERVE_BYTES` (default 256 MiB)
   free, we refuse so the write doesn't tip the OS into swap
   thrash or OOM-kill territory.

The guards are **opportunistic**: they refuse the *next* write
when a threshold is crossed, they don't pre-allocate. Tests
patch :func:`_available_memory_bytes` to drive both code paths
deterministically.
"""
from __future__ import annotations

import io
import logging
import posixpath
import threading
from datetime import datetime
from typing import IO

from models.file_item import FileItem

log = logging.getLogger(__name__)


# Default per-instance cap. 256 MiB is enough for inspecting a
# few decrypted blobs / staging a small archive without becoming
# a hidden footgun. User can override per-profile.
DEFAULT_MAX_BYTES = 256 * 1024 * 1024

# Minimum amount of free system memory we want to keep available
# AFTER a RamFS write completes. Refusing writes when free RAM
# would drop below this avoids OOM-killer scenarios on small
# hosts (e.g. raspberry-pi class boxes running axross-mcp).
SYSTEM_RESERVE_BYTES = 256 * 1024 * 1024


# System-memory probe, by preference:
#   1. /proc/meminfo (Linux — kernel-authoritative, zero deps)
#   2. psutil.virtual_memory().available (cross-platform fallback)
#   3. -1 — caller treats as "skip the guard"
# The function is exposed at module scope so tests can monkey-patch
# it with a deterministic value.

import sys as _sys


def _read_proc_meminfo_available() -> int:
    """Parse ``/proc/meminfo`` and return ``MemAvailable`` in bytes.
    Returns ``-1`` on any read/parse failure.

    ``MemAvailable`` is what the kernel itself reports as a realistic
    estimate of how much memory is available for new allocations
    without swapping (added in Linux 3.14, present on every
    realistically-supported kernel today). ``MemFree`` would
    under-report because it ignores reclaimable cache.
    """
    try:
        with open("/proc/meminfo", "rb") as fh:
            for raw in fh:
                if raw.startswith(b"MemAvailable:"):
                    # Format: b"MemAvailable:   12345678 kB\n"
                    parts = raw.split()
                    if len(parts) >= 2:
                        return int(parts[1]) * 1024
    except (OSError, ValueError):
        pass
    return -1


def _psutil_available() -> int:
    """Best-effort psutil probe for non-Linux platforms.
    Returns ``-1`` when psutil isn't importable or raises.
    """
    try:
        import psutil  # type: ignore[import-not-found]
        return int(psutil.virtual_memory().available)
    except Exception:  # noqa: BLE001 — any failure → skip the guard
        return -1


def _available_memory_bytes() -> int:
    """Return free system memory in bytes, or ``-1`` when no probe
    works. Linux uses /proc/meminfo directly; everything else falls
    back to psutil if it happens to be installed.
    """
    if _sys.platform.startswith("linux"):
        result = _read_proc_meminfo_available()
        if result >= 0:
            return result
        # Linux without /proc (e.g. some hardened sandboxes) — try
        # psutil as a secondary path.
    return _psutil_available()


class RamFsCapacityError(OSError):
    """Raised when a write would push RamFS past its per-instance
    cap or below the system-memory reserve."""


# ---------------------------------------------------------------------------
# Internal storage — a tiny path → entry mapping
# ---------------------------------------------------------------------------

class _Entry:
    """One node in the RamFS tree: file or directory."""
    __slots__ = ("is_dir", "data", "mtime", "mode")

    def __init__(self, is_dir: bool, data: bytes = b"", mode: int = 0o644):
        self.is_dir = is_dir
        # Always a bytes object for files, b"" for dirs.
        self.data = data
        self.mtime = datetime.now()
        self.mode = mode if not is_dir else 0o755


# ---------------------------------------------------------------------------
# Public RamFS session
# ---------------------------------------------------------------------------

class RamFsSession:
    """In-process RAM-backed FileBackend.

    Construction makes an empty tree with ``/`` as the root. The
    backend supports the full FileBackend write surface (mkdir,
    open_read, open_write, remove, rename, chmod) but everything
    is volatile — disconnect / process exit drops it all.
    """

    supports_symlinks = False
    supports_hardlinks = False

    def __init__(
        self,
        label: str = "ramfs",
        max_bytes: int = DEFAULT_MAX_BYTES,
        system_reserve_bytes: int = SYSTEM_RESERVE_BYTES,
    ):
        self._label = label
        self._max_bytes = int(max_bytes)
        self._system_reserve = int(system_reserve_bytes)
        self._lock = threading.RLock()
        # Path → _Entry. Always normalised: leading ``/``, no ``..``.
        self._tree: dict[str, _Entry] = {"/": _Entry(is_dir=True, mode=0o755)}
        log.info(
            "RamFsSession opened: label=%s, max=%d B, system-reserve=%d B",
            label, self._max_bytes, self._system_reserve,
        )

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return f"RAM:{self._label}"

    @property
    def connected(self) -> bool:
        return True

    @property
    def size_bytes(self) -> int:
        with self._lock:
            return sum(len(e.data) for e in self._tree.values() if not e.is_dir)

    @property
    def max_bytes(self) -> int:
        return self._max_bytes

    def disconnect(self) -> None:
        with self._lock:
            self._tree.clear()
            self._tree["/"] = _Entry(is_dir=True, mode=0o755)
        log.info("RamFsSession closed: %s — all bytes discarded", self._label)

    def close(self) -> None:
        self.disconnect()

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def home(self) -> str:
        return "/"

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        cleaned = [p.strip("/") for p in parts if p]
        if not cleaned:
            return "/"
        return "/" + "/".join(cleaned)

    def parent(self, path: str) -> str:
        return posixpath.dirname(self.normalize(path)) or "/"

    def normalize(self, path: str) -> str:
        if not path:
            return "/"
        # Reject ``..`` resolution that would escape — RamFS has no
        # parent-of-root concept and normpath would silently flatten.
        normalised = posixpath.normpath(path)
        if not normalised.startswith("/"):
            normalised = "/" + normalised
        # Drop trailing slashes except on root.
        if normalised != "/" and normalised.endswith("/"):
            normalised = normalised.rstrip("/") or "/"
        return normalised

    # ------------------------------------------------------------------
    # Capacity guards
    # ------------------------------------------------------------------

    def _check_capacity(self, additional_bytes: int) -> None:
        """Raise :class:`RamFsCapacityError` if accepting
        *additional_bytes* would push us past either cap."""
        if additional_bytes <= 0:
            return
        new_total = self.size_bytes + int(additional_bytes)
        if new_total > self._max_bytes:
            raise RamFsCapacityError(
                f"RamFS({self._label}) per-instance cap reached: "
                f"{new_total} > {self._max_bytes} bytes",
            )
        avail = _available_memory_bytes()
        if avail >= 0 and avail - additional_bytes < self._system_reserve:
            raise RamFsCapacityError(
                f"RamFS({self._label}) refuses {additional_bytes}-byte "
                f"write: would leave only {avail - additional_bytes} B "
                f"system-free (reserve={self._system_reserve} B)",
            )

    # ------------------------------------------------------------------
    # FileBackend — read surface
    # ------------------------------------------------------------------

    def list_dir(self, path: str) -> list[FileItem]:
        path = self.normalize(path)
        with self._lock:
            entry = self._tree.get(path)
            if entry is None or not entry.is_dir:
                raise OSError(f"RamFS({self._label}): not a directory: {path}")
            prefix = path if path.endswith("/") else path + "/"
            if path == "/":
                prefix = "/"
            items: list[FileItem] = []
            for p, e in self._tree.items():
                if p == path:
                    continue
                if not p.startswith(prefix):
                    continue
                tail = p[len(prefix):]
                if "/" in tail:
                    continue  # belongs to a subdirectory
                items.append(FileItem(
                    name=tail,
                    size=len(e.data) if not e.is_dir else 0,
                    modified=e.mtime,
                    permissions=e.mode,
                    is_dir=e.is_dir,
                    is_link=False,
                ))
        return sorted(items, key=lambda i: (not i.is_dir, i.name))

    def stat(self, path: str) -> FileItem:
        path = self.normalize(path)
        with self._lock:
            entry = self._tree.get(path)
            if entry is None:
                raise OSError(f"RamFS({self._label}): no such path: {path}")
            return FileItem(
                name=posixpath.basename(path) or "/",
                size=len(entry.data) if not entry.is_dir else 0,
                modified=entry.mtime,
                permissions=entry.mode,
                is_dir=entry.is_dir,
                is_link=False,
            )

    def is_dir(self, path: str) -> bool:
        path = self.normalize(path)
        with self._lock:
            entry = self._tree.get(path)
            return bool(entry and entry.is_dir)

    def open_read(self, path: str, mode: str = "rb") -> IO:
        path = self.normalize(path)
        with self._lock:
            entry = self._tree.get(path)
            if entry is None or entry.is_dir:
                raise OSError(f"RamFS({self._label}): not a file: {path}")
            return io.BytesIO(entry.data)

    # ------------------------------------------------------------------
    # FileBackend — write surface
    # ------------------------------------------------------------------

    def open_write(self, path: str, mode: str = "wb") -> IO:
        path = self.normalize(path)
        # Auto-create parents up to root, like LocalFS does for atomic
        # writes via tempdir helpers.
        parent = posixpath.dirname(path) or "/"
        with self._lock:
            if parent not in self._tree:
                self.mkdir(parent, parents=True, exist_ok=True)
            elif not self._tree[parent].is_dir:
                raise OSError(
                    f"RamFS({self._label}): parent is not a directory: {parent}",
                )
        return _RamFsWriter(self, path)

    def mkdir(self, path: str, parents: bool = False, exist_ok: bool = False) -> None:
        path = self.normalize(path)
        with self._lock:
            if path in self._tree:
                if self._tree[path].is_dir and exist_ok:
                    return
                raise OSError(f"RamFS({self._label}): already exists: {path}")
            if parents:
                # Walk the tree creating each missing component.
                bits = [b for b in path.split("/") if b]
                cur = ""
                for b in bits:
                    cur = cur + "/" + b
                    if cur not in self._tree:
                        self._tree[cur] = _Entry(is_dir=True, mode=0o755)
                    elif not self._tree[cur].is_dir:
                        raise OSError(
                            f"RamFS({self._label}): "
                            f"path component is a file: {cur}",
                        )
            else:
                parent = posixpath.dirname(path) or "/"
                if parent not in self._tree or not self._tree[parent].is_dir:
                    raise OSError(
                        f"RamFS({self._label}): parent missing: {parent}",
                    )
                self._tree[path] = _Entry(is_dir=True, mode=0o755)

    def remove(self, path: str, recursive: bool = False) -> None:
        path = self.normalize(path)
        with self._lock:
            entry = self._tree.get(path)
            if entry is None:
                raise OSError(f"RamFS({self._label}): no such path: {path}")
            if entry.is_dir:
                children = [p for p in self._tree if p.startswith(path + "/")]
                if children and not recursive:
                    raise OSError(
                        f"RamFS({self._label}): directory not empty: {path}",
                    )
                for c in children:
                    self._tree.pop(c, None)
            self._tree.pop(path, None)

    def rename(self, src: str, dst: str) -> None:
        src = self.normalize(src)
        dst = self.normalize(dst)
        with self._lock:
            if src not in self._tree:
                raise OSError(f"RamFS({self._label}): no such path: {src}")
            if dst in self._tree:
                raise OSError(f"RamFS({self._label}): already exists: {dst}")
            # Move the entry plus every descendant (re-keying).
            entry = self._tree.pop(src)
            self._tree[dst] = entry
            if entry.is_dir:
                src_prefix = src + "/"
                dst_prefix = dst + "/"
                relocs = [p for p in list(self._tree.keys()) if p.startswith(src_prefix)]
                for old in relocs:
                    new = dst_prefix + old[len(src_prefix):]
                    self._tree[new] = self._tree.pop(old)

    def chmod(self, path: str, mode: int) -> None:
        path = self.normalize(path)
        with self._lock:
            entry = self._tree.get(path)
            if entry is None:
                raise OSError(f"RamFS({self._label}): no such path: {path}")
            entry.mode = int(mode) & 0o7777

    def copy(self, src: str, dst: str) -> None:
        # Rely on read+write so the capacity guards trigger.
        with self.open_read(src) as f:
            data = f.read()
        with self.open_write(dst) as f:
            f.write(data)

    # ------------------------------------------------------------------
    # Internal: commit a write (called by _RamFsWriter.close)
    # ------------------------------------------------------------------

    def _commit_write(self, path: str, data: bytes) -> None:
        path = self.normalize(path)
        with self._lock:
            old = self._tree.get(path)
            old_size = len(old.data) if old and not old.is_dir else 0
            delta = len(data) - old_size
            self._check_capacity(delta)
            self._tree[path] = _Entry(is_dir=False, data=bytes(data), mode=0o644)


# ---------------------------------------------------------------------------
# Writer — buffers bytes, commits on close
# ---------------------------------------------------------------------------

class _RamFsWriter:
    def __init__(self, session: RamFsSession, path: str):
        self._session = session
        self._path = path
        self._buf = io.BytesIO()
        self._closed = False

    def write(self, data: bytes) -> int:
        if self._closed:
            raise OSError("RamFS writer already closed")
        # Eagerly check capacity so the user sees the error at write
        # time rather than at close().
        self._session._check_capacity(len(data))
        return self._buf.write(data)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._session._commit_write(self._path, self._buf.getvalue())
        self._buf.close()

    def discard(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._buf.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.discard()
        else:
            self.close()


# ---------------------------------------------------------------------------
# Auto-decrypt-to-RAM helper
# ---------------------------------------------------------------------------

def decrypt_to_ram_workspace(
    source_backend,
    source_path: str,
    passphrase: str,
    label: str | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> tuple[RamFsSession, str]:
    """Decrypt an ``.axenc`` blob and place the cleartext into a
    fresh RamFS workspace; never lands on disk.

    Returns ``(session, path_in_session)`` so callers can hand the
    pair to a UI pane that opens the RamFsSession and navigates to
    the cleartext path. The caller owns the session — closing it
    discards the cleartext bytes deterministically.

    The label defaults to the source path's basename so the user
    sees something like ``RAM:report-2026.pdf`` in the pane title.

    Capacity guards apply: the cleartext size must fit under
    ``max_bytes`` and not violate the system-memory reserve.
    """
    from core.encrypted_overlay import read_encrypted
    cleartext = read_encrypted(source_backend, source_path, passphrase)
    base = posixpath.basename(source_path) or "blob"
    # Strip the .axenc suffix so the filename in the RAM pane reads
    # like the original.
    if base.lower().endswith(".axenc"):
        base = base[: -len(".axenc")]
    session = RamFsSession(
        label=(label or base),
        max_bytes=max_bytes,
    )
    target = "/" + base
    with session.open_write(target) as f:
        f.write(cleartext)
    return session, target
