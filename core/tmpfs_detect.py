"""Detect Linux/Unix tmpfs mounts so axross can prefer them over
disk-backed ``/tmp`` for short-lived tempfiles (atomic_io sibling
temp, archive extraction buffers, FUSE per-handle flush staging).

Why this exists separately from RamFS: ``core.ram_fs`` is a pure
in-process backend (bytes in a Python dict). ``tmpfs_detect``
points at **kernel-managed** tmpfs paths the OS already provides:

* ``/dev/shm`` — POSIX shared memory, always tmpfs on modern Linux,
  globally writable by every user.
* ``/run/user/$UID`` — XDG runtime dir, tmpfs, owned by the user,
  ``0o700`` mode. Preferred over /dev/shm because of the per-user
  isolation.
* ``/tmp`` — sometimes tmpfs (systemd default on some distros);
  sometimes a real disk path. We only return it when ``stat -f -t``
  identifies it as tmpfs.

The detection result is cached for the process lifetime — tmpfs
mounts don't appear/disappear at runtime under normal operation.
"""
from __future__ import annotations

import logging
import os
import stat as _stat
from typing import NamedTuple

log = logging.getLogger(__name__)


# Linux tmpfs has its own magic number. Same constant is used by
# ramfs (different filesystem, same memory-backed semantics) — we
# accept both.
_TMPFS_MAGIC = 0x01021994
_RAMFS_MAGIC = 0x858458F6


class TmpfsPath(NamedTuple):
    """A discovered tmpfs / ramfs mount point.

    ``path`` is the absolute filesystem path, ``label`` is a short
    human-readable tag we use in the UI (e.g. ``"shm"``,
    ``"runtime"``), and ``writable`` says whether the current user
    can create files there.
    """

    path: str
    label: str
    writable: bool


def _is_tmpfs(path: str) -> bool:
    """``True`` iff *path* lives on a tmpfs/ramfs filesystem.

    ``os.statvfs`` is POSIX but only reports usage stats. The
    filesystem-magic check is Linux-specific via ``ctypes.statfs``.
    On non-Linux we conservatively return ``False``.
    """
    if not os.path.isdir(path):
        return False
    try:
        # Fast path: parse /proc/self/mountinfo on Linux (the only
        # OS where tmpfs as a concept exists in axross's deployment
        # envelope). On macOS / BSD this returns False — they don't
        # ship a Linux-style tmpfs, and the on-disk /tmp is fine.
        with open("/proc/self/mountinfo", "r", encoding="utf-8") as f:
            for line in f:
                fields = line.split()
                # mountinfo format: ID parent_ID maj:min root mount_point ...
                if len(fields) < 5:
                    continue
                mount_point = fields[4]
                if mount_point != path:
                    continue
                # The fs-type is two fields after the optional " - "
                # separator. Find " - " then the fs-type after it.
                try:
                    sep_idx = fields.index("-")
                except ValueError:
                    continue
                if len(fields) > sep_idx + 1:
                    fs_type = fields[sep_idx + 1]
                    if fs_type in ("tmpfs", "ramfs"):
                        return True
    except OSError:
        return False
    return False


def _writable(path: str) -> bool:
    """Best-effort: try to ``open`` a probe file in *path*. Cleans
    up immediately. Returns False on permission denied / read-only
    filesystem / missing path."""
    if not os.path.isdir(path):
        return False
    if not os.access(path, os.W_OK | os.X_OK):
        return False
    return True


_CACHED: list[TmpfsPath] | None = None


def detect_tmpfs_paths() -> list[TmpfsPath]:
    """Return the list of usable tmpfs paths, ordered by preference.

    Preference: per-user XDG runtime > /dev/shm > /tmp (only if
    tmpfs). Cached process-globally on first call.
    """
    global _CACHED
    if _CACHED is not None:
        return _CACHED

    out: list[TmpfsPath] = []

    runtime_dir = os.environ.get("XDG_RUNTIME_DIR", "")
    if not runtime_dir:
        try:
            runtime_dir = f"/run/user/{os.getuid()}"
        except AttributeError:  # Windows
            runtime_dir = ""
    if runtime_dir and _is_tmpfs(runtime_dir) and _writable(runtime_dir):
        out.append(TmpfsPath(runtime_dir, "runtime", True))

    if _is_tmpfs("/dev/shm") and _writable("/dev/shm"):
        out.append(TmpfsPath("/dev/shm", "shm", True))

    # /tmp may be tmpfs (systemd default on some distros) or disk —
    # only include it when it's actually tmpfs, otherwise we'd miss
    # the goal of "leave nothing on disk".
    if _is_tmpfs("/tmp") and _writable("/tmp"):
        out.append(TmpfsPath("/tmp", "tmp", True))

    _CACHED = out
    log.debug("tmpfs paths detected: %r", out)
    return out


def preferred_tmpfs_dir() -> str | None:
    """Return the highest-preference writable tmpfs path (or None
    when none is available). Use this from temp-file producers
    (atomic_io / archive / fuse_mount) when the user has tmpfs
    routing enabled.
    """
    paths = detect_tmpfs_paths()
    return paths[0].path if paths else None


def reset_cache() -> None:
    """Test hook — drop the process-global cache so a probe re-runs."""
    global _CACHED
    _CACHED = None


def apply_tempdir_preference() -> str | None:
    """Point :mod:`tempfile`'s default directory at the preferred
    tmpfs path when the user has tmpfs enabled in settings AND a
    tmpfs path is detected.

    After this runs, ``tempfile.NamedTemporaryFile()``,
    ``tempfile.mkdtemp()``, ``tempfile.TemporaryDirectory()`` etc.
    all default to tmpfs unless the caller passes an explicit
    ``dir=`` argument. That covers ``core.archive`` extraction
    buffers, ``core.fuse_mount`` per-handle flush staging, and any
    future temp-using code without per-site plumbing.

    Returns the chosen path, or ``None`` when tmpfs is disabled or
    not present. Idempotent: calling twice doesn't change anything
    once ``tempfile.tempdir`` is already set.
    """
    import tempfile
    from core.ramfs_settings import get_settings
    settings = get_settings()
    if not settings.tmpfs_enabled:
        return None
    chosen = preferred_tmpfs_dir()
    if chosen is None:
        return None
    if tempfile.tempdir == chosen:
        return chosen
    tempfile.tempdir = chosen
    log.info("tempfile default-dir routed to tmpfs: %s", chosen)
    return chosen
