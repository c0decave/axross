"""Helpers for writing sensitive data (OAuth tokens, secrets) to disk safely.

Key guarantees:

* The file is never world-readable at any point, including the moment the
  OS creates the inode. This avoids a TOCTOU window between ``open`` and a
  follow-up ``chmod``.
* Writes are atomic: data lands in a sibling temp file and is renamed into
  place. A crash mid-write cannot truncate a previously-valid token file.
* The parent directory is created with ``0o700`` if it does not exist and
  is owned by the current user.
"""

from __future__ import annotations

import logging
import os
import shutil
import stat
import tempfile
import threading
import time
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

from core import posix_compat

try:
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - Windows fallback
    _fcntl = None

log = logging.getLogger(__name__)

_FILE_MODE = 0o600
_DIR_MODE = 0o700


def data_file_path(
    name: str,
    override_var: str,
    *,
    environ: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> Path:
    """Where the axross data file *name* (an index database) lives.

    1. ``$<override_var>`` when it is set and not empty;
    2. ``$XDG_DATA_HOME/axross/<name>`` when ``XDG_DATA_HOME`` is an
       absolute path (the XDG spec ignores a relative one) - unless the file
       is missing there while one exists at the old place, which then stays
       in use, so an index made before the variable was honoured is not
       orphaned;
    3. ``~/.local/share/axross/<name>``, the XDG default.
    """
    env = os.environ if environ is None else environ
    home = Path.home() if home is None else Path(home)
    override = env.get(override_var, "")
    if override.strip():
        return Path(override)
    legacy = home / ".local" / "share" / "axross" / name
    base = env.get("XDG_DATA_HOME", "").strip()
    if not base or not os.path.isabs(base):
        return legacy
    chosen = Path(base) / "axross" / name
    if chosen != legacy and not chosen.exists() and legacy.exists():
        return legacy
    return chosen


def ensure_private_dir(path: str) -> None:
    """Create *path* with ``0o700`` permissions if missing.

    The final directory must be a real directory (not a symlink) owned
    by the current user. Secret stores should fail closed rather than
    writing OAuth tokens into a path an attacker can redirect.
    """
    if not path:
        return
    path = os.path.abspath(path)
    if not os.path.lexists(path):
        os.makedirs(path, mode=_DIR_MODE, exist_ok=True)

    try:
        lst = os.lstat(path)
        if stat.S_ISLNK(lst.st_mode):
            raise OSError(f"secret directory must not be a symlink: {path}")
        if not stat.S_ISDIR(lst.st_mode):
            raise NotADirectoryError(path)

        st = os.stat(path)
        uid_fn = getattr(os, "geteuid", None) or getattr(os, "getuid", None)
        if uid_fn is not None and st.st_uid != uid_fn():
            raise PermissionError(f"secret directory {path!r} is not owned by the current user")
        # Only tighten perms if the dir is not already stricter.
        if (st.st_mode & 0o777) & ~_DIR_MODE:
            os.chmod(path, _DIR_MODE)
    except OSError as exc:
        log.warning("Could not secure secret directory %s: %s", path, exc)
        raise


def write_secret_file(path: str, data: str | bytes) -> None:
    """Atomically write *data* to *path* with ``0o600`` permissions.

    Raises :class:`OSError` if the write or rename fails. The temporary
    file is cleaned up on failure.
    """
    parent = os.path.dirname(os.path.abspath(path))
    ensure_private_dir(parent)

    if isinstance(data, str):
        payload = data.encode("utf-8")
    else:
        payload = data

    # Create temp file in the same dir so ``os.replace`` stays on one FS.
    fd, tmp_path = tempfile.mkstemp(prefix=".", suffix=".tmp", dir=parent or None)
    try:
        try:
            posix_compat.fchmod_private(fd, _FILE_MODE)
        except OSError as exc:
            # Windows has no fchmod — fall back to chmod on the path.
            log.debug("fchmod unavailable on %s: %s", tmp_path, exc)
            try:
                os.chmod(tmp_path, _FILE_MODE)
            except OSError as chmod_exc:
                log.warning(
                    "Could not set 0o600 on temp secret file %s: %s",
                    tmp_path,
                    chmod_exc,
                )
        with os.fdopen(fd, "wb") as fh:
            fd = -1  # ownership transferred to fh
            fh.write(payload)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError as exc:
                # Some filesystems (tmpfs on certain kernels) may reject fsync.
                log.debug("fsync not honored for %s: %s", tmp_path, exc)
        os.replace(tmp_path, path)
        log.debug("Secret written to %s (mode=0o600)", path)
    except BaseException:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def adopt_legacy_secret_file(path: str, legacy: str | None, belongs) -> bool:
    """Move the shared *legacy* token file to *path* when it is this
    profile's: *path* does not exist yet and ``belongs(text)`` says the
    legacy content was issued to the profile's OAuth client.

    A legacy file of another client stays where it is, for the profile
    it belongs to. Returns True when the file was moved.
    """
    if not legacy or os.path.lexists(path) or not os.path.isfile(legacy):
        return False
    try:
        with open(legacy, encoding="utf-8") as fh:
            text = fh.read()
    except (OSError, UnicodeDecodeError) as exc:
        log.warning("Could not read the shared token file %s: %s", legacy, exc)
        return False
    try:
        mine = bool(belongs(text))
    except (ValueError, TypeError, AttributeError):
        mine = False
    if not mine:
        return False
    ensure_private_dir(os.path.dirname(os.path.abspath(path)))
    os.replace(legacy, path)
    try:
        os.chmod(path, _FILE_MODE)
    except OSError as exc:
        log.debug("Could not chmod %s: %s", path, exc)
    log.info("Token file %s moved to the profile's own %s", legacy, path)
    return True


def keep_unreadable_copy(path: str | os.PathLike) -> bool:
    """Copy a store file its loader could not take in completely next to
    it, as ``<name>.unreadable-<time>-<hex>`` (``0o600``), before a save
    replaces it with only what is in memory.

    Returns True when the copy was made or there is no file to keep, and
    False when the copy could not be made: the caller must not save then,
    or the file's content is lost.
    """
    src = os.fspath(path)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup = f"{src}.unreadable-{stamp}-{uuid.uuid4().hex[:8]}"
    try:
        source = open(src, "rb")  # noqa: SIM115 - closed below
    except FileNotFoundError:
        return True
    except OSError as exc:
        log.error("Could not keep a copy of the unreadable %s: %s", src, exc)
        return False
    with source:
        try:
            fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _FILE_MODE)
        except OSError as exc:
            log.error("Could not keep a copy of the unreadable %s: %s", src, exc)
            return False
        try:
            with os.fdopen(fd, "wb") as dst:
                shutil.copyfileobj(source, dst)
                dst.flush()
                os.fsync(dst.fileno())
        except OSError as exc:
            log.error("Could not keep a copy of the unreadable %s: %s", src, exc)
            try:
                os.unlink(backup)
            except OSError:
                pass
            return False
    log.warning("Kept the unreadable %s as %s", src, backup)
    return True


def file_mode(path: str) -> int:
    """Return the POSIX permission bits (0o777 mask) of *path*."""
    return os.stat(path).st_mode & 0o777


class _StoreLock:
    """Per-path in-process lock; ``depth`` counts nested entries of the
    owning thread so only the outermost one takes the file lock (a second
    ``flock`` on a new descriptor would wait for the first forever)."""

    def __init__(self) -> None:
        self.rlock = threading.RLock()
        self.depth = 0


_STORE_LOCKS: dict[str, _StoreLock] = {}
_STORE_LOCKS_GUARD = threading.Lock()


@contextmanager
def locked_store_update(path: str | os.PathLike) -> Iterator[None]:
    """Serialize a read-merge-write of the store file *path* across the
    threads of this process and across processes.

    Holds a per-path in-process lock plus, where ``fcntl`` exists, an
    exclusive ``flock`` on ``<path>.lock`` (created ``0o600``). A lock
    file that cannot be opened (read-only config dir) degrades to the
    in-process lock: the write that follows fails on its own then.
    """
    key = os.path.abspath(os.fspath(path))
    with _STORE_LOCKS_GUARD:
        entry = _STORE_LOCKS.setdefault(key, _StoreLock())
    with entry.rlock:
        lock_fd = -1
        entry.depth += 1
        try:
            if _fcntl is not None and entry.depth == 1:
                try:
                    os.makedirs(os.path.dirname(key), mode=_DIR_MODE, exist_ok=True)
                    lock_fd = os.open(key + ".lock", os.O_RDWR | os.O_CREAT, _FILE_MODE)
                    _fcntl.flock(lock_fd, _fcntl.LOCK_EX)
                except OSError as exc:
                    log.debug("No file lock for %s: %s", key, exc)
                    if lock_fd != -1:
                        os.close(lock_fd)
                        lock_fd = -1
            yield
        finally:
            entry.depth -= 1
            if lock_fd != -1:
                try:
                    _fcntl.flock(lock_fd, _fcntl.LOCK_UN)
                except OSError as exc:
                    log.debug("Could not unlock %s: %s", key, exc)
                os.close(lock_fd)
