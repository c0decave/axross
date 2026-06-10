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
import stat
import tempfile

log = logging.getLogger(__name__)

_FILE_MODE = 0o600
_DIR_MODE = 0o700


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
            os.fchmod(fd, _FILE_MODE)
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


def file_mode(path: str) -> int:
    """Return the POSIX permission bits (0o777 mask) of *path*."""
    return os.stat(path).st_mode & 0o777
