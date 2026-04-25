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
import tempfile

log = logging.getLogger(__name__)

_FILE_MODE = 0o600
_DIR_MODE = 0o700


def ensure_private_dir(path: str) -> None:
    """Create *path* with ``0o700`` permissions if missing.

    If the directory already exists, permissions are tightened to ``0o700``
    only when the current process owns it. This avoids clobbering shared
    system directories that a packager may have pre-created.
    """
    if not path:
        return
    created = False
    if not os.path.isdir(path):
        os.makedirs(path, mode=_DIR_MODE, exist_ok=True)
        created = True
    try:
        st = os.stat(path)
        if created or st.st_uid == os.geteuid():
            # Only tighten perms if the dir is not already stricter.
            if (st.st_mode & 0o777) & ~_DIR_MODE:
                os.chmod(path, _DIR_MODE)
    except OSError as exc:
        log.warning("Could not tighten permissions on %s: %s", path, exc)


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
    fd, tmp_path = tempfile.mkstemp(
        prefix=".", suffix=".tmp", dir=parent or None
    )
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
                    tmp_path, chmod_exc,
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
