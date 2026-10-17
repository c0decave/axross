from __future__ import annotations

import errno
import logging
import os
import shutil
import stat as stat_module
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import IO

from core.backend import SessionLifecycle
from models.file_item import FileItem

try:
    import grp
    import pwd
except ImportError:  # Windows: no user database, st_uid/st_gid say nothing
    grp = pwd = None  # type: ignore[assignment]

# uid / gid -> name, cached. With the stock Arch nsswitch line
# "group: files [SUCCESS=merge] systemd" every grp.getgrgid also asks
# systemd-userdb (~0.56 ms), and a listing called it once per entry.
# The TTL lets a renamed user or group show up without a restart.
NAME_CACHE_TTL = 60.0
NAME_CACHE_MAX = 1024
_owner_cache: dict[int, tuple[float, str]] = {}
_group_cache: dict[int, tuple[float, str]] = {}
_name_lock = threading.Lock()


def _cached_name(cache: dict, ident: int, lookup) -> str:
    now = time.monotonic()
    with _name_lock:
        hit = cache.get(ident)
        if hit is not None and now - hit[0] < NAME_CACHE_TTL:
            return hit[1]
    try:
        name = lookup(ident)
    except (KeyError, OverflowError, TypeError):
        name = str(ident)
    with _name_lock:
        if len(cache) >= NAME_CACHE_MAX:
            cache.clear()
        cache[ident] = (now, name)
    return name


def owner_name(uid: int) -> str:
    """User name for *uid*, or the number when it has none ("" on Windows)."""
    if pwd is None:
        return ""
    return _cached_name(_owner_cache, uid, lambda i: pwd.getpwuid(i).pw_name)


def group_name(gid: int) -> str:
    """Group name for *gid*, or the number when it has none ("" on Windows)."""
    if grp is None:
        return ""
    return _cached_name(_group_cache, gid, lambda i: grp.getgrgid(i).gr_name)


def clear_name_cache() -> None:
    with _name_lock:
        _owner_cache.clear()
        _group_cache.clear()


log = logging.getLogger(__name__)

# The errors that say nothing is at a path: it is missing, a file stands
# where a folder of the path should be, or the name is one the
# filesystem cannot hold.
_ABSENT_ERRNOS = frozenset({errno.ENOENT, errno.ENOTDIR, errno.ENAMETOOLONG})


def entry_stat(path: str, *, follow: bool = False) -> os.stat_result | None:
    """``os.lstat`` (``os.stat`` with ``follow``) of *path*, or None when
    nothing is there.

    ``os.path.lexists`` / ``isdir`` answer False for EVERY error: a soft
    NFS mount that timed out, a stale file handle, a FUSE mount whose
    transport is gone, a folder without search permission. exists() and
    is_dir() must not: the no-clobber checks take "absent" as the
    go-ahead to write. Any other failure is raised.
    """
    try:
        return os.stat(path) if follow else os.lstat(path)
    except OSError as exc:
        if exc.errno in _ABSENT_ERRNOS:
            return None
        raise


class LocalFS(SessionLifecycle):
    """Local filesystem backend implementing the FileBackend protocol."""

    # POSIX filesystems support both link flavours; the UI uses these
    # flags to decide whether to show the "New Symlink…" / "New
    # Hardlink…" context-menu entries.
    supports_symlinks = True
    supports_hardlinks = True
    # A POSIX kernel never splits a name on a backslash: "a\\b.txt" is one
    # legal name there (core.path_policy). On Windows it is a separator.
    literal_backslash_in_names = os.sep == "/"

    # Walking a directory tree here is local syscalls, not network round
    # trips, so the UI may total up a directory's size without asking
    # first. Every other backend leaves this False and gets an explicit
    # "Calculate" button instead — the safe default, since one recursive
    # listing over SFTP or S3 is unbounded work.
    has_cheap_recursive_walk = True

    @property
    def name(self) -> str:
        return "Local"

    def list_dir(self, path: str) -> list[FileItem]:
        items: list[FileItem] = []
        try:
            with os.scandir(path) as it:
                for entry in it:
                    try:
                        items.append(self._entry_to_item(entry))
                    except OSError as e:
                        log.warning("Cannot stat %s: %s", entry.path, e)
        except OSError as e:
            log.error("Cannot list %s: %s", path, e)
            raise
        return items

    def stat(self, path: str) -> FileItem:
        st = os.lstat(path)
        name = os.path.basename(path) or path
        return self._stat_to_item(name, st)

    def is_dir(self, path: str) -> bool:
        """A folder itself, not a link to one. False only when nothing is
        there; a failed lstat is an OSError (see entry_stat)."""
        st = entry_stat(path)
        return st is not None and stat_module.S_ISDIR(st.st_mode)

    def exists(self, path: str) -> bool:
        """The entry itself (a dangling link is there). False only when
        nothing is there; a failed lstat is an OSError."""
        try:
            return entry_stat(path) is not None
        except ValueError:
            return False  # an embedded NUL: no name on disk has one

    def mkdir(self, path: str) -> None:
        os.makedirs(path, exist_ok=True)

    def remove(self, path: str, recursive: bool = False) -> None:
        st = os.lstat(path)
        if stat_module.S_ISLNK(st.st_mode):
            os.remove(path)
        elif stat_module.S_ISDIR(st.st_mode):
            if recursive:
                shutil.rmtree(path)
            else:
                os.rmdir(path)
        else:
            os.remove(path)

    def rename(self, src: str, dst: str) -> None:
        os.rename(src, dst)

    def open_read(self, path: str) -> IO[bytes]:
        """Open a regular file (through symlinks) for reading.

        A named pipe without a writer blocks a plain ``open()`` forever
        (and with it the only transfer worker); a socket, a device or a
        folder is no file content either. The node is opened non-blocking
        and refused unless it is a regular file.
        """
        nonblock = getattr(os, "O_NONBLOCK", 0)
        if not nonblock:  # Windows: no FIFOs on a plain filesystem
            return open(path, "rb")
        fd = os.open(path, os.O_RDONLY | nonblock | getattr(os, "O_CLOEXEC", 0))
        try:
            mode = os.fstat(fd).st_mode
            if stat_module.S_ISDIR(mode):
                raise IsADirectoryError(errno.EISDIR, os.strerror(errno.EISDIR), path)
            if not stat_module.S_ISREG(mode):
                from core.file_type import _special_description

                raise OSError(
                    errno.EINVAL,
                    f"not a regular file ({_special_description(mode)}); not read",
                    path,
                )
            os.set_blocking(fd, True)
            return os.fdopen(fd, "rb")
        except BaseException:
            os.close(fd)
            raise

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        return open(path, "ab" if append else "wb")

    def normalize(self, path: str) -> str:
        return os.path.normpath(os.path.abspath(path))

    def separator(self) -> str:
        return os.sep

    def join(self, *parts: str) -> str:
        return os.path.join(*parts)

    def parent(self, path: str) -> str:
        return str(Path(path).parent)

    def home(self) -> str:
        return str(Path.home())

    def chmod(self, path: str, mode: int) -> None:
        os.chmod(path, mode)

    def set_modified(self, path: str, mtime: float) -> None:
        """Set *path*'s modification time (epoch seconds); the access time
        stays. Used to give a copy its source's time."""
        os.utime(path, (os.stat(path).st_atime, mtime))

    def readlink(self, path: str) -> str:
        return os.readlink(path)

    def symlink(self, target: str, link_path: str) -> None:
        """Create a symlink at *link_path* pointing to *target*.

        ``target`` may be absolute or relative. We do NOT pre-validate
        that *target* exists — dangling symlinks are a legitimate
        POSIX pattern (``ln -s /future/path foo`` before creating
        the target is common). The OS will raise :class:`OSError` on
        invalid paths or when *link_path* already exists."""
        os.symlink(target, link_path)

    def hardlink(self, target: str, link_path: str) -> None:
        """Create a hardlink at *link_path* pointing at the same inode
        as *target*. Both paths must live on the same filesystem —
        :class:`OSError` (EXDEV) when they don't, which the UI
        surfaces as a clear "cross-device link" message."""
        os.link(target, link_path)

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        usage = shutil.disk_usage(path)
        return (usage.total, usage.used, usage.free)

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError(f"{type(self).__name__} does not expose file version history")

    def copy(self, src: str, dst: str) -> None:
        """Server-side copy via shutil.copy2 (preserves timestamps)."""
        shutil.copy2(src, dst)

    def local_path(self, path: str) -> str:
        """The path on this machine's filesystem (see core.storage_identity)."""
        return os.path.abspath(path)

    def same_file(self, a: str, b: str) -> bool:
        """True when *a* and *b* name one file — hardlink, bind mount or a
        path through a symlink. The duplicate finder needs this to tell a
        second copy from a second name for the same bytes."""
        return os.path.samefile(a, b)

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        """Stream-hash the file. No native shortcut on a plain mount."""
        import hashlib

        try:
            h = hashlib.new(algorithm)
        except ValueError as exc:
            raise OSError(f"Unsupported checksum algorithm: {algorithm}") from exc
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return f"{algorithm}:{h.hexdigest()}"

    def _entry_to_item(self, entry: os.DirEntry) -> FileItem:
        st = entry.stat(follow_symlinks=False)
        return self._stat_to_item(entry.name, st, full_path=entry.path)

    def _stat_to_item(self, name: str, st: os.stat_result, full_path: str = "") -> FileItem:
        is_link = stat_module.S_ISLNK(st.st_mode)
        is_dir = stat_module.S_ISDIR(st.st_mode)
        link_target = ""
        if is_link and full_path:
            try:
                link_target = os.readlink(full_path)
            except OSError:
                pass

        owner = owner_name(st.st_uid) if hasattr(st, "st_uid") else ""
        group = group_name(st.st_gid) if hasattr(st, "st_gid") else ""

        accessed = datetime.fromtimestamp(st.st_atime) if getattr(st, "st_atime", 0) else None
        created = None
        # On Linux st_ctime is inode-change-time; on macOS/Windows it
        # is birthtime. Prefer explicit birthtime when the platform
        # exposes it.
        birth = getattr(st, "st_birthtime", 0)
        if birth:
            created = datetime.fromtimestamp(birth)
        return FileItem(
            name=name,
            size=st.st_size,
            modified=datetime.fromtimestamp(st.st_mtime),
            permissions=st.st_mode & 0o7777,
            is_dir=is_dir,
            is_link=is_link,
            link_target=link_target,
            owner=owner,
            group=group,
            accessed=accessed,
            created=created,
        )
