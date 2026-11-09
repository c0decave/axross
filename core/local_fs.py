from __future__ import annotations

import errno
import logging
import os
import shutil
import stat as stat_module
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import IO

from core import removal_cancel
from core.backend import SessionLifecycle
from models.file_item import FileItem, local_time

_from_timestamp = datetime.fromtimestamp

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


#: Per thread, while one LocalFS.list_dir runs: (uid -> owner, gid -> group)
#: of that listing - a dict lookup per entry instead of the shared cache's
#: lock and clock (two per entry: ~1 us of every entry's ~5 us).
_listing = threading.local()


def _cached_name(cache: dict, ident: int, lookup) -> str:
    now = time.monotonic()
    # A dict read is atomic: the lock guards the writes (clear, then set).
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


#: The stat fields that can flag an entry hidden on this platform (none on
#: Linux: a listing there skips the check for real stat results).
_HIDDEN_FIELDS_HERE = tuple(
    name for name in ("st_file_attributes", "st_flags") if hasattr(os.stat_result, name))


def stat_hidden_flag(st) -> bool:
    """True when the stat result itself marks the entry hidden: Windows
    ``st_file_attributes & FILE_ATTRIBUTE_HIDDEN`` or macOS / BSD
    ``st_flags & UF_HIDDEN`` (``chflags hidden``). Linux has neither field;
    a missing or unreadable field is "not flagged", never an error. Reads
    only the stat the listing already made - no extra system call."""
    for field_name, bit in (
        ("st_file_attributes", stat_module.FILE_ATTRIBUTE_HIDDEN),
        ("st_flags", stat_module.UF_HIDDEN),
    ):
        value = getattr(st, field_name, 0)
        if isinstance(value, int) and value & bit:
            return True
    return False


# The errors that say nothing is at a path: it is missing, a file stands
# where a folder of the path should be, or the name is one the
# filesystem cannot hold.
_ABSENT_ERRNOS = frozenset({errno.ENOENT, errno.ENOTDIR, errno.ENAMETOOLONG})


def copy_file_onto(src: str, dst: str) -> None:
    """Copy the file *src* to the path *dst* (timestamps kept), replacing
    a file there. ``shutil.copy2`` puts *src* INTO *dst* when *dst* is a
    folder or a link to one and reports success - copy() then answered
    "done" while *dst* was still a folder; that is an IsADirectoryError
    now, as the shell backends' ``cp`` refuses it (copy_command)."""
    if os.path.isdir(dst):
        raise IsADirectoryError(errno.EISDIR, "copy target is a folder", dst)
    shutil.copy2(src, dst)


def unstattable_item(entry: os.DirEntry, error: OSError) -> FileItem:
    """An entry the listing names but lstat refuses (EACCES on a mount
    point the user may not enter, ...). Shown, never dropped: a recursive
    delete or move over a listing without it would report success while the
    entry stays behind. Whether it is a folder comes from the directory
    entry's type (d_type), which needs no stat."""
    try:
        is_dir = entry.is_dir(follow_symlinks=False)
    except OSError:
        is_dir = False
    try:
        is_link = entry.is_symlink()
    except OSError:
        is_link = False
    return FileItem(
        name=entry.name,
        is_dir=is_dir,
        is_link=is_link,
        stat_error=error.strerror or str(error),
    )


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


#: renameat2(2)'s flag: fail with EEXIST instead of replacing the target.
_RENAME_NOREPLACE = 1
_AT_FDCWD = -100
_renameat2_fn: list = []


def _renameat2():
    """libc's renameat2, or None (not Linux, an old libc)."""
    if not _renameat2_fn:
        fn = None
        if sys.platform.startswith("linux"):
            try:
                import ctypes

                fn = ctypes.CDLL(None, use_errno=True).renameat2
                fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
                               ctypes.c_uint]
                fn.restype = ctypes.c_int
            except (AttributeError, OSError):
                fn = None
        _renameat2_fn.append(fn)
    return _renameat2_fn[0]


def rename_no_replace(src: str, dst: str, *, src_dir_fd: int | None = None,
                      dst_dir_fd: int | None = None) -> None:
    """Rename *src* to *dst* unless *dst* exists - FileExistsError then,
    also for a *dst* that appears while this runs, where the system can
    tell: renameat2(RENAME_NOREPLACE) on Linux; a hard link and an unlink
    for a file elsewhere (or on a file system without renameat2's flag);
    Windows' rename never replaces. Only where neither works (a folder
    off Linux, a file system without hard links) the target is checked
    and then renamed onto, as before. A plain ``os.rename`` replaces a
    file that appeared after the caller's check."""
    if os.name == "nt":
        os.rename(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)
        return
    fn = _renameat2()
    if fn is not None:
        import ctypes

        result = fn(_AT_FDCWD if src_dir_fd is None else src_dir_fd, os.fsencode(src),
                    _AT_FDCWD if dst_dir_fd is None else dst_dir_fd, os.fsencode(dst),
                    _RENAME_NOREPLACE)
        if result == 0:
            return
        err = ctypes.get_errno()
        if err not in (errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP, errno.ENOTSUP):
            raise OSError(err, os.strerror(err), src, None, dst)
    st = os.stat(src, dir_fd=src_dir_fd, follow_symlinks=False)
    if not stat_module.S_ISDIR(st.st_mode):
        try:
            os.link(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd,
                    follow_symlinks=False)
        except FileExistsError:
            raise
        except (OSError, NotImplementedError) as exc:
            log.debug("no-replace rename %s -> %s by a hard link failed: %s", src, dst, exc)
        else:
            os.unlink(src, dir_fd=src_dir_fd)
            return
    try:
        os.stat(dst, dir_fd=dst_dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), dst)
    os.rename(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)


_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_BINARY = getattr(os, "O_BINARY", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


def own_file_problem(st: os.stat_result) -> str:
    """Why the file *st* describes is not one this user alone writes ("" =
    it is): a regular file of this user with one name. A symlink, a
    device or FIFO, another user's file or a second hard link put in place
    of a partial in a folder others can write to would take the bytes meant
    for it (review round 9)."""
    if not stat_module.S_ISREG(st.st_mode):
        return "it is not a regular file"
    from core.posix_compat import effective_uid

    uid = effective_uid()
    if uid is not None and st.st_uid != uid:
        return "it belongs to another user"
    if st.st_nlink != 1:
        return "it has other hard links"
    return ""


def create_private_file(path: str, mode: int | None = None) -> IO[bytes]:
    """A NEW file at *path*, open for writing: FileExistsError when anything
    (a symlink too) is there already. With *mode* it is created 0600 and
    given *mode* through its descriptor before a byte is written - never
    readable by more than *mode* allows, not for a moment (a 0600 key copied
    through a 0644 temp file could be opened by anyone meanwhile); without,
    it gets a new file's default mode (0666 less the umask). The handle
    writes into that file whatever its name is made to point to later."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC | _O_BINARY
    fd = os.open(path, flags, 0o666 if mode is None else 0o600)
    try:
        if mode is not None:
            from core.posix_compat import fchmod_private

            try:
                fchmod_private(fd, mode & 0o7777)
            except OSError as exc:  # vfat, a FUSE mount: the file stays 0600
                log.debug("could not set mode %04o on %s: %s", mode, path, exc)
        return os.fdopen(fd, "wb")
    except BaseException:
        os.close(fd)
        raise


def open_own_partial(path: str, *, expect_size: int | None = None) -> IO[bytes]:
    """The existing file *path*, open to append to it - only when it is
    :func:`own_file_problem`-clean and (with *expect_size*) still as long
    as when it was looked at. A symbolic link there is never followed and
    a FIFO never blocks the open: PermissionError either way, nothing
    written. Keep writing through the handle; never reopen the path (a
    name in a shared folder can be swapped for a link at any moment)."""
    flags = os.O_WRONLY | os.O_APPEND | _O_NOFOLLOW | _O_CLOEXEC | _O_BINARY | _O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK, errno.ENXIO):
            raise PermissionError(errno.EPERM, f"{path} is not a regular file of this user "
                                  "(a link or a pipe was put in its place); not written",
                                  path) from exc
        raise
    try:
        st = os.fstat(fd)
        problem = own_file_problem(st)
        if not problem and expect_size is not None and st.st_size != expect_size:
            problem = f"it holds {st.st_size} bytes, not the {expect_size} compared"
        if problem:
            raise PermissionError(errno.EPERM, f"{path}: {problem}; not written", path)
        if _O_NONBLOCK:
            os.set_blocking(fd, True)
        return os.fdopen(fd, "ab")
    except BaseException:
        os.close(fd)
        raise


def same_entry(path: str, st: os.stat_result) -> bool:
    """Whether *path* (not followed) still names the file *st* describes."""
    try:
        now = os.lstat(path)
    except OSError:
        return False
    return os.path.samestat(now, st)


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
        outer = getattr(_listing, "names", None)
        _listing.names = ({}, {})  # owner / group names of this listing (see _listing)
        try:
            with os.scandir(path) as it:
                append, to_item = items.append, self._entry_to_item
                for entry in it:
                    try:
                        append(to_item(entry))
                    except FileNotFoundError:
                        # Removed between readdir and lstat (a cache, a
                        # build): gone, not a "?" row - a folder copy failed
                        # a job for it and the pane showed a ghost.
                        log.debug("Gone while listed: %s", entry.path)
                    except OSError as e:
                        log.warning("Cannot stat %s: %s", entry.path, e)
                        append(unstattable_item(entry, e))
        except OSError as e:
            log.error("Cannot list %s: %s", path, e)
            raise
        finally:
            _listing.names = outer
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
                # shutil.rmtree, stoppable between entries by the pane's Cancel.
                removal_cancel.rmtree(path)
            else:
                os.rmdir(path)
        else:
            os.remove(path)

    def rename(self, src: str, dst: str) -> None:
        os.rename(src, dst)

    def rename_no_replace(self, src: str, dst: str) -> None:
        """:meth:`rename` that refuses an existing *dst* (FileExistsError),
        also one that appears meanwhile (see :func:`rename_no_replace`).
        Where :meth:`rename` is replaced (a subclass, a stand-in) the
        system call would go around it: then checked, then that rename."""
        if getattr(self.rename, "__func__", None) is not LocalFS.rename:
            if entry_stat(dst) is not None:
                raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), dst)
            self.rename(src, dst)
            return
        rename_no_replace(src, dst)

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

    def private_writes(self) -> bool:
        """Whether :func:`create_private_file` and :func:`open_own_partial`
        may stand in for :meth:`open_write` on this backend: only where
        open_write is LocalFS's own (a subclass that confines or redirects
        its writes keeps them)."""
        return getattr(self.open_write, "__func__", None) is _STOCK_OPEN_WRITE

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
        """Server-side copy (timestamps kept); never into a folder *dst*."""
        copy_file_onto(src, dst)

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
        mode = st.st_mode
        is_link = stat_module.S_ISLNK(mode)
        is_dir = stat_module.S_ISDIR(mode)
        link_target = ""
        if is_link and full_path:
            try:
                link_target = os.readlink(full_path)
            except OSError:
                pass

        names = getattr(_listing, "names", None)
        if names is None:
            owner = owner_name(st.st_uid) if hasattr(st, "st_uid") else ""
            group = group_name(st.st_gid) if hasattr(st, "st_gid") else ""
        else:
            owners, groups = names
            uid, gid = getattr(st, "st_uid", None), getattr(st, "st_gid", None)
            owner = owners.get(uid) if uid is not None else ""
            if owner is None:
                owner = owners[uid] = owner_name(uid)
            group = groups.get(gid) if gid is not None else ""
            if group is None:
                group = groups[gid] = group_name(gid)

        # local_time() inlined for the common case (two calls per entry).
        mtime, atime = st.st_mtime, getattr(st, "st_atime", 0)
        try:
            modified = _from_timestamp(mtime)
            accessed = _from_timestamp(atime) if atime else None
        except (ValueError, OverflowError, OSError, TypeError):
            modified = local_time(mtime)
            accessed = local_time(atime) if atime else None
        created = None
        # On Linux st_ctime is inode-change-time; on macOS/Windows it
        # is birthtime. Prefer explicit birthtime when the platform
        # exposes it.
        birth = getattr(st, "st_birthtime", 0)
        if birth:
            created = local_time(birth)
        return FileItem(
            name=name,
            size=st.st_size,
            modified=modified,
            permissions=mode & 0o7777,
            is_dir=is_dir,
            is_link=is_link,
            link_target=link_target,
            owner=owner,
            group=group,
            accessed=accessed,
            created=created,
            attr_hidden=(stat_hidden_flag(st)
                         if _HIDDEN_FIELDS_HERE or type(st) is not os.stat_result else False),
        )


#: LocalFS.open_write as defined here: a backend whose open_write is anything
#: else (a subclass, a patch) keeps it for its temp files (private_writes).
_STOCK_OPEN_WRITE = LocalFS.open_write
