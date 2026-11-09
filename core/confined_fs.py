"""Local file operations that stay beneath their folders, whatever happens
to the path between the check and the use.

The MCP server checks a path as a string (core.mcp_server._enforce_root:
inside the root, no symlink out of it; core.protected_places: no
autostart folder, no shell start file) and then handed the same string to
LocalFS, which opened it again by name. Between the two, a second tool
call of the same client (the HTTP transport and ``tasks/start`` run calls
in threads) could rename a folder of the path away and put a symlink to
``~/.config/autostart`` or to the home folder in its place: write_file
``proj/w1/evil.desktop`` landed in the autostart folder, ``w1/.bash_profile``
became ``~/.bash_profile``, a read of ``w1/id_ed25519`` could return
``~/.ssh/id_ed25519``.

:class:`ConfinedLocalFS` is the LocalFS the server's tools use instead
(when the backend is the plain local one and a root is configured). Every
path is located beneath one of its folders and opened relative to a
descriptor of that folder WITHOUT following any symlink:

* Linux 5.6+: ``openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
  RESOLVE_NO_MAGICLINKS)`` - the kernel refuses a symlink, a ``..`` and a
  magic link anywhere on the way;
* other POSIX systems (and a kernel or seccomp filter without openat2):
  a walk one component at a time, each folder opened with
  ``O_NOFOLLOW | O_DIRECTORY`` relative to the one before (``O_PATH`` where
  it exists, so a folder with only search permission can be passed).

Operations on an entry (create, remove, rename, link, write via a temp
file) run relative to a descriptor of the entry's parent folder:
``os.mkdir/unlink/rmdir/rename/symlink/link(..., dir_fd=...)``. A symlink
that appears in the path after the check makes the operation fail with
PermissionError; it is never followed. The paths the server passes in are
already resolved (``_enforce_root`` answers the symlink-free form), so a
legitimate symlink inside the root still works - it was resolved before.

Windows has no ``dir_fd``: there the class is LocalFS with a check after
each open (the opened file must be the file the path resolves to now, and
that file must lie beneath a folder), and the server serialises its
mutating tool calls (core.mcp_server._MUTATION_LOCK), so its own calls
cannot race each other.
"""

from __future__ import annotations

import contextlib
import ctypes
import dataclasses
import errno
import logging
import os
import platform
import secrets
import stat as stat_module
import sys
import threading
from typing import IO, Callable, Iterable, Iterator

from core.local_fs import LocalFS, _listing, unstattable_item
from core.posix_compat import effective_uid, fchmod_private
from models.file_item import FileItem

log = logging.getLogger(__name__)

_O_PATH = getattr(os, "O_PATH", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)

#: Whether descriptor-relative operations are available (not on Windows).
FD_CONFINED = bool(
    _O_DIRECTORY
    and _O_NOFOLLOW
    and all(
        fn in os.supports_dir_fd
        for fn in (os.open, os.stat, os.mkdir, os.rename, os.unlink, os.rmdir,
                   os.symlink, os.readlink, os.link, os.utime)
    )
    and os.scandir in os.supports_fd
)

#: Flags of a folder opened on the way (search permission is enough with O_PATH).
_DIR_FLAGS = (_O_PATH or os.O_RDONLY) | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC

#: The errors that say a symlink stood in the way (Linux and macOS ELOOP,
#: FreeBSD EMLINK for O_NOFOLLOW) or openat2 saw the path leave its folder.
_LINK_ERRNOS = frozenset({errno.ELOOP, errno.EMLINK, errno.EXDEV})
#: The errors that say nothing is at a path (LocalFS's own set).
_ABSENT_ERRNOS = frozenset({errno.ENOENT, errno.ENOTDIR, errno.ENAMETOOLONG})

# --------------------------------------------------------------- openat2
_RESOLVE_NO_MAGICLINKS = 0x02
_RESOLVE_NO_SYMLINKS = 0x04
_RESOLVE_BENEATH = 0x08
_SYS_OPENAT2 = 437  # the same number on every architecture with the unified table
_UNIFIED_SYSCALL_MACHINES = frozenset({
    "x86_64", "amd64", "i386", "i686", "aarch64", "arm64", "armv7l", "armv6l",
    "riscv64", "ppc64le", "ppc64", "s390x", "loongarch64",
})
_AT_FDCWD = -100


class _OpenHow(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64),
                ("resolve", ctypes.c_uint64)]


_openat2_lock = threading.Lock()
_openat2_fn: list = []  # [callable or None] once probed


def _make_openat2():
    if not sys.platform.startswith("linux"):
        return None
    if platform.machine().lower() not in _UNIFIED_SYSCALL_MACHINES:
        return None
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        syscall = libc.syscall
    except (OSError, AttributeError):
        return None
    syscall.restype = ctypes.c_long
    syscall.argtypes = [ctypes.c_long, ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p,
                        ctypes.c_size_t]

    def openat2(dirfd: int, path: str, flags: int, mode: int) -> int:
        # A mode only with O_CREAT / O_TMPFILE (EINVAL otherwise); O_TMPFILE
        # includes the O_DIRECTORY bit, so it is compared as a whole.
        tmpfile = getattr(os, "O_TMPFILE", 0)
        creates = flags & os.O_CREAT or (tmpfile and flags & tmpfile == tmpfile)
        how = _OpenHow(flags, mode if creates else 0,
                       _RESOLVE_BENEATH | _RESOLVE_NO_SYMLINKS | _RESOLVE_NO_MAGICLINKS)
        fd = syscall(_SYS_OPENAT2, dirfd, os.fsencode(path), ctypes.byref(how),
                     ctypes.sizeof(how))
        if fd < 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code), path)
        return int(fd)

    try:
        os.close(openat2(_AT_FDCWD, ".", os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC, 0))
    except OSError as exc:  # ENOSYS (before 5.6), EPERM (a seccomp filter), ...
        log.debug("openat2 is not usable here (%s); walking paths component by component", exc)
        return None
    return openat2


def _openat2():
    if not _openat2_fn:
        with _openat2_lock:
            if not _openat2_fn:
                _openat2_fn.append(_make_openat2())
    return _openat2_fn[0]


def uses_openat2() -> bool:
    """Whether paths are resolved by openat2 (else by the component walk)."""
    return FD_CONFINED and _openat2() is not None


# --------------------------------------------------------------- helpers
class SymlinkRefused(PermissionError):
    """A symlink stands where the checked path had a folder or the file:
    it appeared after the check and is not followed."""


def _refused(path: str, exc: OSError | None = None) -> SymlinkRefused:
    return SymlinkRefused(
        errno.EACCES,
        "a symbolic link appeared in the path after it was checked; not followed",
        path,
    )


def _is_link_at(dir_fd: int, name: str) -> bool:
    try:
        return stat_module.S_ISLNK(os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode)
    except OSError:
        return False


def _link_on_the_way(root_fd: int, parts: list[str]) -> bool:
    """Whether a component of ``root/parts`` is a symlink now: O_PATH |
    O_NOFOLLOW opens a link as itself, so O_DIRECTORY on it says ENOTDIR,
    not ELOOP. Only for the error's wording - nothing is opened."""
    for i in range(len(parts)):
        if _is_link_at(root_fd, "/".join(parts[: i + 1])):
            return True
    return False


def _relative(abs_path: str, base: str) -> str | None:
    """*abs_path* relative to the folder *base*, or None when outside it."""
    norm_path, norm_base = os.path.normcase(abs_path), os.path.normcase(base)
    if norm_base == os.sep or (len(norm_base) == 3 and norm_base[1:] == ":" + os.sep):
        return abs_path[len(base):] if norm_path.startswith(norm_base) else None
    if norm_path == norm_base:
        return ""
    prefix = norm_base.rstrip(os.sep) + os.sep
    if norm_path.startswith(prefix):
        return abs_path[len(prefix):]
    return None


def open_beneath(root_fd: int, parts: list[str], flags: int, mode: int = 0o666,
                 *, path: str = "") -> int:
    """A descriptor of ``root/parts...`` opened with *flags*; no symlink is
    followed on the way or at the end (PermissionError when one is there)."""
    if not parts:
        return os.open(".", flags | _O_CLOEXEC, mode, dir_fd=root_fd)
    call = _openat2()
    try:
        if call is not None:
            return call(root_fd, "/".join(parts), flags | _O_NOFOLLOW | _O_CLOEXEC, mode)
        fd = root_fd
        try:
            for name in parts[:-1]:
                try:
                    next_fd = os.open(name, _DIR_FLAGS, dir_fd=fd)
                except NotADirectoryError:
                    # O_PATH | O_NOFOLLOW opens a link as itself: ENOTDIR.
                    if _is_link_at(fd, name):
                        raise _refused(path) from None
                    raise
                if fd != root_fd:
                    os.close(fd)
                fd = next_fd
            return os.open(parts[-1], flags | _O_NOFOLLOW | _O_CLOEXEC, mode, dir_fd=fd)
        finally:
            if fd != root_fd:
                os.close(fd)
    except SymlinkRefused:
        raise
    except OSError as exc:
        if exc.errno in _LINK_ERRNOS or (
            exc.errno == errno.ENOTDIR and _link_on_the_way(root_fd, parts)
        ):
            raise _refused(path, exc) from exc
        if path:
            exc.filename = path
        raise


class ConfinedLocalFS(LocalFS):
    """LocalFS whose operations stay beneath *roots* (see the module doc).

    A path outside every root is a PermissionError. The roots are resolved
    at every operation (a root re-pointed while the server runs counts as
    the operator's choice, as in core.mcp_server._enforce_root).
    """

    #: core.server_ops: a cross-device rename must not fall back to the
    #: path-based copy + remove; a folder moved across devices is refused.
    confined_beneath = True
    #: What list_backends reports: it is the local file system.
    display_class = "LocalFS"

    def __init__(self, roots: Iterable[str], *,
                 follow_check: Callable[[str], None] | None = None) -> None:
        """*follow_check(resolved_path)* raises PermissionError for a file
        open_read must not reach through a symlink that is the path's last
        component (core.mcp_server: the secret files)."""
        super().__init__()
        self._roots = tuple(str(r) for r in roots if r)
        if not self._roots:
            raise ValueError("ConfinedLocalFS needs at least one folder")
        self._follow_check = follow_check

    @property
    def roots(self) -> tuple[str, ...]:
        return self._roots

    # -- locating -------------------------------------------------------
    def _locate(self, path: str) -> tuple[str, list[str]]:
        """``(the root folder as a path, the components below it)``.

        A path is matched against each root as given first (string
        operations only); the roots' resolved forms are taken only when
        none matches - _enforce_root answers the resolved form when the
        path went through a link inside the root. The root folder itself is
        then opened by that path, following links in the root's OWN path
        (the operator's, outside every root); below it nothing is followed.
        """
        if not isinstance(path, str) or not path:
            raise ValueError("path must be a non-empty string")
        if "\x00" in path:
            raise ValueError("path contains NUL byte")
        abs_path = os.path.abspath(path)
        found = self._match(abs_path, [os.path.abspath(r) for r in self._roots])
        if found is None:
            found = self._match(abs_path, [os.path.realpath(os.path.abspath(r))
                                           for r in self._roots])
        if found is None:
            raise PermissionError(errno.EACCES, "outside the folders this server may use", path)
        base, rel = found
        return base, [p for p in rel.split(os.sep) if p]

    @staticmethod
    def _match(abs_path: str, bases: list[str]) -> tuple[str, str] | None:
        best: tuple[str, str] | None = None
        for base in bases:
            rel = _relative(abs_path, base)
            if rel is not None and (best is None or len(base) > len(best[0])):
                best = (base, rel)
        return best

    @contextlib.contextmanager
    def _root(self, path: str) -> Iterator[tuple[int, list[str], str]]:
        base, parts = self._locate(path)
        fd = os.open(base, (_O_PATH or os.O_RDONLY) | _O_DIRECTORY | _O_CLOEXEC)
        try:
            yield fd, parts, base
        finally:
            os.close(fd)

    def _open(self, path: str, flags: int, mode: int = 0o666) -> int:
        with self._root(path) as (root_fd, parts, _base):
            return open_beneath(root_fd, parts, flags, mode, path=path)

    @contextlib.contextmanager
    def _parent(self, path: str) -> Iterator[tuple[int, str]]:
        """``(descriptor of the parent folder, final name)`` of *path*. For a
        root itself the parent is the folder holding it (the operator's)."""
        with self._root(path) as (root_fd, parts, base):
            if parts:
                fd = open_beneath(root_fd, parts[:-1], _DIR_FLAGS, path=path)
                name = parts[-1]
            else:
                parent = os.path.dirname(base)
                name = os.path.basename(base) or "."
                fd = os.open(parent or os.sep, (_O_PATH or os.O_RDONLY) | _O_DIRECTORY
                             | _O_CLOEXEC)
            try:
                yield fd, name
            finally:
                os.close(fd)

    def _lstat(self, path: str) -> os.stat_result:
        with self._parent(path) as (dfd, name):
            return os.stat(name, dir_fd=dfd, follow_symlinks=False)

    def _entry(self, path: str) -> os.stat_result | None:
        try:
            return self._lstat(path)
        except OSError as exc:
            if exc.errno in _ABSENT_ERRNOS and not isinstance(exc, PermissionError):
                return None
            raise

    # -- listing and metadata --------------------------------------------
    def _item(self, name: str, st: os.stat_result, dfd: int, entry_name: str) -> FileItem:
        item = self._stat_to_item(name, st)
        if item.is_link:
            try:
                item = dataclasses.replace(item, link_target=os.readlink(entry_name, dir_fd=dfd))
            except OSError:
                pass
        return item

    def list_dir(self, path: str) -> list[FileItem]:
        if not FD_CONFINED:
            return super().list_dir(path)
        items: list[FileItem] = []
        outer = getattr(_listing, "names", None)
        _listing.names = ({}, {})
        try:
            fd = self._open(path, os.O_RDONLY | _O_DIRECTORY)
            try:
                with os.scandir(fd) as it:
                    for entry in it:
                        try:
                            st = entry.stat(follow_symlinks=False)
                            items.append(self._item(entry.name, st, fd, entry.name))
                        except FileNotFoundError:
                            pass  # gone while listed: no ghost row (as LocalFS)
                        except OSError as e:
                            log.warning("Cannot stat %s: %s", entry.name, e)
                            items.append(unstattable_item(entry, e))
            finally:
                os.close(fd)
        except OSError as e:
            log.error("Cannot list %s: %s", path, e)
            raise
        finally:
            _listing.names = outer
        return items

    def stat(self, path: str) -> FileItem:
        if not FD_CONFINED:
            return super().stat(path)
        with self._parent(path) as (dfd, name):
            st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            return self._item(os.path.basename(path) or path, st, dfd, name)

    def is_dir(self, path: str) -> bool:
        if not FD_CONFINED:
            return super().is_dir(path)
        st = self._entry(path)
        return st is not None and stat_module.S_ISDIR(st.st_mode)

    def exists(self, path: str) -> bool:
        if not FD_CONFINED:
            return super().exists(path)
        try:
            return self._entry(path) is not None
        except ValueError:
            return False

    def readlink(self, path: str) -> str:
        if not FD_CONFINED:
            return super().readlink(path)
        with self._parent(path) as (dfd, name):
            return os.readlink(name, dir_fd=dfd)

    # -- contents ---------------------------------------------------------
    def open_read(self, path: str) -> IO[bytes]:
        if not FD_CONFINED:
            return self._verified(path, super().open_read(path))
        try:
            fd = self._open(path, os.O_RDONLY | _O_NONBLOCK)
        except SymlinkRefused:
            fd = self._open_through_final_link(path, os.O_RDONLY | _O_NONBLOCK)
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

    def _open_through_final_link(self, path: str, flags: int) -> int:
        """Open what the symlink that is *path*'s last component names (a
        transfer of a link reads its target): only when it resolves beneath
        a root and *follow_check* lets it; opened beneath the root again,
        no further link followed. A link among the folders stays refused."""
        with self._parent(path) as (dfd, name):
            if not _is_link_at(dfd, name):
                raise _refused(path)
            target = os.readlink(name, dir_fd=dfd)
        where = target if os.path.isabs(target) else os.path.join(
            os.path.dirname(os.path.abspath(path)), target)
        real = os.path.realpath(where)
        self._locate(real)
        if self._follow_check is not None:
            self._follow_check(real)
        return self._open(real, flags)

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        if not FD_CONFINED:
            return self._verified(path, super().open_write(path, append))
        # Not truncated before the file is known to have one name only.
        flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if append else 0)
        fd = self._open(path, flags, 0o666)
        try:
            st = os.fstat(fd)
            if stat_module.S_ISREG(st.st_mode) and st.st_nlink > 1:
                raise _hard_linked(path, st.st_nlink)
            if not append and stat_module.S_ISREG(st.st_mode):
                os.ftruncate(fd, 0)
            return os.fdopen(fd, "ab" if append else "wb")
        except BaseException:
            os.close(fd)
            raise

    def _verified(self, path: str, fh):
        """Windows: the file opened by name must be the file *path* names
        now, and lie beneath a folder (no dir_fd to open it beneath one)."""
        try:
            real = os.path.realpath(path)
            self._locate(real)
            if not os.path.samestat(os.fstat(fh.fileno()), os.stat(real)):
                raise PermissionError(errno.EACCES, "the path changed while it was opened", path)
        except BaseException:
            fh.close()
            raise
        return fh

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        import hashlib

        try:
            h = hashlib.new(algorithm)
        except ValueError as exc:
            raise OSError(f"Unsupported checksum algorithm: {algorithm}") from exc
        with self.open_read(path) as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return f"{algorithm}:{h.hexdigest()}"

    # -- entries ------------------------------------------------------------
    def mkdir(self, path: str) -> None:
        """``os.makedirs(path, exist_ok=True)``, each folder created and
        entered relative to the one before it."""
        if not FD_CONFINED:
            return super().mkdir(path)
        with self._root(path) as (root_fd, parts, _base):
            fd = root_fd
            try:
                for name in parts:
                    try:
                        next_fd = os.open(name, _DIR_FLAGS, dir_fd=fd)
                    except FileNotFoundError:
                        try:
                            os.mkdir(name, 0o777, dir_fd=fd)
                        except FileExistsError:
                            pass  # a concurrent creator
                        next_fd = os.open(name, _DIR_FLAGS, dir_fd=fd)
                    except OSError as exc:
                        if exc.errno in _LINK_ERRNOS or _is_link_at(fd, name):
                            raise _refused(path, exc) from exc
                        if exc.errno == errno.ENOTDIR:
                            raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST),
                                                  path) from exc
                        raise
                    if fd != root_fd:
                        os.close(fd)
                    fd = next_fd
            finally:
                if fd != root_fd:
                    os.close(fd)

    def remove(self, path: str, recursive: bool = False) -> None:
        if not FD_CONFINED:
            return super().remove(path, recursive)
        with self._parent(path) as (dfd, name):
            st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            if not stat_module.S_ISDIR(st.st_mode):
                os.unlink(name, dir_fd=dfd)
            elif recursive:
                _remove_tree(dfd, name, path)
            else:
                os.rmdir(name, dir_fd=dfd)

    def rename(self, src: str, dst: str) -> None:
        if not FD_CONFINED:
            return super().rename(src, dst)
        with self._parent(src) as (sfd, sname), self._parent(dst) as (dfd, dname):
            try:
                os.rename(sname, dname, src_dir_fd=sfd, dst_dir_fd=dfd)
            except OSError as exc:
                if exc.errno != errno.EXDEV:
                    raise
                st = os.stat(sname, dir_fd=sfd, follow_symlinks=False)
                if stat_module.S_ISDIR(st.st_mode):
                    raise OSError(
                        errno.EXDEV,
                        "a folder is not moved to another file system here; "
                        "copy it and remove the source",
                        src,
                    ) from exc
                _move_entry_across(sfd, sname, dfd, dname, st, exc)

    def rename_no_replace(self, src: str, dst: str) -> None:
        """:meth:`rename` refusing an existing *dst* (FileExistsError),
        within the confinement (core.local_fs.rename_no_replace at the
        parents' descriptors). Across file systems: checked, then
        :meth:`rename`, as before."""
        if not FD_CONFINED or getattr(self.rename, "__func__", None) is not \
                ConfinedLocalFS.rename:
            # Not confined by descriptors, or rename replaced (a subclass,
            # a stand-in): checked, then that rename (see LocalFS).
            if self.exists(dst):
                raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), dst)
            return self.rename(src, dst)
        from core.local_fs import rename_no_replace

        with self._parent(src) as (sfd, sname), self._parent(dst) as (dfd, dname):
            try:
                rename_no_replace(sname, dname, src_dir_fd=sfd, dst_dir_fd=dfd)
                return
            except OSError as exc:
                if exc.errno != errno.EXDEV:
                    raise
        if self.exists(dst):
            raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), dst)
        self.rename(src, dst)

    def symlink(self, target: str, link_path: str) -> None:
        if not FD_CONFINED:
            return super().symlink(target, link_path)
        with self._parent(link_path) as (dfd, name):
            os.symlink(target, name, dir_fd=dfd)

    def hardlink(self, target: str, link_path: str) -> None:
        if not FD_CONFINED:
            return super().hardlink(target, link_path)
        with self._parent(target) as (sfd, sname), self._parent(link_path) as (dfd, dname):
            os.link(sname, dname, src_dir_fd=sfd, dst_dir_fd=dfd, follow_symlinks=False)

    def chmod(self, path: str, mode: int) -> None:
        if not FD_CONFINED:
            return super().chmod(path, mode)
        if _O_PATH and os.path.isdir("/proc/self/fd"):
            # An O_PATH descriptor needs no read permission and opens no
            # device; the mode is set through its /proc name, which is the
            # inode it holds - no path is walked again.
            fd = self._open(path, _O_PATH)
            try:
                if stat_module.S_ISLNK(os.fstat(fd).st_mode):
                    raise _refused(path)
                os.chmod(f"/proc/self/fd/{fd}", mode)
            finally:
                os.close(fd)
            return
        fd = self._open(path, os.O_RDONLY | _O_NONBLOCK)
        try:
            fchmod_private(fd, mode)
        finally:
            os.close(fd)

    def set_modified(self, path: str, mtime: float) -> None:
        if not FD_CONFINED:
            return super().set_modified(path, mtime)
        with self._parent(path) as (dfd, name):
            st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            os.utime(name, (st.st_atime, mtime), dir_fd=dfd, follow_symlinks=False)

    def copy(self, src: str, dst: str) -> None:
        """Copy the file *src* onto *dst* (mode and times kept); never into
        a folder *dst*. The copy is written to a temp name and renamed."""
        if not FD_CONFINED:
            return super().copy(src, dst)
        with self.open_read(src) as fin:
            st = os.fstat(fin.fileno())
            with self._parent(dst) as (dfd, name):
                try:
                    there = os.stat(name, dir_fd=dfd, follow_symlinks=False)
                except FileNotFoundError:
                    there = None
                if there is not None and stat_module.S_ISDIR(there.st_mode):
                    raise IsADirectoryError(errno.EISDIR, "copy target is a folder", dst)
                tmp, fd = _create_temp(dfd, name, 0o600)
                try:
                    with os.fdopen(fd, "wb") as fout:
                        while True:
                            chunk = fin.read(1024 * 1024)
                            if not chunk:
                                break
                            fout.write(chunk)
                        fout.flush()
                        fchmod_private(fout.fileno(), stat_module.S_IMODE(st.st_mode))
                        os.utime(fout.fileno(), ns=(st.st_atime_ns, st.st_mtime_ns))
                    os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
                except BaseException:
                    _unlink_quietly(dfd, tmp)
                    raise

    # -- the MCP write_file ---------------------------------------------------
    def confined_atomic_write(self, path: str, data: bytes) -> None:
        """core.atomic_io.atomic_write for this backend: the new content
        goes to a temp file in the target's folder and is renamed over it,
        both relative to that folder's descriptor; the old file's mode,
        group and extended attributes are carried. A file whose identity a
        rename would lose (another owner, a folder this user cannot create
        in, an attribute that cannot be copied) is written in place, with
        its old bytes put back on failure. A file with other hard links is
        refused (PermissionError): in place the other names would change
        too, renamed over it would no longer be them."""
        if not FD_CONFINED:
            from core.atomic_io import atomic_write

            return atomic_write(self, path, data)
        op_id = _journal_start(path, len(data))
        try:
            with self._parent(path) as (dfd, name):
                _write_beneath(dfd, name, path, data)
        except BaseException as exc:
            _journal_finish(op_id, "error", path, len(data), error=str(exc))
            raise
        _journal_finish(op_id, "done", path, len(data))

    # -- a streamed upload (core.reverse_serve PUT) ------------------------
    def confined_atomic_write_stream(self, path: str, reader, *,
                                     chunk_size: int = 1024 * 1024) -> int:
        """Store what ``reader.read(n)`` delivers at *path*: written to a
        temp file in the target's folder and renamed over it, both relative
        to that folder's descriptor; the old file's mode is kept. The old
        file stays as it was when the reader fails. A symlink at the target
        (one appeared since the caller resolved the path) is refused. The
        bytes written are returned."""
        if not FD_CONFINED:
            from core.atomic_io import atomic_write_stream

            self._locate(os.path.realpath(path))
            return atomic_write_stream(LocalFS(), path, reader, chunk_size=chunk_size)
        with self._parent(path) as (dfd, name):
            try:
                st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            except FileNotFoundError:
                st = None
            if st is not None:
                if stat_module.S_ISLNK(st.st_mode):
                    raise _refused(path)
                if stat_module.S_ISDIR(st.st_mode):
                    raise IsADirectoryError(errno.EISDIR, os.strerror(errno.EISDIR), path)
                if not stat_module.S_ISREG(st.st_mode):
                    raise OSError(errno.EINVAL, "not a regular file; not written", path)
            mode = stat_module.S_IMODE(st.st_mode) if st is not None else None
            tmp, fd = _create_temp(dfd, name, 0o600 if mode is not None else 0o666)
            done = 0
            try:
                with os.fdopen(fd, "wb") as fh:
                    while True:
                        chunk = reader.read(chunk_size)
                        if not chunk:
                            break
                        fh.write(chunk)
                        done += len(chunk)
                    fh.flush()
                    if mode is not None:
                        fchmod_private(fh.fileno(), mode)
                os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
            except BaseException:
                _unlink_quietly(dfd, tmp)
                raise
            return done

    # -- new entries (MCP _place_new, core.packer, core.archive) -----------
    def create_new(self, path: str, mode: int = 0o600) -> IO[bytes]:
        """A new file at *path*, open for writing: FileExistsError when
        anything (a symlink too) is there already; nothing on the way is
        followed."""
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        if not FD_CONFINED:
            self._locate(os.path.realpath(os.path.dirname(path) or "."))
            fd = os.open(path, flags | _O_NOFOLLOW, mode)
            return self._verified(path, os.fdopen(fd, "wb"))
        fd = self._open(path, flags, mode)
        try:
            return os.fdopen(fd, "wb")
        except BaseException:
            os.close(fd)
            raise

    @contextlib.contextmanager
    def parent_dir(self, path: str) -> Iterator[tuple[int, str]]:
        """``(descriptor of *path*'s folder, the final name)``: the folder
        opened beneath a root without following a symlink (core.archive
        creates its target folder in it and extracts beneath that)."""
        with self._parent(path) as pair:
            yield pair


# --------------------------------------------------------------- the workers
def _unlink_quietly(dfd: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=dfd)
    except OSError as exc:
        log.debug("could not remove the temp file %s: %s", name, exc)


def _create_temp(dfd: int, name: str, mode: int) -> tuple[str, int]:
    from core.path_policy import hidden_sibling_name

    for _ in range(16):
        tmp = hidden_sibling_name(name, f".{secrets.token_hex(6)}.tmp")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC,
                         mode, dir_fd=dfd)
        except FileExistsError:
            continue
        return tmp, fd
    raise FileExistsError(errno.EEXIST, "no free temp name", name)


def _carry_attributes(src_fd: int, st: os.stat_result, dst_fd: int) -> bool:
    """Give *dst_fd* the group and extended attributes of the file *src_fd*
    (*st* its stat). False when one of them cannot be carried."""
    if hasattr(os, "fchown") and st.st_gid != os.fstat(dst_fd).st_gid:
        try:
            os.fchown(dst_fd, -1, st.st_gid)
        except OSError:
            return False
    if not hasattr(os, "listxattr"):
        return True
    try:
        names = os.listxattr(src_fd)
    except OSError:
        return True
    for attr in names:
        try:
            value = os.getxattr(src_fd, attr)
            try:
                if os.getxattr(dst_fd, attr) == value:
                    continue
            except OSError:
                pass
            os.setxattr(dst_fd, attr, value)
        except OSError:
            return False
    return True


def _write_in_place(dfd: int, name: str, path: str, data: bytes, reason: str) -> None:
    log.info("confined write: writing %s in place: %s", path, reason)
    fd = os.open(name, os.O_RDWR | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC, dir_fd=dfd)
    with os.fdopen(fd, "r+b") as fh:
        if not stat_module.S_ISREG(os.fstat(fh.fileno()).st_mode):
            raise OSError(errno.EINVAL, "not a regular file; not written", path)
        os.set_blocking(fh.fileno(), True)
        old = fh.read()
        try:
            fh.seek(0)
            fh.write(data)
            fh.truncate()
            fh.flush()
            os.fsync(fh.fileno())
        except BaseException:
            try:
                fh.seek(0)
                fh.write(old)
                fh.truncate()
                fh.flush()
            except Exception as undo_exc:  # noqa: BLE001 - the original error is raised
                log.error("confined write: could not restore %s: %s", path, undo_exc)
            raise


def _write_beneath(dfd: int, name: str, path: str, data: bytes) -> None:
    try:
        st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
    except FileNotFoundError:
        st = None
    if st is not None:
        if stat_module.S_ISLNK(st.st_mode):
            # The server resolved links before; one here appeared since.
            raise _refused(path)
        if stat_module.S_ISDIR(st.st_mode):
            raise IsADirectoryError(errno.EISDIR, os.strerror(errno.EISDIR), path)
        if not stat_module.S_ISREG(st.st_mode):
            raise OSError(errno.EINVAL, "not a regular file; not written", path)
        euid = effective_uid()
        if st.st_nlink > 1:
            raise _hard_linked(path, st.st_nlink)
        if euid is not None and st.st_uid != euid:
            return _write_in_place(dfd, name, path, data, "it belongs to another user")
    mode = stat_module.S_IMODE(st.st_mode) if st is not None else None
    try:
        tmp, fd = _create_temp(dfd, name, 0o600 if mode is not None else 0o666)
    except PermissionError:
        if st is None:
            raise
        return _write_in_place(dfd, name, path, data, "its folder is not writable")
    try:
        with os.fdopen(fd, "wb") as fh:
            if mode is not None:
                fchmod_private(fh.fileno(), mode | 0o200)
                carried = True
                try:
                    src_fd = os.open(name, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC,
                                     dir_fd=dfd)
                except OSError:
                    src_fd = None
                if src_fd is not None:
                    try:
                        carried = _carry_attributes(src_fd, st, fh.fileno())
                    finally:
                        os.close(src_fd)
                if not carried:
                    raise _KeepIdentity()
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
            if mode is not None:
                fchmod_private(fh.fileno(), mode)
        os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
    except _KeepIdentity:
        _unlink_quietly(dfd, tmp)
        return _write_in_place(dfd, name, path, data, "an attribute would not survive a rename")
    except BaseException:
        _unlink_quietly(dfd, tmp)
        raise


class _KeepIdentity(Exception):
    pass


def _hard_linked(path: str, links: int) -> PermissionError:
    """The refusal of a write to a file with more names: written in place
    it would change every other name too (one may be ~/.bashrc or a
    repository's .git/config, which the server never writes); replaced by
    a new file it would quietly stop being the same file as the others."""
    return PermissionError(
        errno.EPERM,
        f"the file has {links} hard links; the tools do not write a file with more names "
        "(the other names would change too - one may be a protected file). Write a copy "
        "under a new name instead",
        path,
    )


def _remove_tree(parent_fd: int, name: str, path: str) -> None:
    """``shutil.rmtree`` of the folder *name* in *parent_fd*: folders are
    opened relative to their parent with O_NOFOLLOW, links are unlinked."""
    try:
        top = os.open(name, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC,
                      dir_fd=parent_fd)
    except OSError as exc:
        if exc.errno in _LINK_ERRNOS:
            raise _refused(path, exc) from exc
        raise
    stack: list[tuple[int, str, list[tuple[str, bool]]]] = []
    try:
        try:
            stack.append((top, name, _entries(top)))
        except BaseException:
            os.close(top)
            raise
        while stack:
            fd, folder, todo = stack[-1]
            if not todo:
                stack.pop()
                os.close(fd)
                os.rmdir(folder, dir_fd=stack[-1][0] if stack else parent_fd)
                continue
            child, is_dir = todo.pop()
            if is_dir:
                try:
                    child_fd = os.open(child, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW
                                       | _O_CLOEXEC, dir_fd=fd)
                except OSError as exc:
                    if exc.errno in _LINK_ERRNOS:
                        raise _refused(path, exc) from exc
                    raise
                try:
                    stack.append((child_fd, child, _entries(child_fd)))
                except BaseException:
                    os.close(child_fd)
                    raise
                continue
            os.unlink(child, dir_fd=fd)
    finally:
        for fd, _folder, _todo in stack:
            os.close(fd)


def _entries(fd: int) -> list[tuple[str, bool]]:
    out = []
    with os.scandir(fd) as it:
        for entry in it:
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                is_dir = False
            out.append((entry.name, is_dir))
    return out


def _move_entry_across(sfd: int, sname: str, dfd: int, dname: str, st: os.stat_result,
                       rename_exc: OSError) -> None:
    """A file or link moved to another file system: copied, then removed."""
    try:
        os.stat(dname, dir_fd=dfd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise rename_exc
    if stat_module.S_ISLNK(st.st_mode):
        os.symlink(os.readlink(sname, dir_fd=sfd), dname, dir_fd=dfd)
    else:
        src = os.open(sname, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC, dir_fd=sfd)
        try:
            tmp, out = _create_temp(dfd, dname, 0o600)
            try:
                with os.fdopen(out, "wb") as fout:
                    while True:
                        chunk = os.read(src, 1024 * 1024)
                        if not chunk:
                            break
                        fout.write(chunk)
                    fout.flush()
                    fchmod_private(fout.fileno(), stat_module.S_IMODE(st.st_mode))
                    os.utime(fout.fileno(), ns=(st.st_atime_ns, st.st_mtime_ns))
                os.rename(tmp, dname, src_dir_fd=dfd, dst_dir_fd=dfd)
            except BaseException:
                _unlink_quietly(dfd, tmp)
                raise
        finally:
            os.close(src)
    try:
        os.unlink(sname, dir_fd=sfd)
    except OSError:
        _unlink_quietly(dfd, dname)
        raise


def _journal_start(path: str, size: int) -> str:
    try:
        from core.operation_journal import start_operation

        return start_operation("atomic_write", dest=path, backend="Local", bytes_total=size)
    except Exception as exc:  # noqa: BLE001
        log.debug("confined write: journal start failed: %s", exc)
        return ""


def _journal_finish(op_id: str, status: str, path: str, size: int, **fields) -> None:
    from core.atomic_io import _finish_journal

    done = {"bytes_done": size} if status == "done" else {}
    _finish_journal(op_id, "atomic_write", status=status, dest=path, bytes_total=size,
                    **done, **fields)


def confinable(backend) -> bool:
    """Whether *backend* is the plain local file system (no subclass that
    changes what the paths mean) and so can be confined."""
    return type(backend) is LocalFS


def makedirs_beneath(root_fd: int, parts: list[str], *, path: str = "") -> int:
    """``os.makedirs(root/parts..., exist_ok=True)`` relative to *root_fd*,
    each folder created and entered without following a symlink
    (SymlinkRefused when one stands in the way). A descriptor of the last
    folder (a dup of *root_fd* for no *parts*); the caller closes it."""
    fd = os.dup(root_fd)
    try:
        for name in parts:
            if name in ("", ".", "..") or "/" in name:
                raise ValueError(f"not a folder name: {name!r}")
            try:
                next_fd = os.open(name, _DIR_FLAGS, dir_fd=fd)
            except FileNotFoundError:
                try:
                    os.mkdir(name, 0o777, dir_fd=fd)
                except FileExistsError:
                    pass  # a concurrent creator
                try:
                    next_fd = os.open(name, _DIR_FLAGS, dir_fd=fd)
                except OSError as exc:
                    if exc.errno in _LINK_ERRNOS or _is_link_at(fd, name):
                        raise _refused(path, exc) from exc
                    raise
            except OSError as exc:
                if exc.errno in _LINK_ERRNOS or _is_link_at(fd, name):
                    raise _refused(path, exc) from exc
                raise
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


__all__ = ["FD_CONFINED", "ConfinedLocalFS", "SymlinkRefused", "confinable", "makedirs_beneath",
           "open_beneath", "uses_openat2"]
