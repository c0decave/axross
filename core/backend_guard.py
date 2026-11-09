"""One guard for the root and for "file/" on every backend.

Review round 7 measured what round 6 had fixed on seven backends only:

* ``remove("/", recursive=True)`` emptied the whole share, server, drive
  or container on SMB, FTP, SFTP, OneDrive, Azure Files and more; SCP and
  Telnet sent ``rm -rf -- /``;
* ``remove("g/")`` and ``rename("g/", ...)`` acted on the FILE g wherever
  the path handling drops the slash (FTP, SMB, WebDAV, the cloud drives,
  the shells) - and ``open_read("g/")`` read it. stat(2) of ``file/`` is
  ENOTDIR, and so it is now on every backend.

:func:`guard_class` wraps ``remove``, ``rename``, ``open_read``,
``stat`` and ``list_dir`` of a backend class; ``SessionLifecycle``
(core.backend), which every backend session inherits, applies it to each
subclass. The wrappers cost nothing for an ordinary path: a path that
ends in ``/`` costs one ``stat`` before ``remove``, ``rename`` and
``open_read`` (a folder with a slash is fine and goes on), ``list_dir``
asks only when the listing came back empty. Calls a backend makes on
itself inside a guarded call (a recursive remove listing its folders)
are not checked again.

Review round 8: SMB hands paths to smbclient, which applies Windows
rules - ``remove("/x\\..", recursive=True)`` and ``remove("\\")``
emptied the share, WinRM's ``C:\\Users\\..`` was no root either. A
backslash separates now on every backend but one that declares it a
name character, drive roots count after normalising, and a ``..``
component is refused in remove and in both paths of rename (whoever
resolves it - smbclient, Remove-Item, the server - decides where it
lands). The root is no rename destination either.
"""

from __future__ import annotations

import contextvars
import errno
import functools
import inspect
import posixpath
import re

#: Ids of the backends inside a guarded call in this thread / task: their
#: calls on themselves are not checked again.
_INSIDE: contextvars.ContextVar[frozenset[int]] = contextvars.ContextVar(
    "axross_backend_guard_inside", default=frozenset())

_DRIVE_ROOT = re.compile(r"[A-Za-z]:/?")
_DRIVE = re.compile(r"/?[A-Za-z]:")
_SLASHES = re.compile(r"/+")
_SEPARATORS = re.compile(r"[/\\]")
#: Marks a wrapper, so that a subclass inheriting it is not wrapped twice.
_GUARDED = "_axross_backend_guard"
GUARDED_METHODS = ("remove", "rename", "open_read", "stat", "list_dir")


def _separator(backend) -> str:
    try:
        sep = backend.separator()
    except Exception:  # noqa: BLE001 - no answer: the usual one
        return "/"
    return sep if isinstance(sep, str) and sep else "/"


def _backslash_separates(backend) -> bool:
    """Whether a ``\\`` in a path may split it somewhere on the way: on
    every backend but one that declares it an ordinary name character
    (LocalFS on POSIX). SMB hands the path to smbclient, which applies
    Windows normalisation (``/x\\..`` is the share root there); WinRM
    to Remove-Item; an IIS FTP or WebDAV server splits on it too."""
    from core.path_policy import BackendPathPolicy

    try:
        policy = BackendPathPolicy.for_backend(backend)
    except Exception:  # noqa: BLE001 - unknown: the careful answer
        return True
    return policy.separator == "\\" or not policy.literal_backslash


def is_root_path(backend, path) -> bool:
    """Whether *path* names the root of *backend*: ``/`` however written
    (``//``, ``/.``, ``/a/..``), the empty path or ``.``, and - wherever a
    backslash separates (every backend but LocalFS on POSIX) - the
    Windows spellings too: ``\\``, ``/x\\..``, a drive root (``C:``,
    ``C:\\``, ``c:/.``, ``C:\\Users\\..``)."""
    if not isinstance(path, str):
        return False
    if _backslash_separates(backend):
        path = _SLASHES.sub("/", path.replace("\\", "/"))
        drive = _DRIVE.match(path)
        rest = path[drive.end():] if drive else path
        return posixpath.normpath(rest) in ("/", ".")
    path = _SLASHES.sub("/", path)
    if _DRIVE_ROOT.fullmatch(path):
        return True
    return posixpath.normpath(path) in ("/", ".")


def has_parent_component(backend, path) -> bool:
    """Whether *path* holds a ``..`` component - split on ``/`` and,
    wherever a backslash separates, on ``\\`` too (``C:..`` counts
    there as well). Where it lands depends on who resolves it (posixpath, ntpath,
    smbclient, Remove-Item, the server), so a remove or rename never
    takes one."""
    if not isinstance(path, str) or ".." not in path:
        return False
    if not _backslash_separates(backend):
        return ".." in path.split("/")
    drive = _DRIVE.match(path.replace("\\", "/"))
    rest = path[drive.end():] if drive else path
    return ".." in _SEPARATORS.split(rest)


def _slashed(path) -> bool:
    return isinstance(path, str) and path.endswith("/") and bool(path.strip("/"))


def _not_a_directory(path: str) -> NotADirectoryError:
    return NotADirectoryError(errno.ENOTDIR, f"Not a directory: {path}", path)


def _is_file(item) -> bool:
    """A stat result that is certainly no folder (a link may lead to one)."""
    return not getattr(item, "is_dir", True) and not getattr(item, "is_link", False)


def _stat_slashed(backend, stat, path: str):
    """stat of a path ending in ``/``: the folder, NotADirectoryError
    when a FILE answers under the name (with the slash dropped, or - a
    backend that keeps it says "not found" - without it)."""
    try:
        item = stat(backend, path)
    except FileNotFoundError:
        try:
            plain = stat(backend, path.rstrip("/"))
        except Exception:  # noqa: BLE001 - not there either: the original answer
            plain = None
        if plain is not None and _is_file(plain):
            raise _not_a_directory(path) from None
        raise
    if _is_file(item):
        raise _not_a_directory(path)
    return item


def _refuse_file_with_slash(backend, path: str) -> None:
    """NotADirectoryError when *path* ends in ``/`` and names a file; a
    folder, a missing path or one that cannot be asked about goes on to
    the operation itself (and its own error)."""
    stat = getattr(type(backend), "stat", None)
    if stat is None:
        return
    raw = getattr(stat, "__wrapped__", stat)
    try:
        _stat_slashed(backend, raw, path)
    except NotADirectoryError:
        raise
    except Exception:  # noqa: BLE001 - unknown: the operation decides
        return


def _refuse_root(backend, path, action: str) -> None:
    if is_root_path(backend, path):
        raise PermissionError(
            errno.EPERM,
            f"{type(backend).__name__}: refusing to {action} the root",
            path,
        )
    if has_parent_component(backend, path):
        raise PermissionError(
            errno.EPERM,
            f"{type(backend).__name__}: refusing to {action} a path with '..' in it",
            path,
        )


def _path_argument(args, kwargs, name: str, index: int = 0):
    if len(args) > index:
        return args[index]
    return kwargs.get(name)


def _wrap(name: str, method):
    try:
        params = [p for p in inspect.signature(method).parameters if p != "self"]
    except (TypeError, ValueError):
        params = []
    first = params[0] if params else "path"
    second = params[1] if len(params) > 1 else "dst"

    @functools.wraps(method)
    def guarded(self, *args, **kwargs):
        inside = _INSIDE.get()
        key = id(self)
        if key in inside:
            return method(self, *args, **kwargs)
        token = _INSIDE.set(inside | {key})
        try:
            path = _path_argument(args, kwargs, first)
            if name == "remove":
                _refuse_root(self, path, "remove")
            elif name == "rename":
                _refuse_root(self, path, "rename")
                # Nor onto the root or past it: rename(x, "//") hid the
                # data on the database backends.
                _refuse_root(self, _path_argument(args, kwargs, second, 1),
                             "rename something onto")
            if _slashed(path):
                if name == "stat":
                    return _stat_slashed(self, method, path)
                if name in ("remove", "rename", "open_read"):
                    _refuse_file_with_slash(self, path)
                elif name == "list_dir":
                    listed = method(self, *args, **kwargs)
                    if not listed:
                        _refuse_file_with_slash(self, path)
                    return listed
            return method(self, *args, **kwargs)
        finally:
            _INSIDE.reset(token)

    setattr(guarded, _GUARDED, True)
    return guarded


def guard_class(cls) -> None:
    """Wrap :data:`GUARDED_METHODS` of backend class *cls* (those it
    defines or inherits unwrapped, e.g. from a mixin)."""
    for name in GUARDED_METHODS:
        # Plain functions only: a staticmethod, a property or a callable
        # object keeps its own binding.
        method = inspect.getattr_static(cls, name, None)
        if not inspect.isfunction(method) or getattr(method, _GUARDED, False):
            continue
        setattr(cls, name, _wrap(name, method))


__all__ = ["GUARDED_METHODS", "guard_class", "has_parent_component", "is_root_path"]
