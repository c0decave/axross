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

Review round 9: on a backend whose separator is ``\\`` (WinRM, WMI,
LocalFS on Windows) the guard knew only drive letters. Windows and
PowerShell reach a root in more ways: a UNC share (``\\\\fs\\share``,
``\\\\host\\C$``), a device path (``\\\\?\\C:\\``, ``\\\\.\\C:\\``,
``\\\\?\\UNC\\fs\\share``), a provider-qualified path
(``FileSystem::C:\\``), any PSDrive (``HKLM:\\``, ``Cert:\\``), and Win32
drops trailing dots and spaces of the last name (``C:\\...`` and ``C:\\ ``
are ``C:\\``). Those count as roots there now. A last name made only of
dots and spaces names the folder above it: remove asks first
(:class:`~core.backend.ConfirmationRequired`, yes is ``confirm_alias=True``),
rename refuses. A POSIX backend keeps its rules: ``a.`` and ``...`` are
ordinary names there.
"""

from __future__ import annotations

import contextvars
import errno
import functools
import inspect
import logging
import posixpath
import re

log = logging.getLogger(__name__)

#: Ids of the backends inside a guarded call in this thread / task: their
#: calls on themselves are not checked again.
_INSIDE: contextvars.ContextVar[frozenset[int]] = contextvars.ContextVar(
    "axross_backend_guard_inside", default=frozenset())

_DRIVE_ROOT = re.compile(r"[A-Za-z]:/?")
_DRIVE = re.compile(r"/?[A-Za-z]:")
_SLASHES = re.compile(r"/+")
_SEPARATORS = re.compile(r"[/\\]")
#: Windows (backend separator ``\\``): a provider qualifier
#: (``FileSystem::``, ``Microsoft.PowerShell.Core\\FileSystem::``), a
#: device prefix (``\\\\?\\``, ``\\\\.\\``, ``\\??\\``), its UNC form, a
#: drive or any PSDrive (``C:``, ``HKLM:``, ``Cert:``).
_PROVIDER = re.compile(r"(?:[\w.]+[\\/])?[\w.]+::")
_DEVICE = re.compile(r"(?:[\\/]{2}[?.]|[\\/]\?\?)(?:[\\/]|$)")
_DEVICE_UNC = re.compile(r"UNC(?:[\\/]|$)", re.IGNORECASE)
_PSDRIVE = re.compile(r"[\\/]?[^\\/:]+:")
#: Marks a wrapper, so that a subclass inheriting it is not wrapped twice.
_GUARDED = "_axross_backend_guard"
GUARDED_METHODS = ("remove", "rename", "open_read", "stat", "list_dir")
#: The keyword of ``remove()`` - taken by the guard, never passed on - that
#: says yes to a Windows name that names the folder above it.
CONFIRM_ALIAS = "confirm_alias"


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


def _windows_rules(backend) -> bool:
    """Whether *backend* resolves paths the Windows way (separator ``\\``:
    WinRM, WMI, LocalFS on Windows)."""
    return _separator(backend) == "\\"


def _win32_trimmed(name: str) -> str:
    """*name* as Win32 opens it: trailing dots and spaces dropped (``.``
    and ``..`` are names of their own)."""
    return name if name in (".", "..") else name.rstrip(". ")


def _windows_split(path: str) -> tuple[str, list[str]]:
    """``(volume, names)`` of *path* as Windows and PowerShell resolve
    it. The volume is a drive or PSDrive (``c:``, ``hklm:``), a UNC share
    (``//server/share``), a device (``//./volume{...}``) or "" for a path
    on the current one; the names follow it, ``""`` first when the path
    is absolute on its volume."""
    provider = _PROVIDER.match(path)
    if provider:
        path = path[provider.end():]
    device = _DEVICE.match(path)
    if device:
        path = path[device.end():]
        unc = _DEVICE_UNC.match(path)
        if unc:
            path = "\\\\" + path[unc.end():]
        else:
            # \\?\C:\, \\.\Volume{...}\, \\.\PhysicalDrive0: the first name is
            # the volume.
            head, *names = _SEPARATORS.split(path)
            return "//./" + head.rstrip(":").lower(), [""] + names if names else []
    if len(path) >= 2 and path[0] in "\\/" and path[1] in "\\/":
        names = _SEPARATORS.split(path)[2:]
        server = names.pop(0) if names else ""
        share = names.pop(0) if names else ""
        return f"//{server}/{share}".lower(), [""] + names if names else []
    drive = _PSDRIVE.match(path)
    if drive:
        return drive.group().lstrip("\\/").lower(), _SEPARATORS.split(path[drive.end():])
    return "", _SEPARATORS.split(path)


def _windows_root(path: str) -> bool:
    _volume, names = _windows_split(path)
    if names:
        # Win32 drops the trailing dots and spaces of the LAST name only
        # (one that ends the path; "...\\" is a name of its own).
        names = [*names[:-1], _win32_trimmed(names[-1])]
    rest = "/".join(names)
    return posixpath.normpath(_SLASHES.sub("/", rest)) in ("/", ".") if rest else True


def windows_alias_of(backend, path) -> str | None:
    """On a Windows backend: the folder *path* really names when its last
    name is made only of dots and spaces (not ``.`` or ``..``) - Win32
    drops trailing dots and spaces of the last name, so ``C:\\data\\...``
    and ``C:\\data\\ `` are ``C:\\data``. None for any other path, and on
    every POSIX backend, where ``...`` is an ordinary name."""
    if not isinstance(path, str) or not _windows_rules(backend):
        return None
    _volume, names = _windows_split(path)
    if not names:
        return None
    last = names[-1]
    if not last or last in (".", "..") or last.strip(". "):
        return None
    return path[: len(path) - len(last)].rstrip("\\/") or path[:1]


def is_root_path(backend, path) -> bool:
    """Whether *path* names the root of *backend*: ``/`` however written
    (``//``, ``/.``, ``/a/..``), the empty path or ``.``, and - wherever a
    backslash separates (every backend but LocalFS on POSIX) - the
    Windows spellings too: ``\\``, ``/x\\..``, a drive root (``C:``,
    ``C:\\``, ``c:/.``, ``C:\\Users\\..``)."""
    if not isinstance(path, str):
        return False
    if _windows_rules(backend):
        return _windows_root(path)
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
    if _windows_rules(backend):
        return ".." in _windows_split(path)[1]
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


def _refuse_root(backend, path, action: str, *, ask: bool = False,
                 confirmed_alias: bool = False) -> None:
    """PermissionError for the root and a ``..`` component; for a Windows
    name that names the folder above (:func:`windows_alias_of`) a
    question (``ask``: remove) or a refusal (rename) - or nothing when
    the person said yes (``confirmed_alias``)."""
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
    means = windows_alias_of(backend, path)
    if means is None:
        return
    from core.i18n import tr

    if confirmed_alias:
        log.warning("%s: %s of %r confirmed; Windows acts on %r", type(backend).__name__,
                    action, path, means)
        return
    if ask:
        from core.backend import ConfirmationRequired

        raise ConfirmationRequired(
            "windows_alias", path,
            tr("Windows reads {path} as {means}: its last name is made only of dots and "
               "spaces, which Windows drops. Yes deletes {means} with everything in it – "
               "not an entry of that name.").format(path=path, means=means),
            option=CONFIRM_ALIAS, details={"means": means},
        )
    raise PermissionError(
        errno.EPERM,
        tr("{backend}: refusing to {action} {path}: Windows drops the dots and spaces its "
           "last name is made of, so it names {means}").format(
            backend=type(backend).__name__, action=action, path=path, means=means),
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
            if name == "remove":
                kwargs.pop(CONFIRM_ALIAS, None)
            return method(self, *args, **kwargs)
        token = _INSIDE.set(inside | {key})
        try:
            path = _path_argument(args, kwargs, first)
            if name == "remove":
                _refuse_root(self, path, "remove", ask=True,
                             confirmed_alias=kwargs.pop(CONFIRM_ALIAS, False) is True)
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


__all__ = ["CONFIRM_ALIAS", "GUARDED_METHODS", "guard_class", "has_parent_component",
           "is_root_path", "windows_alias_of"]
