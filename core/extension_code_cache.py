"""Compiled extension code, kept by the SHA-256 of its source.

ui.extension_host runs an extension from its current source on every load,
never from ``__pycache__`` (a source rewritten within the same second at the
same size kept its old byte code). Compiling all bundled extensions took
about 270 ms of every start, though their sources rarely change. This cache
keeps that guarantee - the key is the SHA-256 of the source itself (with its
path, the Python version and the optimisation level), so a changed source
can never find the old code - and saves the compile. A file of a one-file
binary's bundle is keyed by its path in the bundle (it unpacks to a new
folder at every start); code read back is given the path it runs from.

Where: in memory for this process, and on POSIX in
``$XDG_CACHE_HOME/axross/extension-code`` (an absolute XDG_CACHE_HOME only,
else ``~/.cache``). Code from that folder runs in axross, so it is read only
when the folder is a real directory (no symlink) owned by the user that no
one else may write to, and the file a regular file owned by the user that
no one else may read or write; anything else is ignored (and compiled
anew). Windows keeps the in-memory cache only.

Each entry is authenticated: it carries an HMAC-SHA256 of its key and
payload under a random secret of this user (:data:`SECRET_NAME` in
``~/.config/axross``, 32 bytes, 0600). A plain checksum stopped only
damage: the key is the hash of public inputs, so whoever could write in
the cache folder - an agent or an MCP client allowed to write in the home
folder - planted byte code for a bundled extension and axross ran it at the
next start. An entry without the right MAC is compiled anew, never run.
The secret is made once with O_EXCL (a private temporary file linked to its
name, so no reader sees half of one) and used only when it is a regular
file of this user no one else may read or write, in a folder no one else
may write to; when it cannot be read or made safely, only the in-memory
cache is used. Both folders are protected places (core.protected_places):
no MCP tool writes there, and the agent sandbox mounts them read-only.

Entries are written at most :data:`MAX_ENTRIES` deep; the oldest go first.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import logging
import marshal
import os
import secrets
import stat
import sys
import tempfile
import threading
import types
from pathlib import Path

from core.posix_compat import effective_uid

log = logging.getLogger(__name__)

#: Files kept in the folder (every changed source adds one).
MAX_ENTRIES = 256
#: The largest entry read back (bytes); larger is ignored.
MAX_ENTRY_BYTES = 32 * 1024 * 1024
# AXEC1 entries carried a plain SHA-256 of the payload: never read again.
_MAGIC = b"AXEC2\n"
#: The HMAC secret's file name in ~/.config/axross.
SECRET_NAME = "extension-code.key"
_SECRET_BYTES = 32
#: The secret once looked up: ``[bytes]``, or ``[None]`` (none to be had safely).
_SECRET: list = []
_SUFFIX = ".code"
_MEMORY: dict[str, types.CodeType] = {}
_MEMORY_LIMIT = 128
_LOCK = threading.Lock()
#: How often compile_source found the code in memory, on disk or compiled it,
#: for the tests.
stats = {"memory": 0, "disk": 0, "compiled": 0}


def cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME", "").strip()
    root = Path(base) if base and os.path.isabs(base) else Path.home() / ".cache"
    return root / "axross" / "extension-code"


def _disk_allowed() -> bool:
    return os.name == "posix" and hasattr(os, "geteuid")


def secret_path() -> Path:
    """Where the HMAC secret of the cache entries lives (a protected place)."""
    return Path.home() / ".config" / "axross" / SECRET_NAME


def _read_secret_file(path: Path) -> bytes | None:
    """The secret at *path* when it can be trusted, else None. A missing
    file raises FileNotFoundError."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != effective_uid()
                or st.st_mode & 0o077 or st.st_size != _SECRET_BYTES):
            log.warning("The extension code cache secret %s is not private to this user: "
                        "the disk cache is not used", path)
            return None
        data = os.read(fd, _SECRET_BYTES + 1)
    finally:
        os.close(fd)
    return data if len(data) == _SECRET_BYTES else None


def _make_secret(folder: Path) -> bytes | None:
    """A new secret in *folder*, made atomically: a private temporary file
    (O_EXCL, 0600) linked to its name - which fails when another process
    was first (None: read that one)."""
    fd, tmp = tempfile.mkstemp(prefix=".", suffix=".tmp", dir=folder)
    try:
        secret = secrets.token_bytes(_SECRET_BYTES)
        with os.fdopen(fd, "wb") as fh:
            fh.write(secret)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.link(tmp, folder / SECRET_NAME)
        except FileExistsError:
            return None
        return secret
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _secret() -> bytes | None:
    """This user's HMAC secret, made at the first use; None when it cannot
    be read or made safely (the disk cache is not used then)."""
    with _LOCK:
        if _SECRET:
            return _SECRET[0]
    path = secret_path()
    secret = None
    try:
        if _private_dir(path.parent, create=True):
            try:
                secret = _read_secret_file(path)
            except FileNotFoundError:
                secret = _make_secret(path.parent)
                if secret is None:
                    secret = _read_secret_file(path)
    except OSError as exc:
        log.debug("Extension code cache secret not available: %s", exc)
        secret = None
    with _LOCK:
        _SECRET[:] = [secret]
    return secret


def _mac(secret: bytes, key: str, payload: bytes) -> bytes:
    return hmac.new(secret, _MAGIC + key.encode("ascii") + b"\n" + payload,
                    hashlib.sha256).digest()


def _key_path(path: str) -> str:
    """*path* as the key names it. A one-file binary (PyInstaller) unpacks
    to a new random ``/tmp/_MEIxxxx`` at every start: a file of the bundle
    is named by its path in the bundle, or the cache never hit there and
    every start wrote the bundled extensions' code anew."""
    base = getattr(sys, "_MEIPASS", "") if getattr(sys, "frozen", False) else ""
    if base:
        absolute, bundle = os.path.abspath(path), os.path.abspath(base)
        if absolute.startswith(bundle.rstrip(os.sep) + os.sep):
            return "<bundle>/" + os.path.relpath(absolute, bundle).replace(os.sep, "/")
    return path


def _named(code: types.CodeType, path: str) -> types.CodeType:
    """*code* (and the code objects in it) with ``co_filename`` *path*: code
    read back from a bundle unpacked elsewhere names the file it runs from."""
    if code.co_filename == path:
        return code
    consts = tuple(_named(c, path) if isinstance(c, types.CodeType) else c
                   for c in code.co_consts)
    return code.replace(co_filename=path, co_consts=consts)


def source_key(source: bytes, path: str) -> str:
    """The key of *source* compiled as *path* by this Python."""
    h = hashlib.sha256()
    h.update(importlib.util.MAGIC_NUMBER)
    h.update(f"{sys.implementation.cache_tag}|{sys.flags.optimize}|".encode())
    h.update(os.fsencode(_key_path(path)))
    h.update(b"\0")
    h.update(source)
    return h.hexdigest()


def compile_source(source: bytes, path: str, *, key: str | None = None) -> types.CodeType:
    """*source* compiled as the module at *path* (``exec`` mode, no
    inherited future flags) - from the cache when the same source was
    compiled before. *key* is :func:`source_key` when the caller has it."""
    key = key or source_key(source, path)
    with _LOCK:
        code = _MEMORY.get(key)
    if code is not None:
        stats["memory"] += 1
        return code
    code = _read(key) if _disk_allowed() else None
    if code is not None:
        stats["disk"] += 1
        code = _named(code, path)
    else:
        code = compile(source, path, "exec", dont_inherit=True)
        stats["compiled"] += 1
        if _disk_allowed():
            _write(key, code)
    with _LOCK:
        if len(_MEMORY) >= _MEMORY_LIMIT:
            _MEMORY.pop(next(iter(_MEMORY)))
        _MEMORY[key] = code
    return code


def clear_memory() -> None:
    """Forget the compiled code and the secret (looked up again at the next use)."""
    with _LOCK:
        _MEMORY.clear()
        _SECRET.clear()


def _private_dir(folder: Path, *, create: bool) -> bool:
    """*folder* is a real directory of this user that no one else may
    write to (made with 0o700 when *create* and missing)."""
    try:
        if create and not os.path.lexists(folder):
            os.makedirs(folder, mode=0o700, exist_ok=True)
        st = os.lstat(folder)
    except OSError:
        return False
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != effective_uid():
        return False
    if st.st_mode & 0o022:
        log.warning("Extension code cache %s is writable by others: not used", folder)
        return False
    return True


def _read(key: str) -> types.CodeType | None:
    secret = _secret()
    if secret is None:
        return None
    folder = cache_dir()
    if not _private_dir(folder, create=False):
        return None
    path = folder / (key + _SUFFIX)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return None  # not cached (or a symlink)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != effective_uid()
                or st.st_mode & 0o077 or st.st_size > MAX_ENTRY_BYTES):
            log.warning("Extension code cache entry %s is not private to this user: ignored", path)
            return None
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            data = fh.read(MAX_ENTRY_BYTES + 1)
    except OSError:
        return None
    finally:
        if fd >= 0:
            os.close(fd)
    head = len(_MAGIC) + 64 + 1 + 32
    if len(data) < head or not data.startswith(_MAGIC):
        return None
    stored_key = data[len(_MAGIC):len(_MAGIC) + 64].decode("ascii", "replace")
    digest = data[len(_MAGIC) + 65:head]
    payload = data[head:]
    if stored_key != key or not hmac.compare_digest(_mac(secret, key, payload), digest):
        log.info("Extension code cache entry %s is damaged or not made here: compiled anew",
                 path)
        return None
    try:
        code = marshal.loads(payload)
    except (EOFError, ValueError, TypeError):
        return None
    return code if isinstance(code, types.CodeType) else None


def _write(key: str, code: types.CodeType) -> None:
    secret = _secret()
    if secret is None:
        return
    folder = cache_dir()
    try:
        if not _private_dir(folder, create=True):
            return
        payload = marshal.dumps(code)
        data = (_MAGIC + key.encode("ascii") + b"\n"
                + _mac(secret, key, payload) + payload)
        fd, tmp = tempfile.mkstemp(prefix=".", suffix=".tmp", dir=folder)  # 0o600
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.replace(tmp, folder / (key + _SUFFIX))
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        _prune(folder)
    except OSError as exc:  # a full disk, a read-only home: compiled each time
        log.debug("Extension code not cached: %s", exc)


def _prune(folder: Path) -> None:
    try:
        entries = [e for e in os.scandir(folder) if e.name.endswith(_SUFFIX) and e.is_file(follow_symlinks=False)]
    except OSError:
        return
    if len(entries) <= MAX_ENTRIES:
        return
    entries.sort(key=lambda e: e.stat(follow_symlinks=False).st_mtime)
    for entry in entries[:len(entries) - MAX_ENTRIES]:
        try:
            os.unlink(entry.path)
        except OSError:
            pass
