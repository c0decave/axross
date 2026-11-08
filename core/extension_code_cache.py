"""Compiled extension code, kept by the SHA-256 of its source.

ui.extension_host runs an extension from its current source on every load,
never from ``__pycache__`` (a source rewritten within the same second at the
same size kept its old byte code). Compiling all bundled extensions took
about 270 ms of every start, though their sources rarely change. This cache
keeps that guarantee - the key is the SHA-256 of the source itself (with its
path, the Python version and the optimisation level), so a changed source
can never find the old code - and saves the compile.

Where: in memory for this process, and on POSIX in
``$XDG_CACHE_HOME/axross/extension-code`` (an absolute XDG_CACHE_HOME only,
else ``~/.cache``). Code from that folder runs in axross, so it is read only
when the folder is a real directory (no symlink) owned by the user that no
one else may write to, and the file a regular file owned by the user that
no one else may read or write; anything else is ignored (and compiled
anew). Whoever can write there could already change the user's extensions.
Each entry also carries the SHA-256 of its payload: a truncated or damaged
file is compiled anew, never run. Windows keeps the in-memory cache only.

Entries are written at most :data:`MAX_ENTRIES` deep; the oldest go first.
"""

from __future__ import annotations

import hashlib
import importlib.util
import logging
import marshal
import os
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
_MAGIC = b"AXEC1\n"
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


def source_key(source: bytes, path: str) -> str:
    """The key of *source* compiled as *path* by this Python."""
    h = hashlib.sha256()
    h.update(importlib.util.MAGIC_NUMBER)
    h.update(f"{sys.implementation.cache_tag}|{sys.flags.optimize}|".encode())
    h.update(os.fsencode(path))
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
    with _LOCK:
        _MEMORY.clear()


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
    if stored_key != key or hashlib.sha256(payload).digest() != digest:
        log.info("Extension code cache entry %s is damaged: compiled anew", path)
        return None
    try:
        code = marshal.loads(payload)
    except (EOFError, ValueError, TypeError):
        return None
    return code if isinstance(code, types.CodeType) else None


def _write(key: str, code: types.CodeType) -> None:
    folder = cache_dir()
    try:
        if not _private_dir(folder, create=True):
            return
        payload = marshal.dumps(code)
        data = (_MAGIC + key.encode("ascii") + b"\n"
                + hashlib.sha256(payload).digest() + payload)
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
