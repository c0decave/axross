"""Half-written files and folders of a running process, swept after a crash.

A tool writes its output under a temporary name beside the final one (a
decrypted file, an archive's staging folder, a copy's ``.copy-*.tmp``) and
renames it into place when it is complete. A process killed meanwhile
(SIGKILL, a power cut) left that temporary file behind for good. Here every
such path is recorded - one small file per path in
``~/.local/state/axross/partials/``, named after the process id - and
:func:`sweep` (the MCP server runs it at its start) removes what a process
that no longer runs left.

A record is only a hint, never trusted: a record file could be written by
someone else (an agent whose MCP root once held the state folder). So the
sweep removes a path only when

* its name is one of axross's temporary names (:data:`_TEMP_NAMES`) and
  carries the process id of the record (the dead process's own name),
* it lies inside the root the sweeping server serves, reached without a
  symlink on the way, and is removed relative to its folder's descriptor;

and records are neither written nor read while the state folder lies inside
a served root (:func:`serve_roots`).
"""

from __future__ import annotations

import logging
import os
import re
import secrets
import shutil
import stat as stat_module
from pathlib import Path

log = logging.getLogger(__name__)

#: axross's temporary names, each with the id of the process that made it:
#: core.mcp_groups' outputs, core.server_ops' stream copies,
#: core.confined_fs' temp files, core.packer's staging folders.
_TEMP_NAMES = (
    re.compile(r"^\..*\.axross-part-(?P<pid>\d+)-[0-9a-f]+$", re.S),
    re.compile(r"^\..*\.copy-(?P<pid>\d+)-[0-9a-f]+\.tmp$", re.S),
    re.compile(r"^\..*\.(?P<pid>\d+)-[0-9a-f]{12}\.tmp$", re.S),
    re.compile(r"^\.axross-pack-(?P<pid>\d+)-[A-Za-z0-9_]+$", re.S),
)

#: The roots the running server serves (set by core.mcp_cli).
_SERVED_ROOTS: list[str] = []


def serve_roots(roots) -> None:
    """The folders this process serves to an agent: records are kept only
    when the state folder lies outside all of them."""
    _SERVED_ROOTS[:] = [os.path.realpath(r) for r in roots if r]


def _inside(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def _state_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME", "")
    root = Path(base) if base and os.path.isabs(base) else Path.home() / ".local" / "state"
    return root / "axross" / "partials"


def _usable_state_dir() -> Path | None:
    """The record folder, or None when it lies inside a served root (an
    agent could write records there)."""
    folder = _state_dir()
    real = os.path.realpath(folder)
    for root in _SERVED_ROOTS:
        if _inside(real, root):
            log.warning("partials: the state folder %s lies inside the served root %s; "
                        "half-written files are not recorded or swept", folder, root)
            return None
    return folder


def temp_pid(name: str) -> int | None:
    """The process id in one of axross's temporary names, else None."""
    for pattern in _TEMP_NAMES:
        match = pattern.match(name)
        if match:
            return int(match.group("pid"))
    return None


def track(path: str) -> str | None:
    """Record *path* (absolute, local) as half-written by this process;
    returns the record's name for :func:`done`, None when it could not be
    recorded (nothing then depends on it)."""
    if not path or not os.path.isabs(path):
        return None
    folder = _usable_state_dir()
    if folder is None:
        return None
    try:
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        name = f"{os.getpid()}-{secrets.token_hex(6)}"
        fd = os.open(folder / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", errors="surrogateescape") as fh:
            fh.write(path)
        return name
    except OSError as exc:
        log.debug("partials: cannot record %s: %s", path, exc)
        return None


def done(record: str | None) -> None:
    """*record*'s path was completed or removed: forget it."""
    if not record:
        return
    try:
        os.unlink(_state_dir() / record)
    except OSError:
        pass


def _alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # someone else's process with that id: leave it
    return True


def _remove(path: str, pid: int, root: str | None) -> bool:
    """Remove *path* if it is what a record of process *pid* may name:
    True when it was removed."""
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        return False
    parent, name = os.path.split(path)
    if temp_pid(name) != pid:
        return False
    # No symlink on the way: the folder is where its name says.
    if os.path.realpath(parent) != parent:
        return False
    if root is not None and not _inside(parent, os.path.realpath(root)):
        return False
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        dfd = os.open(parent, flags)
    except OSError:
        return False
    try:
        st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        if stat_module.S_ISDIR(st.st_mode):
            if not name.startswith(".axross-pack-"):
                return False
            # rmtree on a descriptor-based walk: links inside are removed,
            # never followed.
            shutil.rmtree(name, dir_fd=dfd)
        else:
            os.unlink(name, dir_fd=dfd)
        return True
    except (OSError, TypeError, NotImplementedError) as exc:
        log.debug("partials: cannot remove %s: %s", path, exc)
        return False
    finally:
        os.close(dfd)


def sweep(root: str | None = None) -> int:
    """Remove what processes that no longer run recorded and left inside
    *root*; returns how many paths were removed. Records naming anything
    else are dropped."""
    folder = _usable_state_dir()
    if folder is None:
        return 0
    try:
        records = list(folder.iterdir())
    except OSError:
        return 0
    removed = 0
    for record in records:
        pid_text = record.name.split("-", 1)[0]
        if not pid_text.isdigit() or _alive(int(pid_text)):
            continue
        try:
            if record.is_symlink() or not record.is_file():
                continue
            path = record.read_text(encoding="utf-8", errors="surrogateescape").strip()
        except OSError:
            continue
        if root is not None and not _inside(os.path.realpath(os.path.dirname(path) or "/"),
                                            os.path.realpath(root)):
            continue  # another server's root: its own next start sweeps it
        if _remove(path, int(pid_text), root):
            removed += 1
            log.info("partials: removed %s, left by process %s", path, pid_text)
        elif os.path.lexists(path):
            log.warning("partials: a record of process %s names %s, which is no temporary "
                        "file of it; left alone", pid_text, path)
        try:
            record.unlink()
        except OSError:
            pass
    return removed
