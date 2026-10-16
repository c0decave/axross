"""Polkit-gated local filesystem access.

When axross runs unprivileged but the user wants to read a file they
don't own (typical case: ``/var/log/*`` or ``/etc/shadow``), this
module dispatches the operation to ``pkexec`` so the polkit daemon
prompts the user once and the payload is returned to us over stdout.

Security model
--------------
* The password prompt is handled by the *system* polkit agent. We
  never see or store it.
* We invoke pkexec with a fixed argv list — no shell interpolation,
  no env leaks (``env -i`` inside the pkexec target is ensured by
  pkexec itself).
* Every entry point is gated on ``BackendCapabilities.is_local``
  (same as :mod:`core.previews`). Remote backends cannot trigger
  this; a hostile FTP server can't cause us to ``cat /etc/shadow``.
* Path validation mirrors :mod:`core.previews`: no NUL bytes, must
  be an absolute path, no traversal components, length-capped.
* Output is bounded by :data:`MAX_OUTPUT_SIZE` so ``elevated_read``
  on ``/dev/urandom`` (or a 100-GiB log) fails cleanly.
* ``pkexec`` and its helpers are resolved only from root-owned system
  directories (:func:`_trusted_which`) — never from the user's
  ``PATH``, which could put a planted ``cat`` ahead of ``/usr/bin``.

Why subprocess + pkexec and not ``os.setuid``
---------------------------------------------
axross has no business holding privilege. pkexec spawns ``cat`` /
``tee`` / ``stat`` in a tightly-scoped child process, and only the
payload bytes come back. If axross is compromised the attacker
still has to get the user to authenticate to polkit — a phishing
vector, but not an automatic root escalation.
"""

from __future__ import annotations

import logging
import os
import stat
import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    pass

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Security knobs
# ---------------------------------------------------------------------------

MAX_OUTPUT_SIZE: int = 256 * 1024 * 1024  # 256 MiB
MAX_WRITE_SIZE: int = 256 * 1024 * 1024
MAX_PATH_LEN: int = 4096  # POSIX PATH_MAX
ELEVATED_TIMEOUT_SECS: int = 120  # user-auth typing time


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ElevatedIOError(OSError):
    """Base for everything this module raises."""


class ElevatedNotAvailable(ElevatedIOError):
    """pkexec is missing, or the backend is remote."""


class ElevatedCancelled(ElevatedIOError):
    """User dismissed the polkit prompt (pkexec exit 126/127)."""


class ElevatedOutputTooLarge(ElevatedIOError):
    """Command produced more than :data:`MAX_OUTPUT_SIZE` bytes."""


# ---------------------------------------------------------------------------
# Local-only + path gates (same pattern as core.previews)
# ---------------------------------------------------------------------------


def _is_local_backend(backend) -> bool:
    try:
        from core import backend_registry

        cls = type(backend).__name__
        for info in backend_registry.all_backends():
            if info.class_name == cls:
                return bool(getattr(info.capabilities, "is_local", False))
    except Exception as exc:
        log.debug("elevated_io: registry lookup failed: %s", exc)
    try:
        from core.local_fs import LocalFS

        return isinstance(backend, LocalFS)
    except Exception:
        return False


def _require_local(backend) -> None:
    if not _is_local_backend(backend):
        raise ElevatedNotAvailable(
            "elevated_io is restricted to local backends "
            "(remote filesystems can't be pkexec'd into the local root)"
        )


def _validate_path(path: str) -> str:
    if not isinstance(path, str) or not path:
        raise ValueError("path must be a non-empty string")
    if "\x00" in path:
        raise ValueError("path contains NUL byte")
    if len(path.encode("utf-8", errors="replace")) > MAX_PATH_LEN:
        raise ValueError(f"path exceeds {MAX_PATH_LEN} bytes")
    # Absolute path required. We deliberately do NOT resolve symlinks
    # — the user's intent may include following them — but we reject
    # relative + traversal components so a caller bug can't escape.
    if not os.path.isabs(path):
        raise ValueError(f"path must be absolute: {path!r}")
    # Reject traversal components in the RAW path before normpath
    # collapses them — ``os.path.normpath("/etc/../root/x")`` becomes
    # ``/root/x`` which looks clean but silently steps out of the
    # caller's intent. Better to refuse and make the caller pass the
    # intended absolute path directly.
    raw_parts = path.split(os.sep)
    if ".." in raw_parts:
        raise ValueError("path contains traversal component")
    norm = os.path.normpath(path)
    return norm


# ---------------------------------------------------------------------------
# pkexec plumbing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Pkexec:
    binary: str  # absolute path to pkexec
    helpers: dict[str, str]  # name -> absolute path for cat/tee/stat/ls


_TRUSTED_DIRS = ("/usr/bin", "/bin", "/usr/sbin", "/sbin")


def _trusted_which(name: str, dirs: tuple[str, ...] = _TRUSTED_DIRS) -> str | None:
    """Find *name* only in root-owned system directories.

    ``shutil.which`` walks the caller's ``$PATH``; a ``~/.local/bin/cat``
    placed ahead of ``/usr/bin`` would be handed to pkexec as the program
    to run as root. A candidate must be a regular, executable file owned
    by root and writable by nobody but root.
    """
    for directory in dirs:
        candidate = os.path.join(directory, name)
        try:
            st = os.stat(candidate)
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode) or not os.access(candidate, os.X_OK):
            continue
        if st.st_uid != 0 or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            continue
        return candidate
    return None


def _resolve_helpers() -> _Pkexec | None:
    """Resolve absolute paths to pkexec + the helper binaries. Returns
    None when pkexec or any required helper is missing."""
    pkexec = _trusted_which("pkexec")
    if pkexec is None:
        return None
    helpers: dict[str, str] = {}
    for name in ("cat", "tee", "stat", "ls"):
        full = _trusted_which(name)
        if full is None:
            log.debug("elevated_io: helper missing: %s", name)
            return None
        helpers[name] = full
    return _Pkexec(binary=pkexec, helpers=helpers)


def is_pkexec_available() -> bool:
    """True iff pkexec + the helper binaries are on PATH."""
    return _resolve_helpers() is not None


def _run(
    argv: list[str], *, stdin: bytes | None = None, capture_output: bool = True
) -> subprocess.CompletedProcess:
    """Wrapper around subprocess.run with our fixed policy:
    no shell, no env passthrough beyond the minimum, bounded timeout."""
    # pkexec itself scrubs the env; we still pass a minimal PATH so
    # helpers that re-exec children resolve normally.
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
    try:
        return subprocess.run(
            argv,
            input=stdin,
            capture_output=capture_output,
            env=env,
            timeout=ELEVATED_TIMEOUT_SECS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ElevatedIOError(
            f"elevated_io: command timed out after {ELEVATED_TIMEOUT_SECS}s"
        ) from exc


#: stderr kept from a capped run; the rest is read and dropped.
_MAX_STDERR_BYTES = 64 * 1024


def _abandon(proc: subprocess.Popen) -> None:
    """Stop a capped run early. The helper runs as root once pkexec has
    authorised it, so a kill from us may be refused; closing our end of
    its stdout ends it with SIGPIPE on its next write either way."""
    for pipe in (proc.stdout, proc.stderr):
        if pipe is not None:
            try:
                pipe.close()
            except OSError:
                pass
    try:
        proc.kill()
    except (OSError, ProcessLookupError):
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        log.warning("elevated_io: helper pid %d did not exit after abort", proc.pid)


def _run_capped(argv: list[str], cap: int, action: str) -> subprocess.CompletedProcess:
    """Like :func:`_run` without stdin, but stdout is read as it arrives
    and the run is abandoned once it passes *cap* bytes or the timeout,
    so a helper reading ``/dev/zero`` cannot fill memory."""
    import selectors
    import time

    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    out = bytearray()
    err = bytearray()
    deadline = time.monotonic() + ELEVATED_TIMEOUT_SECS
    try:
        with selectors.DefaultSelector() as sel:
            sel.register(proc.stdout, selectors.EVENT_READ)
            sel.register(proc.stderr, selectors.EVENT_READ)
            open_pipes = 2
            while open_pipes:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ElevatedIOError(
                        f"elevated_io: command timed out after {ELEVATED_TIMEOUT_SECS}s"
                    )
                for key, _events in sel.select(remaining):
                    chunk = os.read(key.fd, 1024 * 1024)
                    if not chunk:
                        sel.unregister(key.fileobj)
                        open_pipes -= 1
                    elif key.fileobj is proc.stdout:
                        out += chunk
                        if len(out) > cap:
                            raise ElevatedOutputTooLarge(
                                f"elevated_io: {action}: output exceeds {cap} byte cap"
                            )
                    elif len(err) < _MAX_STDERR_BYTES:
                        err += chunk[: _MAX_STDERR_BYTES - len(err)]
            remaining = max(0.0, deadline - time.monotonic())
            try:
                returncode = proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired as exc:
                raise ElevatedIOError(
                    f"elevated_io: command timed out after {ELEVATED_TIMEOUT_SECS}s"
                ) from exc
    except BaseException:
        _abandon(proc)
        raise
    for pipe in (proc.stdout, proc.stderr):
        pipe.close()
    return subprocess.CompletedProcess(argv, returncode, bytes(out), bytes(err))


def _check_exit(proc: subprocess.CompletedProcess, action: str) -> None:
    """pkexec returns 126 when the user cancelled the auth dialog and
    127 when authorisation was denied. Everything else that isn't 0
    is a real error from the helper we invoked."""
    if proc.returncode == 0:
        return
    stderr = (proc.stderr or b"").decode("utf-8", errors="replace").strip()
    if proc.returncode in (126, 127):
        raise ElevatedCancelled(f"elevated_io: user cancelled / polkit denied {action}")
    raise ElevatedIOError(f"elevated_io: {action} failed with rc={proc.returncode}: {stderr!r}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def elevated_read(backend, path: str) -> bytes:
    """Return the bytes of *path* on *backend*, going through pkexec.

    Raises :class:`ElevatedNotAvailable` when the backend is remote
    or pkexec is missing, :class:`ElevatedCancelled` when the user
    dismisses the prompt, :class:`ElevatedOutputTooLarge` when the
    file exceeds :data:`MAX_OUTPUT_SIZE`.
    """
    _require_local(backend)
    abs_path = _validate_path(path)
    helpers = _resolve_helpers()
    if helpers is None:
        raise ElevatedNotAvailable(
            "pkexec or one of its required helpers (cat/tee/stat/ls) is not installed"
        )
    # The cap is enforced while reading: the run is abandoned as soon
    # as cat has printed more than MAX_OUTPUT_SIZE bytes.
    proc = _run_capped(
        [helpers.binary, "--disable-internal-agent", helpers.helpers["cat"], "--", abs_path],
        MAX_OUTPUT_SIZE,
        f"read {abs_path!r}",
    )
    _check_exit(proc, f"read {abs_path!r}")
    return proc.stdout or b""


def elevated_write(backend, path: str, data: bytes) -> None:
    """Write *data* to *path* via pkexec + ``tee``.

    ``tee`` is used instead of redirection because the redirection
    would happen in the caller's shell (we avoid shell entirely).
    """
    _require_local(backend)
    abs_path = _validate_path(path)
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")
    if len(data) > MAX_WRITE_SIZE:
        raise ElevatedOutputTooLarge(f"elevated_write: payload {len(data)} > {MAX_WRITE_SIZE}")
    helpers = _resolve_helpers()
    if helpers is None:
        raise ElevatedNotAvailable("pkexec not available")
    # ``tee`` writes stdin to the file. ``> /dev/null`` would need a
    # shell; we just discard tee's stdout by ignoring proc.stdout.
    proc = _run(
        [helpers.binary, "--disable-internal-agent", helpers.helpers["tee"], "--", abs_path],
        stdin=bytes(data),
    )
    _check_exit(proc, f"write {abs_path!r}")


def elevated_stat(backend, path: str) -> dict:
    """Return a small dict ``{mode, size, uid, gid, mtime}`` for a
    path the user can't normally stat. The format string is fixed
    (Unix stat format %a / %s / %u / %g / %Y)."""
    _require_local(backend)
    abs_path = _validate_path(path)
    helpers = _resolve_helpers()
    if helpers is None:
        raise ElevatedNotAvailable("pkexec not available")
    fmt = "%a\t%s\t%u\t%g\t%Y"
    proc = _run(
        [
            helpers.binary,
            "--disable-internal-agent",
            helpers.helpers["stat"],
            "-c",
            fmt,
            "--",
            abs_path,
        ],
    )
    _check_exit(proc, f"stat {abs_path!r}")
    try:
        text = (proc.stdout or b"").decode("utf-8", errors="replace").strip()
        mode, size, uid, gid, mtime = text.split("\t")
        return {
            "mode": int(mode, 8),
            "size": int(size),
            "uid": int(uid),
            "gid": int(gid),
            "mtime": int(mtime),
        }
    except (ValueError, IndexError) as exc:
        raise ElevatedIOError(
            f"elevated_stat {abs_path!r}: couldn't parse stat output: {exc}"
        ) from exc


__all__ = [
    "ELEVATED_TIMEOUT_SECS",
    "ElevatedCancelled",
    "ElevatedIOError",
    "ElevatedNotAvailable",
    "ElevatedOutputTooLarge",
    "MAX_OUTPUT_SIZE",
    "MAX_PATH_LEN",
    "MAX_WRITE_SIZE",
    "elevated_read",
    "elevated_stat",
    "elevated_write",
    "is_pkexec_available",
]
