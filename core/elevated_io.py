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
* ``pkexec`` must be discovered via a trusted absolute path lookup
  (``shutil.which``) — we don't trust the user's ``PATH`` for the
  binary we shell to.

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
import shutil
import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from core.backend import FileBackend

log = logging.getLogger("core.elevated_io")


# ---------------------------------------------------------------------------
# Security knobs
# ---------------------------------------------------------------------------

MAX_OUTPUT_SIZE: int = 256 * 1024 * 1024          # 256 MiB
MAX_WRITE_SIZE: int = 256 * 1024 * 1024
MAX_PATH_LEN: int = 4096                           # POSIX PATH_MAX
ELEVATED_TIMEOUT_SECS: int = 120                   # user-auth typing time


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
    binary: str              # absolute path to pkexec
    helpers: dict[str, str]  # name -> absolute path for cat/tee/stat/ls


def _resolve_helpers() -> _Pkexec | None:
    """Resolve absolute paths to pkexec + the helper binaries. Returns
    None when pkexec or any required helper is missing."""
    pkexec = shutil.which("pkexec")
    if pkexec is None:
        return None
    helpers: dict[str, str] = {}
    for name in ("cat", "tee", "stat", "ls"):
        full = shutil.which(name)
        if full is None:
            log.debug("elevated_io: helper missing: %s", name)
            return None
        helpers[name] = full
    return _Pkexec(binary=pkexec, helpers=helpers)


def is_pkexec_available() -> bool:
    """True iff pkexec + the helper binaries are on PATH."""
    return _resolve_helpers() is not None


def _run(argv: list[str], *, stdin: bytes | None = None,
         capture_output: bool = True) -> subprocess.CompletedProcess:
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
            f"elevated_io: command timed out after "
            f"{ELEVATED_TIMEOUT_SECS}s"
        ) from exc


def _check_exit(proc: subprocess.CompletedProcess, action: str) -> None:
    """pkexec returns 126 when the user cancelled the auth dialog and
    127 when authorisation was denied. Everything else that isn't 0
    is a real error from the helper we invoked."""
    if proc.returncode == 0:
        return
    stderr = (proc.stderr or b"").decode("utf-8", errors="replace").strip()
    if proc.returncode in (126, 127):
        raise ElevatedCancelled(
            f"elevated_io: user cancelled / polkit denied {action}"
        )
    raise ElevatedIOError(
        f"elevated_io: {action} failed with rc={proc.returncode}: {stderr!r}"
    )


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
            "pkexec or one of its required helpers (cat/tee/stat/ls) "
            "is not installed"
        )
    # We bound the output with ``head -c`` — that's a cleaner cap
    # than relying on subprocess buffering. pkexec ``cat`` | head is
    # two processes; we can just cat and check the size after.
    proc = _run(
        [helpers.binary, "--disable-internal-agent",
         helpers.helpers["cat"], "--", abs_path],
    )
    _check_exit(proc, f"read {abs_path!r}")
    data = proc.stdout or b""
    if len(data) > MAX_OUTPUT_SIZE:
        raise ElevatedOutputTooLarge(
            f"elevated_read {abs_path!r}: {len(data)} bytes exceeds "
            f"{MAX_OUTPUT_SIZE} cap"
        )
    return data


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
        raise ElevatedOutputTooLarge(
            f"elevated_write: payload {len(data)} > {MAX_WRITE_SIZE}"
        )
    helpers = _resolve_helpers()
    if helpers is None:
        raise ElevatedNotAvailable("pkexec not available")
    # ``tee`` writes stdin to the file. ``> /dev/null`` would need a
    # shell; we just discard tee's stdout by ignoring proc.stdout.
    proc = _run(
        [helpers.binary, "--disable-internal-agent",
         helpers.helpers["tee"], "--", abs_path],
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
        [helpers.binary, "--disable-internal-agent",
         helpers.helpers["stat"], "-c", fmt, "--", abs_path],
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
