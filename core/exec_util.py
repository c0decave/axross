"""Shared pieces of the backends' ``exec()``: environment checks,
shell quoting and output caps, so Telnet, rsh, ADB and WinRM answer
exactly like SSHSession.exec does."""

from __future__ import annotations

import re
import shlex

from models.exec_result import ExecResult

_ENV_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

DEFAULT_STDOUT_CAP = 1024 * 1024
DEFAULT_STDERR_CAP = 64 * 1024


def checked_env(env: dict[str, str] | None, label: str) -> dict[str, str]:
    """*env* with every key a shell name and no NUL in a value."""
    for key, value in (env or {}).items():
        if not _ENV_KEY.fullmatch(key):
            raise OSError(f"{label}: env key {key!r} must match [A-Za-z_][A-Za-z0-9_]* (refusing to send)")
        if "\x00" in str(value):
            raise OSError(f"{label}: env value of {key!r} contains NUL (refusing to send)")
    return dict(env or {})


def sh_env_prefix(env: dict[str, str] | None, label: str) -> str:
    """``export K='v'; `` for a POSIX shell, values quoted."""
    return "".join(f"export {k}={shlex.quote(str(v))}; " for k, v in checked_env(env, label).items())


def capped(returncode: int, stdout: bytes, stderr: bytes, stdout_cap: int, stderr_cap: int) -> ExecResult:
    return ExecResult(
        returncode=returncode,
        stdout=bytes(stdout[:stdout_cap]),
        stderr=bytes(stderr[:stderr_cap]),
        truncated_stdout=len(stdout) > stdout_cap,
        truncated_stderr=len(stderr) > stderr_cap,
    )
