"""Shared pieces of the backends' ``exec()``: environment checks,
shell quoting and output caps, so Telnet, rsh, ADB and WinRM answer
exactly like SSHSession.exec does."""

from __future__ import annotations

import errno
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
            raise OSError(
                f"{label}: env key {key!r} must match [A-Za-z_][A-Za-z0-9_]* (refusing to send)"
            )
        if "\x00" in str(value):
            raise OSError(f"{label}: env value of {key!r} contains NUL (refusing to send)")
    return dict(env or {})


def sh_env_prefix(env: dict[str, str] | None, label: str) -> str:
    """``export K='v'; `` for a POSIX shell, values quoted."""
    return "".join(
        f"export {k}={shlex.quote(str(v))}; " for k, v in checked_env(env, label).items()
    )


#: Hex digits per digest of the algorithms the remote ``*sum`` tools offer.
_DIGEST_HEX_LEN = {"sha256": 64, "sha1": 40, "md5": 32}

#: Exit status of a POSIX shell whose command was not found / not executable.
COMMAND_NOT_FOUND = (126, 127)


def digest_from_sum_output(output: str, algorithm: str) -> str:
    """The lowercase hex digest in ``sha256sum`` / ``md5sum`` output, or "".

    GNU coreutils escape a file name holding a backslash or a newline and
    mark that line with a leading backslash (``\\<hex>  a\\\\b``); the
    marker is not part of the digest. Anything that is not a digest of
    the algorithm's length is "" - the caller then hashes the stream.
    """
    for line in (output or "").splitlines():
        words = line.split()
        if not words:
            continue
        digest = words[0].removeprefix("\\").lower()
        expected = _DIGEST_HEX_LEN.get(algorithm)
        if expected and len(digest) == expected and all(c in "0123456789abcdef" for c in digest):
            return digest
        return ""
    return ""


def ls_dir_operand(path: str) -> str:
    """*path* as the operand of an ``ls -la`` that lists a folder.

    ``ls -l`` lists a symlink operand ITSELF; a folder reached through a
    symlink then showed one entry - the link. A trailing slash makes path
    resolution follow the link on every POSIX ls (GNU, BSD, busybox,
    toybox, AIX, Solaris), where -H is not universal.
    """
    return path if path.endswith("/") else path + "/"


def ls_error(where: str, message: str) -> OSError:
    """The OSError for an ``ls`` refusal, typed by its wording (GNU,
    busybox and toybox say the same words).

    Only "No such file or directory" is a FileNotFoundError: callers
    answer exists() = False from it alone, so a refused permission or a
    message nobody recognises stays an OSError that means "cannot tell".
    """
    for text, kind, code in (
        ("No such file or directory", FileNotFoundError, errno.ENOENT),
        ("Permission denied", PermissionError, errno.EACCES),
        ("Not a directory", NotADirectoryError, errno.ENOTDIR),
    ):
        if text in message:
            return kind(code, f"{where}: {message}")
    return OSError(f"{where}: {message}")


_KIND_DIR = "axross-kind:dir"
_KIND_OTHER = "axross-kind:other"


def path_kind_command(path: str) -> str:
    """A POSIX ``sh`` command that prints what *path* is, for
    :func:`path_kind`. ``ls -d`` names the entry itself (a dangling link
    too) and, under LC_ALL=C, says why it cannot; ``test`` alone exits 1
    for "missing" and "may not search" alike. Ends in ``false`` rather
    than ``exit``: a Telnet shell must survive the probe."""
    q = shlex.quote(path)
    return (
        f"if test -d {q}; then echo {_KIND_DIR}; "
        f"elif LC_ALL=C ls -d -- {q} >/dev/null; then echo {_KIND_OTHER}; "
        "else false; fi"
    )


def path_kind(where: str, output: str, code: int) -> str | None:
    """``"dir"``, ``"other"`` or None (not there) from the answer to
    :func:`path_kind_command`, with stderr in *output*. Only "No such
    file or directory" and "Not a directory" are None; any other failure
    or an answer without the marker raises - exists() callers take None
    as the go-ahead to write."""
    lines = output.strip().splitlines()
    if code == 0:
        if lines and lines[-1].strip() == _KIND_DIR:
            return "dir"
        if lines and lines[-1].strip() == _KIND_OTHER:
            return "other"
        raise OSError(f"{where}: unreadable answer: {output[:200]!r}")
    err = ls_error(where, output.strip()[:500] or f"exit {code}")
    if isinstance(err, (FileNotFoundError, NotADirectoryError)):
        return None
    raise err


def capped(
    returncode: int, stdout: bytes, stderr: bytes, stdout_cap: int, stderr_cap: int
) -> ExecResult:
    return ExecResult(
        returncode=returncode,
        stdout=bytes(stdout[:stdout_cap]),
        stderr=bytes(stderr[:stderr_cap]),
        truncated_stdout=len(stdout) > stdout_cap,
        truncated_stderr=len(stderr) > stderr_cap,
    )
