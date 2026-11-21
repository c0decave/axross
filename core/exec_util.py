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


def _not_found_patterns(tool: str) -> tuple[re.Pattern[str], ...]:
    name = re.escape(tool)
    return (
        # bash "bash: line 1: sha256sum: command not found", dash / busybox
        # "sh: 1: sha256sum: not found" - the whole line, so that the tool's
        # own complaint about a FILE named like that does not count.
        re.compile(rf"(?:^|[\s:]){name}: (?:command )?not found\s*$", re.M),
        # zsh "zsh:1: command not found: sha256sum"
        re.compile(rf"command not found: {name}\s*$", re.M),
        # Windows OpenSSH with cmd.exe as its shell (exit 1):
        # "'sha256sum' is not recognized as an internal or external command"
        re.compile(rf"^'{name}' is not recognized as an internal or external command", re.M),
        # ... and with PowerShell: "The term 'sha256sum' is not recognized
        # as the name of a cmdlet" (PowerShell 7: "as a name of a cmdlet")
        re.compile(rf"The term '{name}' is not recognized as (?:the|a) name", re.M),
    )


def command_missing(returncode: int, stderr: str, tool: str) -> bool:
    """Whether a remote command failed because *tool* does not exist there.

    A POSIX shell says so with exit 126/127; cmd.exe and PowerShell (the
    shells of Windows OpenSSH) exit 1 and say it only in words - without
    them a copy of 500 files opened 500 channels to hear the same answer.
    """
    if returncode in COMMAND_NOT_FOUND:
        return True
    if returncode == 0 or not stderr:
        return False
    return any(p.search(stderr) for p in _not_found_patterns(tool))


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


#: What a backslash-marked ``sha256sum`` line writes for a character of a
#: name (GNU coreutils: backslash and newline, since 9.0 carriage return).
_SUM_ESCAPES = {ord("\\"): b"\\", ord("n"): b"\n", ord("r"): b"\r"}


def _unescape_sum_name(name: bytes) -> bytes | None:
    """A name of a backslash-marked sum line, unescaped; None for an escape
    GNU does not write (the line is not trusted then)."""
    out = bytearray()
    i = 0
    while i < len(name):
        byte = name[i]
        if byte != 0x5C:  # "\"
            out.append(byte)
            i += 1
            continue
        if i + 1 >= len(name) or name[i + 1] not in _SUM_ESCAPES:
            return None
        out += _SUM_ESCAPES[name[i + 1]]
        i += 2
    return bytes(out)


def digests_from_sum_output(output: bytes, names: list[bytes], algorithm: str) -> dict[bytes, str]:
    """The lowercase hex digest of each of *names* (the operands as the
    command got them, bytes) in the output of one ``sha256sum -- n1 n2 ...``.

    A line is ``[\\]<hex><space><space or *><name>``; a leading backslash
    marks a name with ``\\\\``, ``\\n`` (and ``\\r``) escaped (GNU coreutils), other
    bytes of a name - blanks, non-UTF-8 - come as they are. Only a line
    whose digest has the algorithm's length and whose name is one of
    *names* counts, and a name claimed by two lines by none of them: a
    sum tool that does not escape (busybox) splits a name with a newline
    over two lines, and its first part may be another operand's name. A
    name without a usable line is not in the result - the caller checks
    that file another way. A file the tool could not read has no line
    (its error is on stderr)."""
    expected = _DIGEST_HEX_LEN.get(algorithm)
    wanted = set(names)
    found: dict[bytes, str] = {}
    claimed: set[bytes] = set()
    for line in (output or b"").split(b"\n"):
        escaped = line.startswith(b"\\")
        if escaped:
            line = line[1:]
        if not expected or len(line) < expected + 2:
            continue
        digest, sep, name = line[:expected], line[expected:expected + 2], line[expected + 2:]
        if sep not in (b"  ", b" *"):
            continue
        try:
            text = digest.decode("ascii").lower()
        except UnicodeDecodeError:
            continue
        if any(c not in "0123456789abcdef" for c in text):
            continue
        if escaped:
            name = _unescape_sum_name(name)
            if name is None:
                continue
        if name not in wanted:
            continue
        if name in claimed:
            found.pop(name, None)  # two lines for one name: neither is trusted
            continue
        claimed.add(name)
        found[name] = text
    return found


def shell_path(path: str) -> str:
    """*path* quoted as an operand of a remote shell command.

    A relative path that starts with ``-`` gets ``./`` in front first:
    ``ls -ld -R`` listed the current folder recursively, ``cat -`` read
    stdin, ``readlink -f`` lost its operand. Not every command on every
    box (toybox, busybox, old Unix ``test``) honours ``--``; every one
    reads ``./-R`` as a name. Absolute paths are never touched.
    """
    if path.startswith("-"):
        path = "./" + path
    return shlex.quote(path)


def ls_dir_operand(path: str) -> str:
    """*path* as the operand of an ``ls -la`` that lists a folder.

    ``ls -l`` lists a symlink operand ITSELF; a folder reached through a
    symlink then showed one entry - the link. A trailing slash makes path
    resolution follow the link on every POSIX ls (GNU, BSD, busybox,
    toybox, AIX, Solaris), where -H is not universal.
    """
    return path if path.endswith("/") else path + "/"


def ls_error(where: str, message: str) -> OSError:
    """The OSError for an ``ls`` (``stat``, ``rm``, ``mkdir``) refusal,
    typed by its wording (GNU, busybox and toybox say the same words).

    Only "No such file or directory" is a FileNotFoundError: callers
    answer exists() = False from it alone, so a refused permission or a
    message nobody recognises stays an OSError that means "cannot tell".
    "File exists" (mkdir of an existing name) is a FileExistsError.
    """
    for text, kind, code in (
        ("No such file or directory", FileNotFoundError, errno.ENOENT),
        ("Permission denied", PermissionError, errno.EACCES),
        ("Not a directory", NotADirectoryError, errno.ENOTDIR),
        ("File exists", FileExistsError, errno.EEXIST),
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


#: What the operation needs *path* to be, and the error for each other
#: kind: open_read a file, list_dir a folder, mkdir nothing at all.
_REFUSED_AS = {
    "file": {None: (FileNotFoundError, errno.ENOENT, "not found"),
             "dir": (IsADirectoryError, errno.EISDIR, "is a folder")},
    "dir": {None: (FileNotFoundError, errno.ENOENT, "not found"),
            "other": (NotADirectoryError, errno.ENOTDIR, "not a folder")},
    "absent": {"dir": (FileExistsError, errno.EEXIST, "exists"),
               "other": (FileExistsError, errno.EEXIST, "a file of that name exists")},
}


def refused_as(where: str, path: str, message: str, kind, *, wanted: str) -> OSError:
    """The OSError for a shell command on *path* that failed with
    *message* - typed by what *path* turns out to be, asked with
    ``kind()`` (``"dir"`` / ``"other"`` / None, as :func:`path_kind`)
    only now that the command failed. ``wanted`` is ``"file"``
    (open_read: missing is FileNotFoundError, a folder IsADirectoryError),
    ``"dir"`` (list_dir: NotADirectoryError for a file) or ``"absent"``
    (mkdir: FileExistsError). A redirect's wording differs per shell
    (dash: "cannot open x: No such file"), and some transports carry no
    stderr at all, so the wording alone could not type it. When the
    probe fails, or the kind is the wanted one, :func:`ls_error` types
    the message."""
    try:
        found = kind()
    except Exception:  # noqa: BLE001 - no answer: the wording decides
        return ls_error(where, message)
    typed = _REFUSED_AS[wanted].get(found)
    if typed is None:
        return ls_error(where, message)
    cls, code, why = typed
    return cls(code, f"{where}: {why} ({message})" if message else f"{where}: {why}", path)


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
