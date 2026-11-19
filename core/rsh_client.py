"""rsh / rcp / rlogin (BSD r-services) FileBackend.

Legacy plaintext remote-shell suite, port 514 (rsh) / 513 (rlogin).
Still encountered on AIX, Solaris, HP-UX, embedded gear, lab networks.
We support the *client* side via the system's ``rsh`` binary so the
host's setuid wrapper can bind to the privileged source port the
protocol requires — running axross as an unprivileged user otherwise
would not be able to talk to a real rshd.

Capabilities:

* **Read / write / list / delete** by shelling out to ``rsh host
  '<command>'`` for ``cat`` / ``ls -la`` / ``rm`` / ``mkdir`` /
  ``mv`` etc.
* **Server-side copy** maps to ``rsh host 'cp src dst'`` — bytes
  never round-trip through the client.
* **rcp** sits on the same wire (the rcp binary uses rsh under the
  hood); ``copy()`` plus a same-host ``rename()`` covers the useful
  rcp surface. We don't shell out to a separate ``rcp`` binary
  because every modern distribution ships rcp as ``rsh host
  'cat'``-style anyway.

Security notes:

* rsh sends username + command in cleartext. We log a loud warning
  on every session; profile UI flags this protocol as legacy.
* Authentication is host-based (``.rhosts`` / ``hosts.equiv``) so
  passwords never traverse the wire — they aren't part of the
  protocol. The ``password`` profile field is ignored.
* For interactive shell sessions, prefer rlogin (handled by
  :class:`ui.terminal_pane.TerminalPaneWidget` with ``mode="rlogin"``).

Requires the ``rsh`` system binary on PATH (Debian package:
``rsh-client`` — provides ``/usr/bin/rsh``).
"""

from __future__ import annotations

import errno
import logging
import posixpath
import re
import secrets
import shlex
import shutil
import subprocess
import threading
import time
from dataclasses import replace
from datetime import datetime
from typing import IO, TYPE_CHECKING

if TYPE_CHECKING:
    from models.exec_result import ExecResult

from core import transfer_hooks
from core.backend import SessionLifecycle
from core.subprocess_env import clean_child_env
from core.telnet_client import copy_command, ls_records, remove_command, rename_command
from models.file_item import FileItem
from security.protocol_line_split import split_lf_only_stream

log = logging.getLogger(__name__)


DEFAULT_TIMEOUT = 30.0
#: cp / mv / rm -r / sha256sum on the server: a large copy or hash takes
#: minutes, and the 30 s time-out failed it while it was still running.
TREE_OP_TIMEOUT = 3600.0
#: A transfer fails only when nothing moved for this long (not when a
#: large file simply takes longer than a fixed time).
TRANSFER_IDLE_TIMEOUT = 120.0
#: Sanity cap on one download (it streams into a spool on disk now; the
#: old in-memory cap of 64 MiB made larger files unreadable).
MAX_FILE_BYTES = 64 * 1024**3
_PIECE = 1024 * 1024


# Pattern matching `ls -la` POSIX output. Loose by design — different
# Unix flavours format times slightly differently; we extract what we
# can and treat the rest as best-effort.
_LS_RE = re.compile(
    r"^(?P<perms>[bcdlsp\-][rwxsStTl\-]{9})[.+@]?\s+"  # mode; . SELinux, + ACL, @ xattr
    r"\d+\s+"  # link count
    r"\S+\s+\S+\s+"  # user, group
    r"(?P<size>\d+|\d+,\s*\d+)\s+"  # size, or "major, minor" for a device
    r"(?P<date>\S+\s+\S+\s+\S+) "  # date triplet, then ONE space
    r"(?P<name>.+)$"  # the name exactly: blanks at either end belong to it
)


class RshError(OSError):
    """Raised on rsh non-zero exit / unexpected stderr."""


def _validate_path(path: str) -> str:
    # rsh quotes via ``shlex.quote``, but rshd hands the command line to a
    # login shell and a control character (CR / LF / NUL, a terminal's
    # line-editing keys) is safe on none of those layers: refused up-front,
    # the one rule Telnet, ADB, SCP and FTP share.
    from core.path_policy import refuse_control_chars

    refuse_control_chars(path, "rsh")
    # Refuse paths that start with '-' so they cannot be re-interpreted
    # as flags by the remote tool (``head -c -r`` etc.). Callers should
    # also pass the explicit ``--`` separator in the command string.
    base = path.lstrip("/")
    if base.startswith("-"):
        raise OSError(
            f"rsh path may not start with '-' (would be interpreted "
            f"as a flag by the remote tool): {path!r}"
        )
    return path


def _ensure_rsh_available() -> str:
    """Return the absolute path to the system ``rsh`` binary, or raise
    a clear ImportError pointing the user at the right package."""
    which = shutil.which("rsh")
    if not which:
        raise ImportError(
            "rsh backend requires the system ``rsh`` binary. "
            "Install via your distro's ``rsh-client`` / ``netkit-rsh`` package.",
        )
    return which


# ---------------------------------------------------------------------------
# Public session
# ---------------------------------------------------------------------------


class RshSession(SessionLifecycle):
    """rsh-as-filesystem FileBackend.

    Instantiated with at minimum ``host`` and ``username``. Trusts
    the system ``rsh`` binary's setuid wrapper for privileged-port
    handling; unauthenticated rshd servers reject any connection
    that isn't from a low source port, and a non-setuid rsh will
    fail in an obvious way (the constructor's probe surfaces it)."""

    supports_symlinks = False
    supports_hardlinks = False

    def __init__(
        self,
        host: str,
        port: int = 514,
        username: str = "",
        password: str = "",
        timeout: float = DEFAULT_TIMEOUT,
        address_family: str = "auto",
        **_ignored,
    ):
        from core.proxy import refuse_unsupported_proxy

        refuse_unsupported_proxy(
            "rsh",
            _ignored.get("proxy_type", "none"),
            _ignored.get("proxy_host", ""),
            "rsh needs a reverse stderr connection from the server to the client and a "
            "privileged source port, which no forward proxy can provide.",
        )
        # rsh reads its options with getopt: a host "-lroot" was the option
        # -l root, and the command became the host name.
        if not host or host.startswith("-") or any(ch.isspace() for ch in host):
            raise OSError(errno.EINVAL, f"rsh: not a host name: {host!r}")
        if username.startswith("-"):
            raise OSError(errno.EINVAL, f"rsh: not a user name: {username!r}")
        self._host = host
        self._port = int(port)
        self._username = username
        self._timeout = float(timeout)
        # The profile's IP version: rsh -4 / -6 (netkit, inetutils).
        self._family_flag = {"ipv4": "-4", "ipv6": "-6"}.get(address_family or "auto", "")
        self._rsh = _ensure_rsh_available()
        # Plaintext-credential warning. rsh negotiation never carries
        # the password (host-based auth) but sends username + command
        # in the clear, so flag a single line so a misconfigured
        # profile doesn't slip past silently.
        log.warning(
            "rsh backend connecting to %s@%s:%d in PLAINTEXT — "
            "every command + filename traverses the wire unencrypted. "
            "Use SFTP / SCP for anything sensitive.",
            username,
            host,
            self._port,
        )
        # Cheap probe: ``echo axross`` tells us auth + connectivity in
        # one round-trip. A trust failure surfaces as non-zero exit.
        try:
            out = self._run_remote("echo axross-rsh-probe")
        except Exception as exc:
            raise OSError(
                f"rsh probe to {host} failed: {exc}. Verify .rhosts / "
                "hosts.equiv on the server permits this user."
            ) from exc
        if "axross-rsh-probe" not in out.decode("utf-8", "replace"):
            raise OSError(f"rsh probe to {host} returned unexpected payload: {out!r}")

    # ------------------------------------------------------------------
    # Identity / lifecycle
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return f"rsh: {self._username}@{self._host}:{self._port}"

    @property
    def connected(self) -> bool:
        return True  # stateless — every op spawns a fresh rsh.

    def close(self) -> None:
        pass

    def disconnect(self) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def home(self) -> str:
        return "/"

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        cleaned = [s for s in (p.strip("/") for p in parts) if s]
        if not cleaned:
            return "/"
        return "/" + "/".join(cleaned)

    def parent(self, path: str) -> str:
        return posixpath.dirname(path.rstrip("/")) or "/"

    def normalize(self, path: str) -> str:
        if not path:
            return "/"
        if not path.startswith("/"):
            path = "/" + path
        return posixpath.normpath(path) or "/"

    # ------------------------------------------------------------------
    # Remote execution
    # ------------------------------------------------------------------

    def _run_status(
        self, command: str, *, stdin: bytes | None = None, timeout: float | None = None
    ) -> tuple[int, bytes, bytes]:
        """Execute ``command`` on the remote via rsh; return the remote
        exit status, stdout and stderr. A failed connection or a cut
        stream raises :class:`RshError`.

        The rsh protocol carries stdout and stderr but not the remote
        command's exit status (classic rsh exits 0 whenever the
        connection worked), so the command reports it itself: a trailer
        line with a per-call random tag. No trailer means the stream was
        cut short, and that is an error too, never a short result.
        """
        tag, argv = self._argv(command)
        log.debug("rsh exec: %s", " ".join(shlex.quote(a) for a in argv))
        # No input: stdin is /dev/null, not axross' own (the terminal it
        # was started from, which rsh forwarded to the server).
        io_kw = {"input": stdin} if stdin is not None else {"stdin": subprocess.DEVNULL}
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                timeout=timeout or self._timeout,
                check=False,
                env=clean_child_env(),
                **io_kw,
            )
        except subprocess.TimeoutExpired as exc:
            raise RshError(f"rsh timed out: {exc}") from exc
        err = (proc.stderr or b"").decode("utf-8", "replace").strip()
        if proc.returncode != 0:
            raise RshError(
                f"rsh '{command[:60]}...' on {self._host} exited {proc.returncode}: {err}"
            )
        status, out = self._split_status(command, tag, proc.stdout or b"", err)
        return status, out, proc.stderr or b""

    def _argv(self, command: str) -> tuple[str, list[str]]:
        """The per-call status tag and the rsh command line for *command*."""
        tag = f"__AXROSS_RSH_STATUS_{secrets.token_hex(8)}__"
        # sh -c: the login shell rshd hands the command to may be csh,
        # which has no "$?"; one line, as csh rejects a quoted newline.
        script = f"{command}; printf '\\n%s %d\\n' {tag} \"$?\""
        argv = [self._rsh]
        if getattr(self, "_family_flag", ""):
            argv.append(self._family_flag)
        if self._port and self._port != 514:
            # netkit-rsh accepts -p; some forks don't. Only add when
            # the user actually customised the port.
            argv += ["-p", str(self._port)]
        if self._username:
            argv += ["-l", self._username]
        argv += [self._host, f"sh -c {shlex.quote(script)}"]
        return tag, argv

    def _split_status(self, command: str, tag: str, out: bytes, err: str) -> tuple[int, bytes]:
        """(remote exit status, the output before the status trailer)."""
        marker = b"\n" + tag.encode() + b" "
        idx = out.rfind(marker)
        status = out[idx + len(marker) :].strip() if idx >= 0 else b""
        if idx < 0 or not out.endswith(b"\n") or not status.isdigit():
            raise RshError(
                f"rsh '{command[:60]}...' on {self._host}: output ended without the "
                f"remote exit status (connection cut?): {err}"
            )
        return int(status), out[:idx]

    def _spawn(self, command: str, *, stdin: bool) -> tuple[str, subprocess.Popen]:
        """*command* in a running rsh process (a streamed transfer): stdout
        and stderr piped, stdin piped when *stdin* else /dev/null."""
        tag, argv = self._argv(command)
        log.debug("rsh stream: %s", " ".join(shlex.quote(a) for a in argv))
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE if stdin else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=clean_child_env(),
        )
        return tag, proc

    def _run_remote(
        self, command: str, *, stdin: bytes | None = None, timeout: float | None = None
    ) -> bytes:
        """Like :meth:`_run_status`, but a non-zero exit raises
        :class:`RshError` carrying the captured stderr; returns stdout."""
        status, out, err = self._run_status(command, stdin=stdin, timeout=timeout)
        if status != 0:
            detail = err.decode("utf-8", "replace").strip()
            raise RshError(f"rsh '{command[:60]}...' on {self._host} exited {status}: {detail}")
        return out

    def exec(
        self,
        cmd: str,
        *,
        timeout: float | None = 30.0,
        stdin: bytes | None = None,
        stdout_cap: int = 1024 * 1024,
        stderr_cap: int = 64 * 1024,
        env: dict[str, str] | None = None,
    ) -> "ExecResult":
        """Run *cmd* on the host - same shape as ``SSHSession.exec``;
        the exit status is ``returncode``, stdin goes to the process."""
        from core.exec_util import capped, sh_env_prefix

        prefix = sh_env_prefix(env, "rsh exec")
        # Its own sh: 'exit' must not skip the status trailer.
        status, out, err = self._run_status(
            f"sh -c {shlex.quote(prefix + cmd)}", stdin=stdin, timeout=timeout
        )
        return capped(status, out, err, stdout_cap, stderr_cap)

    # ------------------------------------------------------------------
    # Read surface
    # ------------------------------------------------------------------

    def list_dir(self, path: str) -> list[FileItem]:
        path = _validate_path(self.normalize(path))
        # ``ls -la --time-style=long-iso`` would be nicer but isn't
        # universal on AIX / Solaris. Keep the safer plain ``ls -la``
        # and parse defensively.
        from core.exec_util import ls_dir_operand

        try:
            out = self._run_remote(f"ls -la {shlex.quote(ls_dir_operand(path))}")
        except OSError as exc:
            raise self._refused(f"rsh list_dir({path})", path, exc, wanted="dir") from exc
        items: list[FileItem] = []
        for raw, rest in ls_records(out.decode("utf-8", "replace"), _LS_RE.match):
            item = _parse_ls_line(raw, rest)
            if item is None or item.name in (".", ".."):
                continue
            items.append(item)
        return items

    def _kind(self, path: str) -> str | None:
        """"dir", "other" or None (not there), by :meth:`stat`."""
        try:
            return "dir" if self.stat(path).is_dir else "other"
        except (FileNotFoundError, NotADirectoryError):
            return None

    def _refused(self, where: str, path: str, exc: OSError, *, wanted: str) -> OSError:
        """*exc* of a failed command on *path*, typed by what *path* is
        (core.exec_util.refused_as); a timeout or a cut connection keeps
        its own error."""
        if isinstance(exc, (TimeoutError, ConnectionError)):
            return exc
        from core.exec_util import refused_as

        return refused_as(where, path, str(exc), lambda: self._kind(path), wanted=wanted)

    def stat(self, path: str) -> FileItem:
        item = self._stat(path)
        # normalize() drops the slash: "g/" answered with the file g.
        if path.endswith("/") and path.strip("/") and not (item.is_dir or item.is_link):
            raise NotADirectoryError(errno.ENOTDIR, f"rsh stat({path}): not a folder", path)
        return item

    def _stat(self, path: str) -> FileItem:
        path = _validate_path(self.normalize(path))
        if path == "/":
            return FileItem(
                name="/",
                is_dir=True,
                is_link=False,
                size=0,
                modified=datetime.fromtimestamp(0),
                permissions=0o755,
            )
        # The entry itself (-d: a folder is not expanded). It used to be
        # looked up in a listing of the parent, where a cut connection, a
        # refused parent and a missing parent all ended as "not found".
        from core.exec_util import ls_error

        # LC_ALL=C: rshd runs the command in the user's locale, and only the
        # C wording of "No such file or directory" is told apart (it also
        # outranks a LANGUAGE setting).
        status, out, err = self._run_status(f"LC_ALL=C ls -la -d {shlex.quote(path)}")
        if status != 0:
            raise ls_error(f"rsh stat({path})", err.decode("utf-8", "replace").strip())
        for raw, rest in ls_records(out.decode("utf-8", "replace"), _LS_RE.match):
            item = _parse_ls_line(raw, rest)
            if item is not None and item.name == path:
                return replace(item, name=posixpath.basename(path))
        raise OSError(f"rsh stat({path}): unreadable answer from ls: {out[:200]!r}")

    def is_dir(self, path: str) -> bool:
        """False for a missing path or one below a file; any other
        failure is an OSError (transfer_manager recurses on True)."""
        try:
            return self.stat(path).is_dir
        except (FileNotFoundError, NotADirectoryError):
            return False

    def _is_file(self, path: str) -> bool:
        """True for an entry that is not a folder (False when nothing is there)."""
        try:
            return not self.stat(path).is_dir
        except (FileNotFoundError, NotADirectoryError):
            return False

    def exists(self, path: str) -> bool:
        """False only when ``ls`` reports the path missing. A timeout, a
        cut connection, a refused permission or an unreadable answer is
        an OSError: server_side_copy(overwrite=False) and the transfer
        worker take False as the go-ahead to write."""
        try:
            self.stat(path)
            return True
        except (FileNotFoundError, NotADirectoryError):
            return False

    def open_read(self, path: str) -> IO[bytes]:
        """The file streamed through ``cat`` into a spool: progress per
        piece, Cancel kills the rsh process, a time-out only when nothing
        arrives for TRANSFER_IDLE_TIMEOUT. The status trailer after the
        content says whether ``cat`` read it all; a stream without it was
        cut. Above MAX_FILE_BYTES the read fails, never comes back short."""
        from core.read_spool import new_spool

        path = _validate_path(self.normalize(path))
        command = f"cat -- {shlex.quote(path)}"
        tag, proc = self._spawn(command, stdin=False)
        watch = _Watchdog(proc, TRANSFER_IDLE_TIMEOUT)
        err_buf = _Drain(proc.stderr)
        hooks = transfer_hooks.current()
        spool = new_spool(max_size=8 * 1024 * 1024)
        keep = len(tag) + 16  # the trailer "\n<tag> <status>\n" stays back
        carry = b""
        done = 0
        try:
            while True:
                piece = proc.stdout.read1(_PIECE)
                watch.moved()
                if not piece:
                    break
                carry += piece
                if len(carry) > keep:
                    spool.write(carry[:-keep])
                    done += len(carry) - keep
                    carry = carry[-keep:]
                if done > MAX_FILE_BYTES:
                    raise RshError(
                        f"rsh read of {path}: file is larger than the {MAX_FILE_BYTES} byte cap "
                        "for a single rsh read"
                    )
                if hooks is not None:
                    hooks.received(done)
            proc.wait(timeout=DEFAULT_TIMEOUT)
            if watch.fired:
                raise RshError(
                    f"rsh read of {path}: nothing arrived for {TRANSFER_IDLE_TIMEOUT:.0f} s"
                )
            err = err_buf.text()
            if proc.returncode != 0:
                raise RshError(
                    f"rsh '{command[:60]}' on {self._host} exited {proc.returncode}: {err}"
                )
            status, rest = self._split_status(command, tag, carry, err)
            if status != 0:
                exc = RshError(f"rsh '{command[:60]}' on {self._host} exited {status}: {err}")
                raise self._refused(f"rsh read({path})", path, exc, wanted="file")
            spool.write(rest)
            done += len(rest)
            if done > MAX_FILE_BYTES:
                raise RshError(
                    f"rsh read of {path}: file is larger than the {MAX_FILE_BYTES} byte cap "
                    "for a single rsh read"
                )
            if hooks is not None:
                hooks.received(done, done)
            spool.seek(0)
            return spool
        except BaseException:
            spool.close()
            raise
        finally:
            watch.stop()
            _end(proc)

    def readlink(self, path: str) -> str:
        path = _validate_path(self.normalize(path))
        out = self._run_remote(f"readlink -- {shlex.quote(path)}")
        return out.decode("utf-8", "replace").strip()

    # ------------------------------------------------------------------
    # Write surface
    # ------------------------------------------------------------------

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        from core.path_policy import refuse_folder_path

        # normalize() drops the slash: "x/" was written as a FILE "x".
        path = _validate_path(self.normalize(refuse_folder_path(path)))
        return _RshWriter(self, path, append=append)

    def remove(self, path: str, recursive: bool = False) -> None:
        path = _validate_path(self.normalize(path))
        # FileNotFoundError for a missing path: remove_command asks ls
        # first (rm -f alone reported success for it).
        from core.exec_util import ls_error

        try:
            self._run_remote(remove_command(path, recursive=recursive), timeout=TREE_OP_TIMEOUT)
        except OSError as exc:
            # The message ends in the remote stderr: ls's wording types it.
            raise ls_error(f"rsh remove({path})", str(exc)) from exc

    def mkdir(self, path: str) -> None:
        path = _validate_path(self.normalize(path))
        try:
            self._run_remote(f"mkdir -p -- {shlex.quote(path)}")
        except OSError as exc:
            # mkdir -p over a FILE: FileExistsError, not a bare OSError.
            raise self._refused(f"rsh mkdir({path})", path, exc, wanted="absent") from exc

    def rename(self, src: str, dst: str) -> None:
        from core.path_policy import refuse_folder_path

        src = _validate_path(self.normalize(src))
        # normalize() drops the slash: a file renamed to "x/" became "x". A
        # source that is not there goes on to mv, which says so.
        refuse_folder_path(dst, "rename to", source_is_file=lambda: self._is_file(src))
        dst = _validate_path(self.normalize(dst))
        # Plain mv moves src INTO an existing folder dst (review B6 twin).
        self._run_remote(rename_command(src, dst), timeout=TREE_OP_TIMEOUT)

    def chmod(self, path: str, mode: int) -> None:
        path = _validate_path(self.normalize(path))
        self._run_remote(f"chmod {oct(mode)[2:]} -- {shlex.quote(path)}")

    def copy(self, src: str, dst: str) -> None:
        """Server-side copy via remote ``cp``. Same wire as
        traditional rcp (which is implemented as rsh+cp on most
        systems anyway)."""
        src = _validate_path(self.normalize(src))
        dst = _validate_path(self.normalize(dst))
        self._run_remote(copy_command(src, dst, preserve=True), timeout=TREE_OP_TIMEOUT)

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        path = _validate_path(self.normalize(path))
        try:
            out = self._run_remote(f"df -P -- {shlex.quote(path)}").decode("utf-8", "replace")
        except RshError:
            return (0, 0, 0)
        # Parse second line of `df -P` output.
        lines = [ln for ln in split_lf_only_stream(out) if ln.strip()]
        if len(lines) < 2:
            return (0, 0, 0)
        parts = lines[-1].split()
        try:
            # df -P emits 1024-byte blocks → multiply.
            total = int(parts[1]) * 1024
            used = int(parts[2]) * 1024
            free = int(parts[3]) * 1024
            return total, used, free
        except (ValueError, IndexError):
            return (0, 0, 0)

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError("rsh has no version history")

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        path = _validate_path(self.normalize(path))
        tool = {"sha256": "sha256sum", "sha1": "sha1sum", "md5": "md5sum"}.get(algorithm)
        if not tool:
            return ""
        try:
            out = self._run_remote(
                f"{tool} -- {shlex.quote(path)}", timeout=TREE_OP_TIMEOUT
            ).decode("utf-8", "replace")
        except RshError:
            return ""
        from core.exec_util import digest_from_sum_output

        digest = digest_from_sum_output(out, algorithm)
        if not digest:
            return ""
        return f"{algorithm}:{digest}"


def _parse_ls_line(raw: str, rest: str = "") -> FileItem | None:
    """One ``ls -la`` line as a FileItem; None for the ``total`` line,
    an ``ls:`` message and anything else the pattern does not match.
    *rest*: the further lines of a name with a line break
    (:func:`core.telnet_client.ls_records`). The line is not stripped:
    blanks around a name are part of it, and "report " cut to "report"
    named another file, which a delete then removed."""
    line = raw
    if not line or line.startswith("total ") or line.startswith("ls:"):
        return None
    m = _LS_RE.match(line)
    if not m:
        return None
    name = m.group("name") + rest
    perms_text = m.group("perms")
    # Strip ``-> target`` for symlinks; we don't model them.
    if perms_text.startswith("l"):
        name = name.split(" -> ", 1)[0]
    try:
        size = int(m.group("size"))
    except ValueError:
        size = 0
    return FileItem(
        name=name,
        is_dir=perms_text.startswith("d"),
        is_link=perms_text.startswith("l"),
        size=size,
        modified=datetime.fromtimestamp(0),
        permissions=_perms_to_octal(perms_text),
    )


def _perms_to_octal(text: str) -> int:
    """Translate ``rwxr-xr-x`` style perms to octal ``0o755``. Ignores
    the leading file-type char and any setuid/setgid/sticky letters
    (we don't currently surface those bits)."""
    if len(text) < 10:
        return 0o644
    bits = 0
    for i, ch in enumerate(text[1:10]):
        bits |= (1 if ch != "-" else 0) << (8 - i)
    return bits


class _Watchdog:
    """Kills *proc* when :meth:`moved` was not called for *idle* seconds
    (a transfer that stalls; one that is merely long goes on)."""

    def __init__(self, proc: subprocess.Popen, idle: float) -> None:
        self._proc = proc
        self._idle = idle
        self._last = time.monotonic()
        self._stop = threading.Event()
        self.fired = False
        threading.Thread(target=self._run, daemon=True, name="rsh-watchdog").start()

    def moved(self) -> None:
        self._last = time.monotonic()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.wait(1.0):
            if time.monotonic() - self._last > self._idle:
                self.fired = True
                _end(self._proc)
                return


class _Drain:
    """Reads a pipe to its end in a thread (at most 64 KiB kept), so the
    process never blocks on a full pipe nobody reads."""

    def __init__(self, pipe) -> None:
        self._data = bytearray()
        self._thread = threading.Thread(target=self._run, args=(pipe,), daemon=True)
        self._thread.start()

    def _run(self, pipe) -> None:
        try:
            while True:
                chunk = pipe.read1(65536) if hasattr(pipe, "read1") else pipe.read(65536)
                if not chunk:
                    return
                if len(self._data) < 65536:
                    self._data += chunk[: 65536 - len(self._data)]
        except (OSError, ValueError):
            return

    def data(self) -> bytes:
        self._thread.join(DEFAULT_TIMEOUT)
        return bytes(self._data)

    def text(self) -> str:
        return self.data().decode("utf-8", "replace").strip()


def _end(proc: subprocess.Popen) -> None:
    """*proc* gone: killed if it still runs, reaped."""
    if proc.poll() is None:
        try:
            proc.kill()
        except OSError:
            pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


class _RshWriter:
    """File-like writer that streams into ``cat > path`` through a running
    rsh process: nothing is held in memory, the transfer engine's progress
    and Cancel act on the real upload, and a time-out comes only when the
    pipe takes nothing for TRANSFER_IDLE_TIMEOUT. close() reads the status
    trailer (a failed ``cat`` - no such folder, no permission - raises)."""

    def __init__(self, session: RshSession, path: str, append: bool = False):
        self._session = session
        self._path = path
        op = ">>" if append else ">"
        self._command = f"cat {op} {shlex.quote(path)}"
        self._tag, self._proc = session._spawn(self._command, stdin=True)
        self._watch = _Watchdog(self._proc, TRANSFER_IDLE_TIMEOUT)
        self._out = _Drain(self._proc.stdout)
        self._err = _Drain(self._proc.stderr)
        self._closed = False

    def write(self, data: bytes) -> int:
        if self._closed:
            raise OSError("writer closed")
        view = memoryview(data)
        try:
            for start in range(0, len(view), _PIECE):
                self._proc.stdin.write(view[start : start + _PIECE])
                self._proc.stdin.flush()
                self._watch.moved()
        except (OSError, ValueError) as exc:
            # cat (or the connection) ended early: say why.
            self._closed = True
            self._finish(cause=exc)
        return len(data)

    def _finish(self, cause: BaseException | None = None) -> None:
        proc = self._proc
        try:
            try:
                proc.stdin.close()
            except (OSError, ValueError):
                pass
            try:
                proc.wait(timeout=TRANSFER_IDLE_TIMEOUT)
            except subprocess.TimeoutExpired as exc:
                raise RshError(f"rsh upload of {self._path}: no answer after the data") from exc
            err = self._err.text()
            if self._watch.fired:
                raise RshError(
                    f"rsh upload of {self._path}: nothing moved for {TRANSFER_IDLE_TIMEOUT:.0f} s"
                )
            host = self._session._host
            if proc.returncode != 0:
                raise RshError(
                    f"rsh upload of {self._path} on {host} exited {proc.returncode}: {err}"
                ) from cause
            status, _ = self._session._split_status(
                self._command, self._tag, self._out.data(), err
            )
            if status != 0:
                raise RshError(
                    f"rsh upload of {self._path} on {host} exited {status}: {err}"
                ) from cause
            if cause is not None:
                raise RshError(f"rsh upload of {self._path}: {cause}") from cause
        finally:
            self._watch.stop()
            _end(proc)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._finish()

    def discard(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._watch.stop()
        _end(self._proc)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.discard()
        else:
            self.close()
