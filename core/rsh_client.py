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

import io
import logging
import posixpath
import re
import shlex
import shutil
import subprocess
from datetime import datetime
from typing import IO

from models.file_item import FileItem

log = logging.getLogger(__name__)


DEFAULT_TIMEOUT = 30.0
MAX_FILE_BYTES = 64 * 1024 * 1024  # cap on a single read; rsh has no chunking


# Pattern matching `ls -la` POSIX output. Loose by design — different
# Unix flavours format times slightly differently; we extract what we
# can and treat the rest as best-effort.
_LS_RE = re.compile(
    r"^(?P<perms>[bcdlsp\-][rwxsStTl\-]{9})\s+"   # mode string
    r"\d+\s+"                                       # link count
    r"\S+\s+\S+\s+"                                 # user, group
    r"(?P<size>\d+)\s+"                             # size
    r"(?P<date>\S+\s+\S+\s+\S+)\s+"                 # date triplet
    r"(?P<name>.+?)$"
)


# Filename-allow-list. rsh quotes via ``shlex.quote`` already, but
# refusing newlines / NUL up-front catches programmer errors and
# stops a hostile profile from smuggling a second command via a
# crafted path even if the quoting were ever weakened.
_PATH_RE = re.compile(r"^[^\x00\r\n]*$")


class RshError(OSError):
    """Raised on rsh non-zero exit / unexpected stderr."""


def _validate_path(path: str) -> str:
    if not _PATH_RE.match(path):
        raise OSError(f"rsh path contains CR / LF / NUL: {path!r}")
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

class RshSession:
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
        **_ignored,
    ):
        self._host = host
        self._port = int(port)
        self._username = username
        self._timeout = float(timeout)
        self._rsh = _ensure_rsh_available()
        # Plaintext-credential warning. rsh negotiation never carries
        # the password (host-based auth) but sends username + command
        # in the clear, so flag a single line so a misconfigured
        # profile doesn't slip past silently.
        log.warning(
            "rsh backend connecting to %s@%s:%d in PLAINTEXT — "
            "every command + filename traverses the wire unencrypted. "
            "Use SFTP / SCP for anything sensitive.",
            username, host, self._port,
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
            raise OSError(
                f"rsh probe to {host} returned unexpected payload: {out!r}"
            )

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

    def _run_remote(self, command: str, *, stdin: bytes | None = None) -> bytes:
        """Execute ``command`` on the remote via rsh; return stdout
        bytes. Non-zero exit raises :class:`RshError` carrying the
        captured stderr.
        """
        argv = [self._rsh]
        if self._port and self._port != 514:
            # netkit-rsh accepts -p; some forks don't. Only add when
            # the user actually customised the port.
            argv += ["-p", str(self._port)]
        if self._username:
            argv += ["-l", self._username]
        argv += [self._host, command]
        log.debug("rsh exec: %s", " ".join(shlex.quote(a) for a in argv))
        try:
            proc = subprocess.run(
                argv, input=stdin,
                capture_output=True,
                timeout=self._timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RshError(f"rsh timed out: {exc}") from exc
        if proc.returncode != 0:
            err = (proc.stderr or b"").decode("utf-8", "replace").strip()
            raise RshError(
                f"rsh '{command[:60]}...' on {self._host} "
                f"exited {proc.returncode}: {err}"
            )
        return proc.stdout

    # ------------------------------------------------------------------
    # Read surface
    # ------------------------------------------------------------------

    def list_dir(self, path: str) -> list[FileItem]:
        path = _validate_path(self.normalize(path))
        # ``ls -la --time-style=long-iso`` would be nicer but isn't
        # universal on AIX / Solaris. Keep the safer plain ``ls -la``
        # and parse defensively.
        out = self._run_remote(f"ls -la {shlex.quote(path)}")
        items: list[FileItem] = []
        for raw in out.decode("utf-8", "replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("total ") or line.startswith("ls:"):
                continue
            m = _LS_RE.match(line)
            if not m:
                continue
            name = m.group("name")
            if name in (".", ".."):
                continue
            # Strip ``-> target`` for symlinks; we don't model them.
            name = name.split(" -> ", 1)[0]
            perms_text = m.group("perms")
            is_dir = perms_text.startswith("d")
            try:
                size = int(m.group("size"))
            except ValueError:
                size = 0
            items.append(FileItem(
                name=name, is_dir=is_dir, is_link=perms_text.startswith("l"),
                size=size,
                modified=datetime.fromtimestamp(0),
                permissions=_perms_to_octal(perms_text),
            ))
        return items

    def stat(self, path: str) -> FileItem:
        path = _validate_path(self.normalize(path))
        if path == "/":
            return FileItem(
                name="/", is_dir=True, is_link=False,
                size=0, modified=datetime.fromtimestamp(0),
                permissions=0o755,
            )
        parent = self.parent(path)
        leaf = posixpath.basename(path)
        for item in self.list_dir(parent):
            if item.name == leaf:
                return item
        raise OSError(f"rsh stat({path}): not found")

    def is_dir(self, path: str) -> bool:
        try:
            return self.stat(path).is_dir
        except OSError:
            return False

    def exists(self, path: str) -> bool:
        try:
            self.stat(path)
            return True
        except OSError:
            return False

    def open_read(self, path: str) -> IO[bytes]:
        path = _validate_path(self.normalize(path))
        # ``head -c <cap> -- <path>`` enforces a wire-level cap so a
        # hostile remote can't dump GB of unbounded data through the rsh
        # socket while we buffer. The explicit ``--`` separator stops
        # any path that survived _validate_path from re-attaching as a
        # flag on the remote tool.
        cmd = (
            f"head -c {MAX_FILE_BYTES} -- {shlex.quote(path)} && true"
        )
        data = self._run_remote(cmd)
        return io.BytesIO(data)

    def readlink(self, path: str) -> str:
        path = _validate_path(self.normalize(path))
        out = self._run_remote(f"readlink -- {shlex.quote(path)}")
        return out.decode("utf-8", "replace").strip()

    # ------------------------------------------------------------------
    # Write surface
    # ------------------------------------------------------------------

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        path = _validate_path(self.normalize(path))
        return _RshWriter(self, path, append=append)

    def remove(self, path: str, recursive: bool = False) -> None:
        path = _validate_path(self.normalize(path))
        flag = "-rf" if recursive else "-f"
        self._run_remote(f"rm {flag} -- {shlex.quote(path)}")

    def mkdir(self, path: str) -> None:
        path = _validate_path(self.normalize(path))
        self._run_remote(f"mkdir -p -- {shlex.quote(path)}")

    def rename(self, src: str, dst: str) -> None:
        src = _validate_path(self.normalize(src))
        dst = _validate_path(self.normalize(dst))
        self._run_remote(
            f"mv -- {shlex.quote(src)} {shlex.quote(dst)}"
        )

    def chmod(self, path: str, mode: int) -> None:
        path = _validate_path(self.normalize(path))
        self._run_remote(
            f"chmod {oct(mode)[2:]} -- {shlex.quote(path)}"
        )

    def copy(self, src: str, dst: str) -> None:
        """Server-side copy via remote ``cp``. Same wire as
        traditional rcp (which is implemented as rsh+cp on most
        systems anyway)."""
        src = _validate_path(self.normalize(src))
        dst = _validate_path(self.normalize(dst))
        self._run_remote(
            f"cp -p -- {shlex.quote(src)} {shlex.quote(dst)}"
        )

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        path = _validate_path(self.normalize(path))
        try:
            out = self._run_remote(f"df -P -- {shlex.quote(path)}").decode("utf-8", "replace")
        except RshError:
            return (0, 0, 0)
        # Parse second line of `df -P` output.
        lines = [ln for ln in out.splitlines() if ln.strip()]
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
            out = self._run_remote(f"{tool} -- {shlex.quote(path)}").decode("utf-8", "replace")
        except RshError:
            return ""
        digest = out.split()[0] if out.strip() else ""
        if not digest:
            return ""
        return f"{algorithm}:{digest.lower()}"

    # ------------------------------------------------------------------
    # Internal: actual upload (called by writer.close)
    # ------------------------------------------------------------------

    def _upload(self, path: str, data: bytes, append: bool) -> None:
        op = ">>" if append else ">"
        cmd = f"cat {op} {shlex.quote(path)}"
        self._run_remote(cmd, stdin=data)


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


class _RshWriter:
    """File-like writer: buffers in memory, ships via ``cat > path``
    on close."""

    def __init__(self, session: RshSession, path: str, append: bool = False):
        self._session = session
        self._path = path
        self._append = append
        self._buf = io.BytesIO()
        self._closed = False

    def write(self, data: bytes) -> int:
        if self._closed:
            raise OSError("writer closed")
        return self._buf.write(data)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._session._upload(self._path, self._buf.getvalue(), self._append)
        self._buf.close()

    def discard(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._buf.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
