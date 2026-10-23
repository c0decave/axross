"""SCP backend implementing the FileBackend protocol.

Uses paramiko SSH transport + exec_command to run remote shell commands
for filesystem operations.  This provides a fully featured POSIX backend
over SSH *without* requiring the SFTP subsystem — useful for legacy
devices that only expose SCP / raw shell access.

File transfers use base64 encoding over exec_command (same approach as
the telnet backend) for reliable binary-safe transfer.
"""

from __future__ import annotations

import base64
import binascii
import errno
import hashlib
import logging
import posixpath
import re
import shlex
import socket
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import IO, TYPE_CHECKING

import paramiko

from core.append_helpers import read_existing_for_append
from core.backend import SessionLifecycle
from core.profiles import ConnectionProfile
from core.proxy import ProxyConfig, create_direct_socket, create_proxy_socket
from core.redaction import redact_text
from core.ssh_client import (
    CleanEnvProxyCommand,
    HostKeyMismatchError,
    RevokedHostKeyError,
    UnknownHostKeyError,
    _read_limited_stream,
    append_known_host,
    drain_exec_channel,
    load_known_hosts,
)
from core.ssh_config import expand_proxy_command
from models.file_item import FileItem

if TYPE_CHECKING:
    from models.exec_result import ExecResult
    from models.interactive_shell import InteractiveShell

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Reuse parsers from telnet_client (they are module-level functions)
# ---------------------------------------------------------------------------
from core.telnet_client import (  # noqa: E402 — re-using telnet shell-output parsers
    SHELL_ENV,
    _parse_df,
    _parse_ls_la,
    _parse_stat_gnu,
    copy_command,
    rename_command,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CMD_TIMEOUT = 30.0
TRANSFER_TIMEOUT = 300.0
COMMAND_STDOUT_CAP = 4 * 1024 * 1024
COMMAND_STDERR_CAP = 256 * 1024
_READ_CHUNK = 1024 * 1024
_READ_SPOOL_MAX = 8 * 1024 * 1024

# Strip ANSI escape sequences
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]|\x1b\([AB0-2]")


# ---------------------------------------------------------------------------
# Capability probe (what tools are available on the remote shell)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class _Capabilities:
    """Available shell tools detected after login."""

    has_base64: bool = False
    has_stat_gnu: bool = False
    has_stat_bsd: bool = False
    has_chmod: bool = False
    has_readlink: bool = False
    has_df: bool = False
    # "base64" and "raw" (cat) move bytes through the shell; "scp" speaks
    # the SCP protocol (scp -f / scp -t) where the shell has neither.
    transfer_method: str = "raw"  # "base64", "raw", "scp"
    os_name: str = "unknown"
    # Whether "VAR=value command" works. Restricted shells (Rebex's virtual
    # shell) refuse any command that starts with an assignment.
    has_env_prefix: bool = True


def _probe_capabilities(exec_fn: Callable[[str, float], tuple[str, int]]) -> _Capabilities:
    """Detect available commands on the remote system."""

    def _has(cmd: str) -> bool:
        _, code = exec_fn(f"command -v {cmd} 2>/dev/null || which {cmd} 2>/dev/null", 5.0)
        return code == 0

    has_base64 = _has("base64")
    has_chmod = _has("chmod")
    has_readlink = _has("readlink")
    has_df = _has("df")

    # Detect GNU stat vs BSD stat
    has_stat_gnu = False
    has_stat_bsd = False
    if _has("stat"):
        _, code = exec_fn("stat --format='%s' / 2>/dev/null", 5.0)
        if code == 0:
            has_stat_gnu = True
        else:
            _, code = exec_fn("stat -f '%z' / 2>/dev/null", 5.0)
            if code == 0:
                has_stat_bsd = True

    # Detect OS
    os_output, _ = exec_fn("uname -s 2>/dev/null", 5.0)
    os_name = os_output.strip() or "unknown"

    if has_base64:
        transfer_method = "base64"
    elif _has("cat"):
        transfer_method = "raw"
    else:
        # A restricted shell (Rebex's virtual shell): no cat, no base64,
        # but the server runs the SCP protocol itself.
        transfer_method = "scp"

    env_output, code = exec_fn(f"{SHELL_ENV} echo env-ok", 5.0)
    has_env_prefix = code == 0 and env_output.strip() == "env-ok"

    caps = _Capabilities(
        has_base64=has_base64,
        has_stat_gnu=has_stat_gnu,
        has_stat_bsd=has_stat_bsd,
        has_chmod=has_chmod,
        has_readlink=has_readlink,
        has_df=has_df,
        transfer_method=transfer_method,
        os_name=os_name,
        has_env_prefix=has_env_prefix,
    )
    log.info(
        "SCP capabilities: transfer=%s, stat_gnu=%s, env_prefix=%s, os=%s",
        caps.transfer_method,
        caps.has_stat_gnu,
        caps.has_env_prefix,
        caps.os_name,
    )
    return caps


# ---------------------------------------------------------------------------
# SCP protocol (scp -f / scp -t) for shells without cat and base64
# ---------------------------------------------------------------------------
_SCP_LINE_MAX = 4096


def _scp_read_line(chan) -> bytes:
    line = b""
    while not line.endswith(b"\n"):
        byte = chan.recv(1)
        if not byte:
            raise OSError("SCP: the connection closed in the middle of a message")
        line += byte
        if len(line) > _SCP_LINE_MAX:
            raise OSError("SCP: control line too long")
    return line


def _scp_raise(path: str, message: bytes) -> None:
    """Raise the error an SCP status message (after its 1/2 byte) reports."""
    text = message.decode("utf-8", "replace").strip()
    if "No such file" in text:
        raise FileNotFoundError(errno.ENOENT, text, path)
    if "Permission denied" in text:
        raise PermissionError(errno.EACCES, text, path)
    raise OSError(text or f"SCP: {path} refused")


def _scp_status(chan, path: str) -> None:
    """Read one status answer: 0 is ok, 1 and 2 carry an error line."""
    byte = chan.recv(1)
    if byte == b"\0":
        return
    if not byte:
        raise OSError(f"SCP {path}: the connection closed without an answer")
    if byte in (b"\1", b"\2"):
        _scp_raise(path, _scp_read_line(chan))
    raise OSError(f"SCP {path}: protocol error, got {byte!r}")


# ---------------------------------------------------------------------------
# SpooledWriter — buffers writes, uploads on close()
# ---------------------------------------------------------------------------
class _SpooledWriter:
    """Buffer writes in memory, upload via exec_command on close()."""

    def __init__(
        self,
        exec_fn: Callable[..., str],
        remote_path: str,
        caps: _Capabilities,
        append: bool = False,
        scp_upload: Callable[[str, bytes], None] | None = None,
    ):
        self._exec_fn = exec_fn
        self._scp_upload = scp_upload
        self._remote_path = remote_path
        self._caps = caps
        self._append = append
        self._buf = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024)
        self._closed = False

    def write(self, data: bytes) -> int:
        return self._buf.write(data)

    def read(self, n: int = -1) -> bytes:
        return self._buf.read(n)

    def seek(self, pos: int, whence: int = 0) -> int:
        return self._buf.seek(pos, whence)

    def tell(self) -> int:
        return self._buf.tell()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._buf.seek(0)
            data = self._buf.read()
        finally:
            self._buf.close()
        qpath = shlex.quote(self._remote_path)

        if self._caps.transfer_method == "base64":
            self._upload_base64(data, qpath)
        elif self._caps.transfer_method == "scp" and self._scp_upload is not None:
            self._scp_upload(self._remote_path, data)
        else:
            self._upload_raw(data, qpath)

    def discard(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._buf.close()

    # The payload travels on the command's stdin. Inside the command
    # string (a heredoc) it became one argument of ``$SHELL -c``, and
    # Linux refuses exec arguments above 128 KiB (E2BIG).

    def _upload_base64(self, data: bytes, qpath: str) -> None:
        redirect = ">>" if self._append else ">"
        self._exec_fn(
            f"base64 -d {redirect} {qpath}",
            TRANSFER_TIMEOUT,
            stdin_data=base64.b64encode(data),
        )

    def _upload_raw(self, data: bytes, qpath: str) -> None:
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            raise OSError(
                "Cannot upload binary file: no base64 available on remote system. "
                "Only text files are supported."
            )
        redirect = ">>" if self._append else ">"
        self._exec_fn(f"cat {redirect} {qpath}", TRANSFER_TIMEOUT, stdin_data=data)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.discard()
        else:
            self.close()


# ---------------------------------------------------------------------------
# Main Backend: SCPSession (FileBackend implementation)
# ---------------------------------------------------------------------------
class SCPSession(SessionLifecycle):
    """SCP filesystem backend using paramiko SSH transport + exec_command.

    Connects via SSH (same auth flow as SSHSession), then uses standard
    Unix commands (ls, stat, cat, base64, etc.) over exec_command to
    implement the FileBackend interface.  Does NOT require SFTP subsystem.
    """

    _MAX_APPEND_EXISTING_SIZE = 256 * 1024 * 1024

    def __init__(self, profile: ConnectionProfile):
        self._profile = profile
        self._client: paramiko.SSHClient | None = None
        self._home_dir: str = "/"
        self._caps: _Capabilities = _Capabilities()
        self._lock = threading.Lock()
        self._known_hosts_path = Path.home() / ".ssh" / "known_hosts"
        # Read at connect; the host key policy consults its @revoked keys.
        self._known_hosts = None

    # -- Properties ----------------------------------------------------------

    @property
    def name(self) -> str:
        return f"{self._profile.username}@{self._profile.host} (SCP)"

    @property
    def connected(self) -> bool:
        if self._client is None:
            return False
        transport = self._client.get_transport()
        return transport is not None and transport.is_active()

    @property
    def transport(self) -> paramiko.Transport | None:
        """Public handle to the underlying paramiko Transport.

        Exposed so the MainWindow's terminal-dock plumbing can
        multiplex an interactive shell channel onto the SAME transport
        that already serves SCP file ops — without this property, the
        ``hasattr(session, 'transport')`` check in
        ``_on_success`` / session-restore silently falls back to a
        local shell. See ``interactive_shell()`` for the channel
        allocation itself.
        """
        if self._client is None:
            return None
        return self._client.get_transport()

    # -- Connection ----------------------------------------------------------

    def connect(
        self,
        password: str = "",
        key_passphrase: str = "",
        on_unknown_host: Callable[[UnknownHostKeyError], bool] | None = None,
        resolve_profile: object | None = None,
    ) -> None:
        """Establish SSH connection (no SFTP channel needed)."""
        profile = self._profile

        try:
            # Create socket (ProxyCommand, SOCKS/HTTP proxy, or direct)
            family = self._socket_family()
            if profile.proxy_command:
                cmd = expand_proxy_command(
                    profile.proxy_command,
                    host=profile.host,
                    port=profile.port,
                    username=profile.username,
                    resolve_profile=resolve_profile,
                )
                log.info("Using ProxyCommand for %s: %s", profile.host, redact_text(cmd))
                sock = CleanEnvProxyCommand(cmd)
            elif (profile.proxy_type or "none").lower() != "none":
                if not profile.proxy_host:
                    raise OSError(
                        f"SCP proxy_type={profile.proxy_type!r} requires "
                        "proxy_host; refusing direct traffic."
                    )
                proxy_pw = profile.get_proxy_password() or ""
                proxy_config = ProxyConfig(
                    proxy_type=profile.proxy_type,
                    host=profile.proxy_host,
                    port=profile.proxy_port,
                    username=profile.proxy_username,
                    password=proxy_pw,
                )
                sock = create_proxy_socket(
                    proxy_config,
                    profile.host,
                    profile.port,
                    family=family,
                )
            else:
                sock = create_direct_socket(profile.host, profile.port, family=family)

            log.info("Creating SSH transport to %s:%d (SCP mode)", profile.host, profile.port)

            # Build paramiko SSHClient with custom host key policy
            self._client = paramiko.SSHClient()
            self._client.set_missing_host_key_policy(_HostKeyPolicy(self, on_unknown_host))

            # Load known hosts line by line (marker lines, revoked keys);
            # SSHClient.load_host_keys raised InvalidHostKey on them.
            self._known_hosts = load_known_hosts(self._known_hosts_path)
            client_keys = self._client.get_host_keys()
            for host in self._known_hosts.keys():
                for key_type, key in self._known_hosts.lookup(host).items():
                    client_keys.add(host, key_type, key)

            # Build auth kwargs
            auth_kw: dict = {
                "username": profile.username,
                "sock": sock,
            }

            if profile.auth_type == "agent":
                auth_kw["allow_agent"] = True
                auth_kw["look_for_keys"] = False
            elif profile.auth_type == "key":
                key_path = profile.key_file
                if not key_path:
                    raise ValueError("No key file specified")
                pkey = self._load_private_key(key_path, key_passphrase)
                auth_kw["pkey"] = pkey
                auth_kw["allow_agent"] = False
                auth_kw["look_for_keys"] = False
            else:  # password
                pw = password or profile.get_password() or ""
                auth_kw["password"] = pw
                auth_kw["allow_agent"] = False
                auth_kw["look_for_keys"] = False

            self._client.connect(
                profile.host,
                port=profile.port,
                **auth_kw,
            )

            transport = self._client.get_transport()
            if transport and profile.ssh_keepalive_interval > 0:
                # Off by default — see docs/OPSEC.md #2.
                transport.set_keepalive(profile.ssh_keepalive_interval)

            # Probe capabilities
            self._caps = _probe_capabilities(self._exec_raw)

            # Determine home directory
            output, code = self._exec_raw("echo $HOME", 5.0)
            home = output.strip()
            if code == 0 and home:
                self._home_dir = home
            else:
                output, code = self._exec_raw("pwd", 5.0)
                self._home_dir = output.strip() or "/"

            # Configure locale for predictable output
            if self._caps.has_env_prefix:
                self._exec_raw(f"export {SHELL_ENV}", 5.0)

            log.info(
                "SCP session established. Home: %s, transfer: %s",
                self._home_dir,
                self._caps.transfer_method,
            )
        except Exception:
            self.disconnect()
            raise

    def disconnect(self) -> None:
        """Close SSH connection."""
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
        log.info("SCP disconnected from %s", self._profile.host)

    # -- Internal helpers ----------------------------------------------------

    def _socket_family(self) -> int:
        return {
            "auto": socket.AF_UNSPEC,
            "ipv4": socket.AF_INET,
            "ipv6": socket.AF_INET6,
        }.get(self._profile.address_family, socket.AF_UNSPEC)

    @staticmethod
    def _load_private_key(path: str, passphrase: str) -> paramiko.PKey:
        """Load a private key, trying multiple formats (as SFTP does: an
        encrypted key without its passphrase says so)."""
        from core.ssh_client import load_private_key

        return load_private_key(path, passphrase)

    def _host_key_aliases(self) -> list[str]:
        if self._profile.port == 22:
            return [self._profile.host]
        return [f"[{self._profile.host}]:{self._profile.port}"]

    @staticmethod
    def _fingerprint_sha256(key: paramiko.PKey) -> str:
        digest = hashlib.sha256(key.asbytes()).digest()
        return base64.b64encode(digest).decode("ascii").rstrip("=")

    def trust_current_host_key(self) -> None:
        """Persist the currently negotiated host key to known_hosts."""
        if not self._client:
            raise ConnectionError("Not connected")
        transport = self._client.get_transport()
        if not transport:
            raise ConnectionError("Transport not initialized")

        remote_key = transport.get_remote_server_key()
        append_known_host(self._known_hosts_path, self._host_key_aliases()[0], remote_key)

    def _exec_raw(
        self, cmd: str, timeout: float = CMD_TIMEOUT, stdin_data: bytes | None = None
    ) -> tuple[str, int]:
        """Execute a command via SSH exec_command. Returns (stdout, exit_code).

        ``stdin_data`` is sent on the command's stdin, followed by EOF.
        It is written before any output is read, so it suits commands
        that only consume stdin (``base64 -d > file``, ``cat > file``).
        """
        if not self._client:
            raise ConnectionError("Not connected")

        with self._lock:
            try:
                stdin, stdout, stderr = self._client.exec_command(
                    cmd,
                    timeout=timeout,
                )
                if stdin_data is not None:
                    view = memoryview(stdin_data)
                    for start in range(0, len(view), 64 * 1024):
                        stdin.channel.sendall(view[start : start + 64 * 1024])
                    stdin.channel.shutdown_write()
                out_bytes = _read_limited_stream(
                    stdout,
                    COMMAND_STDOUT_CAP,
                    "SCP command stdout",
                )
                err_bytes = _read_limited_stream(
                    stderr,
                    COMMAND_STDERR_CAP,
                    "SCP command stderr",
                )
                exit_code = stdout.channel.recv_exit_status()
                if exit_code != 0 and err_bytes:
                    out_bytes += b"\n" + err_bytes
                out = out_bytes.decode("utf-8", errors="replace")
                return out, exit_code
            except (paramiko.SSHException, socket.error) as exc:
                raise OSError(f"Command execution failed: {exc}") from exc

    def _exec(
        self, cmd: str, timeout: float = CMD_TIMEOUT, stdin_data: bytes | None = None
    ) -> str:
        """Execute command, raise OSError on non-zero exit code."""
        output, code = self._exec_raw(cmd, timeout, stdin_data=stdin_data)
        if code != 0:
            # Read stderr for better error messages
            raise OSError(f"Command failed (exit {code}): {cmd[:120]}\n{output[:500]}")
        return output

    def interactive_shell(
        self,
        *,
        term: str = "xterm-256color",
        cols: int = 80,
        rows: int = 24,
        env: dict[str, str] | None = None,
    ) -> "InteractiveShell":
        """Open a NEW interactive-shell channel on the SAME paramiko
        SSH transport that already serves the SCP file ops —
        multiplexing.

        The user asked for this so a script that's already connected
        for SCP can spawn a real shell without a second TCP connect /
        re-auth. The implementation opens a new session channel on
        ``self._client.get_transport()``, allocates a PTY, and
        invokes the user's login shell. File ops on the same session
        keep running because they use a separate channel.

        See ``models.interactive_shell.InteractiveShell`` for the
        wrapper API (read / write / read_until / resize_pty /
        close / interact / iter-as-lines).
        """
        from models.interactive_shell import InteractiveShell

        if not self._client:
            raise OSError("SCP interactive_shell: not connected")
        transport = self._client.get_transport()
        if transport is None or not transport.is_active():
            raise OSError(
                "SCP interactive_shell: transport not active",
            )
        if env:
            import re as _re

            for k, v in env.items():
                if not _re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k):
                    raise OSError(
                        f"SCP interactive_shell: env key {k!r} must match [A-Za-z_][A-Za-z0-9_]*"
                    )
                if "\x00" in v or "\r" in v or "\n" in v:
                    raise OSError(
                        f"SCP interactive_shell: env value for {k!r} must not contain NUL/CR/LF"
                    )
        if "\r" in term or "\n" in term or "\x00" in term:
            raise ValueError("SCP interactive_shell: term must not contain NUL/CR/LF")
        chan = transport.open_session()
        try:
            chan.get_pty(term=term, width=int(cols), height=int(rows))
            if env:
                for k, v in env.items():
                    try:
                        chan.update_environment({k: v})
                    except paramiko.SSHException:
                        log.debug(
                            "SCP interactive_shell: env key %s rejected by sshd",
                            k,
                        )
            chan.invoke_shell()
        except Exception:
            try:
                chan.close()
            except Exception:  # noqa: BLE001
                pass
            raise
        log.info(
            "SCP interactive shell opened on %s (%dx%d %s)",
            self.name,
            cols,
            rows,
            term,
        )
        return InteractiveShell(chan, label=str(self.name))

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
        """Public ``exec`` surface — same shape as ``SSHSession.exec``.

        SCP backend already runs every primitive through paramiko's
        ``exec_command`` (the SCP wire-protocol is just shell calls
        wrapped around base64 streams). Re-exposing it as a first-class
        verb means a script can do::

            b = axross.open("scp_box")
            r = b.exec("uptime").check()
            print(r.stdout.decode())

        without dropping to ``b._exec_raw`` (private). Implemented in
        terms of paramiko's stream API so we can cap stdout/stderr and
        pipe stdin in, just like ``SSHSession.exec``.
        """
        if not self._client:
            raise OSError("SCP exec: not connected")
        log.info(
            "SCP exec on %s: %s%s",
            self.name,
            cmd[:120],
            "..." if len(cmd) > 120 else "",
        )
        if env:
            import re as _re

            for k, v in env.items():
                if not _re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k):
                    raise OSError(
                        f"SCP exec: env key {k!r} must match "
                        "[A-Za-z_][A-Za-z0-9_]* (refusing to send)"
                    )
                if "\x00" in v or "\r" in v or "\n" in v:
                    raise OSError(
                        f"SCP exec: env value for {k!r} must not contain "
                        "NUL/CR/LF (refusing to send). F39."
                    )
        with self._lock:
            try:
                stdin_chan, stdout_chan, _stderr_chan = self._client.exec_command(
                    cmd,
                    timeout=timeout,
                    environment=env or None,
                )
                chan = stdout_chan.channel
                try:
                    if stdin:
                        try:
                            stdin_chan.write(stdin)
                            stdin_chan.flush()
                        except OSError:
                            pass
                        try:
                            chan.shutdown_write()
                        except Exception:  # noqa: BLE001
                            pass
                    # Both streams together, like SSHSession.exec: reading
                    # stdout to its cap and then waiting for stderr's end
                    # deadlocked once the unread stdout filled the window.
                    return drain_exec_channel(
                        chan,
                        timeout=timeout,
                        stdout_cap=stdout_cap,
                        stderr_cap=stderr_cap,
                        label="SCP exec",
                    )
                finally:
                    chan.close()
            except TimeoutError:
                raise
            except (paramiko.SSHException, socket.error) as exc:
                raise OSError(f"SCP exec failed: {exc}") from exc

    def _env_prefix(self) -> str:
        """SHELL_ENV in front of a command, where the shell takes it."""
        return f"{SHELL_ENV} " if self._caps.has_env_prefix else ""

    # -- FileBackend interface -----------------------------------------------

    def list_dir(self, path: str) -> list[FileItem]:
        path = self.normalize(path)
        from core.exec_util import ls_dir_operand

        output = self._exec(f"{self._env_prefix()}ls -la {shlex.quote(ls_dir_operand(path))}")
        if not output.strip():
            # ls -la of a folder prints at least "."; Rebex's shell answers a
            # missing path with nothing and exit 0.
            raise FileNotFoundError(errno.ENOENT, "No such file or directory", path)
        from core.path_policy import drop_unsafe_names

        return drop_unsafe_names(_parse_ls_la(output), keep_dots=True, origin=f"SCP {path}")

    def stat(self, path: str) -> FileItem:
        path = self.normalize(path)
        qpath = shlex.quote(path)
        if self._caps.has_stat_gnu:
            output = self._exec(f"stat --format='%n|%s|%Y|%f|%U|%G|%F' {qpath}")
            return _parse_stat_gnu(output)
        # Fallback: ls -ld
        output = self._exec(f"{self._env_prefix()}ls -ld {qpath}")
        items = _parse_ls_la(output)
        if not items:
            raise FileNotFoundError(
                errno.ENOENT, f"Cannot stat {path}: no output from ls -ld", path
            )
        item = items[0]
        return FileItem(
            name=posixpath.basename(path.rstrip("/")) or path,
            size=item.size,
            modified=item.modified,
            permissions=item.permissions,
            is_dir=item.is_dir,
            is_link=item.is_link,
            link_target=item.link_target,
            owner=item.owner,
            group=item.group,
        )

    def _path_kind(self, path: str) -> str | None:
        """"dir", "other" or None (not there). ``test -e`` read every
        non-zero exit as "no", a folder it may not search included;
        server_side_copy(overwrite=False) and the transfer worker take
        False from exists() as the go-ahead to write."""
        from core.exec_util import path_kind, path_kind_command

        path = self.normalize(path)
        out, code = self._exec_raw(path_kind_command(path))
        return path_kind(f"SCP {path}", out, code)

    def is_dir(self, path: str) -> bool:
        return self._path_kind(path) == "dir"

    def exists(self, path: str) -> bool:
        return self._path_kind(path) is not None

    def mkdir(self, path: str) -> None:
        self._exec(f"mkdir -p {shlex.quote(self.normalize(path))}")

    def remove(self, path: str, recursive: bool = False) -> None:
        path = self.normalize(path)
        qpath = shlex.quote(path)
        if recursive:
            self._exec(f"rm -rf {qpath}")
        else:
            if self.is_dir(path):
                self._exec(f"rmdir {qpath}")
            else:
                self._exec(f"rm -f {qpath}")

    def rename(self, src: str, dst: str) -> None:
        self._exec(rename_command(self.normalize(src), self.normalize(dst)))

    def open_read(self, path: str) -> IO[bytes]:
        """Stream the file into a spooled temp file.

        Not through ``_exec_raw``: its 4 MiB stdout cap is meant for
        command output, and base64 of any file above ~3 MiB exceeded it.
        An exec channel is 8-bit clean, so ``cat`` output is kept as
        bytes rather than round-tripped through ``str``.
        """
        path = self.normalize(path)
        if self._caps.transfer_method == "scp":
            return self._scp_read(path)
        qpath = shlex.quote(path)
        use_base64 = self._caps.transfer_method == "base64"
        tool = "base64" if use_base64 else "cat"
        cmd = f"base64 < {qpath}" if use_base64 else f"cat {qpath}"
        if not self._client:
            raise ConnectionError("Not connected")

        spool = tempfile.SpooledTemporaryFile(max_size=_READ_SPOOL_MAX)
        try:
            with self._lock:
                try:
                    stdin, stdout, stderr = self._client.exec_command(
                        cmd, timeout=TRANSFER_TIMEOUT
                    )
                    stdin.channel.shutdown_write()
                    carry = b""
                    while True:
                        chunk = stdout.read(_READ_CHUNK)
                        if not chunk:
                            break
                        if not use_base64:
                            spool.write(chunk)
                            continue
                        text = carry + b"".join(chunk.split())
                        whole = len(text) - len(text) % 4
                        spool.write(base64.b64decode(text[:whole], validate=True))
                        carry = text[whole:]
                    err = _read_limited_stream(stderr, COMMAND_STDERR_CAP, "SCP command stderr")
                    # -1: the channel closed without an exit status, i.e.
                    # the stream was cut - never a complete file.
                    code = stdout.channel.recv_exit_status()
                except (paramiko.SSHException, socket.error) as exc:
                    raise OSError(f"Cannot read {path}: {exc}") from exc
                except binascii.Error as exc:
                    raise OSError(f"Cannot decode {path}: {exc}") from exc
            if code != 0:
                detail = err.decode("utf-8", "replace").strip()[:500]
                raise OSError(f"Cannot read {path}: {tool} failed (exit {code}) {detail}".rstrip())
            if carry:
                raise OSError(f"Cannot decode {path}: base64 output ends mid-group")
        except BaseException:
            spool.close()
            raise
        spool.seek(0)
        return spool

    def _scp_channel(self, cmd: str):
        """An exec channel running *cmd*, for the SCP protocol."""
        chan = self._client.get_transport().open_session()
        chan.settimeout(TRANSFER_TIMEOUT)
        chan.exec_command(cmd)
        return chan

    def _scp_read(self, path: str) -> IO[bytes]:
        """Read *path* with ``scp -f`` (source mode) into a spooled file."""
        if not self._client:
            raise ConnectionError("Not connected")
        spool = tempfile.SpooledTemporaryFile(max_size=_READ_SPOOL_MAX)
        try:
            with self._lock:
                chan = self._scp_channel(f"scp -f {shlex.quote(path)}")
                try:
                    chan.sendall(b"\0")
                    header = _scp_read_line(chan)
                    if header[:1] in (b"\1", b"\2"):
                        _scp_raise(path, header[1:])
                    if not header.startswith(b"C"):
                        raise OSError(f"Cannot read {path}: not a regular file over SCP")
                    try:
                        size = int(header.split(b" ", 2)[1])
                    except (IndexError, ValueError):
                        raise OSError(f"Cannot read {path}: bad SCP header {header[:80]!r}")
                    chan.sendall(b"\0")
                    left = size
                    while left:
                        chunk = chan.recv(min(_READ_CHUNK, left))
                        if not chunk:
                            raise OSError(
                                f"Cannot read {path}: the SCP stream ended after "
                                f"{size - left} of {size} bytes"
                            )
                        spool.write(chunk)
                        left -= len(chunk)
                    _scp_status(chan, path)
                    chan.sendall(b"\0")
                except (paramiko.SSHException, socket.error) as exc:
                    if isinstance(exc, FileNotFoundError | PermissionError):
                        raise
                    raise OSError(f"Cannot read {path}: {exc}") from exc
                finally:
                    chan.close()
        except BaseException:
            spool.close()
            raise
        spool.seek(0)
        return spool

    def _scp_write(self, path: str, data: bytes) -> None:
        """Write *data* to *path* with ``scp -t`` (sink mode)."""
        name = posixpath.basename(path)
        if "\n" in name or "\r" in name:
            raise OSError(f"SCP cannot carry a file name with a line break: {path!r}")
        if not self._client:
            raise ConnectionError("Not connected")
        with self._lock:
            chan = self._scp_channel(f"scp -t {shlex.quote(path)}")
            try:
                _scp_status(chan, path)
                chan.sendall(b"C0644 %d %s\n" % (len(data), name.encode("utf-8")))
                _scp_status(chan, path)
                chan.sendall(data)
                chan.sendall(b"\0")
                _scp_status(chan, path)
                chan.shutdown_write()
            except (paramiko.SSHException, socket.error) as exc:
                if isinstance(exc, FileNotFoundError | PermissionError):
                    raise
                raise OSError(f"Cannot write {path}: {exc}") from exc
            finally:
                chan.close()

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        path = self.normalize(path)
        if append:
            cap = self._MAX_APPEND_EXISTING_SIZE
            existing = read_existing_for_append(
                open_read=self.open_read,
                stat=self.stat,
                path=path,
                cap=cap,
                label="SCP",
                logger=log,
            )
            if len(existing) > cap:
                raise OSError(f"SCP append: existing file exceeds {cap // (1024 * 1024)} MiB cap")
            writer = _SpooledWriter(
                self._exec, path, self._caps, append=False, scp_upload=self._scp_write
            )
            writer.write(existing)
            return writer
        return _SpooledWriter(self._exec, path, self._caps, scp_upload=self._scp_write)

    def normalize(self, path: str) -> str:
        return posixpath.normpath(path) or "/"

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        return posixpath.join(*parts)

    def parent(self, path: str) -> str:
        return posixpath.dirname(path.rstrip("/")) or "/"

    def home(self) -> str:
        return self._home_dir

    def chmod(self, path: str, mode: int) -> None:
        if not self._caps.has_chmod:
            raise OSError("chmod not available on remote system")
        self._exec(f"chmod {oct(mode)[2:]} {shlex.quote(self.normalize(path))}")

    def readlink(self, path: str) -> str:
        if not self._caps.has_readlink:
            raise OSError("readlink not available on remote system")
        output = self._exec(f"readlink {shlex.quote(self.normalize(path))}")
        result = output.strip()
        if not result:
            raise OSError(f"Not a symlink: {path}")
        return result

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError(f"{type(self).__name__} does not expose file version history")

    def copy(self, src: str, dst: str) -> None:
        """Server-side shell cp via SSH exec_command."""
        src = self.normalize(src)
        dst = self.normalize(dst)
        output, code = self._exec_raw(f"{copy_command(src, dst, preserve=True)} 2>&1")
        if code != 0:
            raise OSError(f"cp {src} -> {dst} failed: {output.strip()!r}")

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        """Remote ``sha256sum`` / ``md5sum`` via ssh exec_command."""
        tool = {
            "sha256": "sha256sum",
            "sha1": "sha1sum",
            "md5": "md5sum",
        }.get(algorithm)
        if not tool:
            return ""
        path = self.normalize(path)
        output, code = self._exec_raw(f"{tool} {shlex.quote(path)} 2>/dev/null")
        if code != 0 or not output:
            return ""
        from core.exec_util import digest_from_sum_output

        digest = digest_from_sum_output(output, algorithm)
        return f"{algorithm}:{digest}" if digest else ""

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        if not self._caps.has_df:
            return (0, 0, 0)
        path = self.normalize(path)
        qpath = shlex.quote(path)
        # Try df -B1 (GNU) first
        output, code = self._exec_raw(f"df -B1 {qpath} 2>/dev/null")
        if code == 0:
            result = _parse_df(output)
            if result != (0, 0, 0):
                return result
        # Fallback: df -k (POSIX) — multiply by 1024
        output, code = self._exec_raw(f"df -k {qpath}")
        if code == 0:
            total, used, free = _parse_df(output)
            return (total * 1024, used * 1024, free * 1024)
        return (0, 0, 0)


# ---------------------------------------------------------------------------
# Host key policy — bridges paramiko's MissingHostKeyPolicy with our
# UnknownHostKeyError / trust flow.
# ---------------------------------------------------------------------------
class _HostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Custom host key policy that raises our typed exceptions."""

    def __init__(
        self,
        session: SCPSession,
        on_unknown_host: Callable[[UnknownHostKeyError], bool] | None,
    ):
        self._session = session
        self._on_unknown_host = on_unknown_host

    def missing_host_key(
        self,
        client: paramiko.SSHClient,
        hostname: str,
        key: paramiko.PKey,
    ) -> None:
        key_type = key.get_name()
        fingerprint = self._session._fingerprint_sha256(key)
        alias = self._session._host_key_aliases()[0]

        known_hosts = getattr(self._session, "_known_hosts", None)
        if known_hosts is not None and known_hosts.is_revoked(key):
            raise RevokedHostKeyError(alias, key_type, fingerprint)

        # Check for mismatch against loaded keys
        host_keys = client.get_host_keys()
        known = host_keys.lookup(hostname)
        if known is not None:
            if key_type in known and known[key_type] != key:
                raise HostKeyMismatchError(alias, key_type, fingerprint)

        error = UnknownHostKeyError(alias, key_type, fingerprint)
        if self._on_unknown_host and self._on_unknown_host(error):
            # Accept and persist the key
            self._session.trust_current_host_key()
            log.info("Trusted new host key for %s (SCP)", alias)
            return

        raise error
