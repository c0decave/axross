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
import hashlib
import io
import logging
import posixpath
import re
import shlex
import socket
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import IO

import paramiko

from core.profiles import ConnectionProfile
from core.proxy import ProxyConfig, create_direct_socket, create_proxy_socket
from core.ssh_config import expand_proxy_command
from core.ssh_client import (
    HostKeyMismatchError,
    HostKeyVerificationError,
    UnknownHostKeyError,
)
from models.file_item import FileItem

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Reuse parsers from telnet_client (they are module-level functions)
# ---------------------------------------------------------------------------
from core.telnet_client import (
    _parse_ls_la,
    _parse_stat_gnu,
    _parse_df,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CMD_TIMEOUT = 30.0
TRANSFER_TIMEOUT = 300.0

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
    transfer_method: str = "raw"  # "base64", "raw"
    os_name: str = "unknown"


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

    transfer_method = "base64" if has_base64 else "raw"

    caps = _Capabilities(
        has_base64=has_base64,
        has_stat_gnu=has_stat_gnu,
        has_stat_bsd=has_stat_bsd,
        has_chmod=has_chmod,
        has_readlink=has_readlink,
        has_df=has_df,
        transfer_method=transfer_method,
        os_name=os_name,
    )
    log.info(
        "SCP capabilities: transfer=%s, stat_gnu=%s, os=%s",
        caps.transfer_method, caps.has_stat_gnu, caps.os_name,
    )
    return caps


# ---------------------------------------------------------------------------
# SpooledWriter — buffers writes, uploads on close()
# ---------------------------------------------------------------------------
class _SpooledWriter:
    """Buffer writes in memory, upload via exec_command on close()."""

    def __init__(
        self,
        exec_fn: Callable[[str, float], str],
        remote_path: str,
        caps: _Capabilities,
        append: bool = False,
    ):
        self._exec_fn = exec_fn
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
        self._buf.seek(0)
        data = self._buf.read()
        self._buf.close()
        qpath = shlex.quote(self._remote_path)

        if self._caps.transfer_method == "base64":
            self._upload_base64(data, qpath)
        else:
            self._upload_raw(data, qpath)

    @staticmethod
    def _safe_eof(payload: str) -> str:
        eof = "__AXX_EOF__"
        while eof in payload:
            eof += "_"
        return eof

    def _upload_base64(self, data: bytes, qpath: str) -> None:
        encoded = base64.b64encode(data).decode("ascii")
        redirect = ">>" if self._append else ">"
        eof = self._safe_eof(encoded)
        cmd = f"base64 -d {redirect} {qpath} << '{eof}'\n{encoded}\n{eof}"
        self._exec_fn(cmd, TRANSFER_TIMEOUT)

    def _upload_raw(self, data: bytes, qpath: str) -> None:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise OSError(
                "Cannot upload binary file: no base64 available on remote system. "
                "Only text files are supported."
            )
        redirect = ">>" if self._append else ">"
        eof = self._safe_eof(text)
        cmd = f"cat {redirect} {qpath} << '{eof}'\n{text}\n{eof}"
        self._exec_fn(cmd, TRANSFER_TIMEOUT)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


# ---------------------------------------------------------------------------
# Main Backend: SCPSession (FileBackend implementation)
# ---------------------------------------------------------------------------
class SCPSession:
    """SCP filesystem backend using paramiko SSH transport + exec_command.

    Connects via SSH (same auth flow as SSHSession), then uses standard
    Unix commands (ls, stat, cat, base64, etc.) over exec_command to
    implement the FileBackend interface.  Does NOT require SFTP subsystem.
    """

    def __init__(self, profile: ConnectionProfile):
        self._profile = profile
        self._client: paramiko.SSHClient | None = None
        self._home_dir: str = "/"
        self._caps: _Capabilities = _Capabilities()
        self._lock = threading.Lock()
        self._known_hosts_path = Path.home() / ".ssh" / "known_hosts"

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
                log.info("Using ProxyCommand for %s: %s", profile.host, cmd)
                sock = paramiko.ProxyCommand(cmd)
            elif profile.proxy_type != "none" and profile.proxy_host:
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

            # Load known hosts
            if self._known_hosts_path.exists():
                try:
                    self._client.load_host_keys(str(self._known_hosts_path))
                except (OSError, paramiko.SSHException) as exc:
                    log.warning("Could not load known_hosts: %s", exc)

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
            self._exec_raw("export LANG=C LC_ALL=C", 5.0)

            log.info(
                "SCP session established. Home: %s, transfer: %s",
                self._home_dir, self._caps.transfer_method,
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
        """Load a private key, trying multiple formats."""
        key_classes = [
            paramiko.Ed25519Key,
            paramiko.ECDSAKey,
            paramiko.RSAKey,
        ]
        if hasattr(paramiko, "DSSKey"):
            key_classes.append(paramiko.DSSKey)
        passphrase_arg = passphrase or None

        for cls in key_classes:
            try:
                return cls.from_private_key_file(path, password=passphrase_arg)
            except (paramiko.SSHException, paramiko.PasswordRequiredException):
                continue

        raise paramiko.SSHException(f"Cannot load key from {path}")

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
        host_keys = paramiko.HostKeys()
        if self._known_hosts_path.exists():
            try:
                host_keys.load(str(self._known_hosts_path))
            except (OSError, paramiko.SSHException):
                pass

        self._known_hosts_path.parent.mkdir(parents=True, exist_ok=True)
        for alias in self._host_key_aliases()[:1]:
            host_keys.add(alias, remote_key.get_name(), remote_key)
        host_keys.save(str(self._known_hosts_path))
        try:
            self._known_hosts_path.chmod(0o600)
        except OSError:
            pass

    def _exec_raw(self, cmd: str, timeout: float = CMD_TIMEOUT) -> tuple[str, int]:
        """Execute a command via SSH exec_command. Returns (stdout, exit_code)."""
        if not self._client:
            raise ConnectionError("Not connected")

        with self._lock:
            try:
                stdin, stdout, stderr = self._client.exec_command(
                    cmd, timeout=timeout,
                )
                out = stdout.read().decode("utf-8", errors="replace")
                exit_code = stdout.channel.recv_exit_status()
                return out, exit_code
            except (paramiko.SSHException, socket.error) as exc:
                raise OSError(f"Command execution failed: {exc}") from exc

    def _exec(self, cmd: str, timeout: float = CMD_TIMEOUT) -> str:
        """Execute command, raise OSError on non-zero exit code."""
        output, code = self._exec_raw(cmd, timeout)
        if code != 0:
            # Read stderr for better error messages
            raise OSError(
                f"Command failed (exit {code}): {cmd[:120]}\n{output[:500]}"
            )
        return output

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
        from models.exec_result import ExecResult
        if not self._client:
            raise OSError("SCP exec: not connected")
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
                stdin_chan, stdout_chan, stderr_chan = self._client.exec_command(
                    cmd, timeout=timeout, environment=env or None,
                )
                if stdin:
                    try:
                        stdin_chan.write(stdin)
                        stdin_chan.flush()
                    except OSError:
                        pass
                    try:
                        stdin_chan.channel.shutdown_write()
                    except Exception:  # noqa: BLE001
                        pass
                stdout_buf = stdout_chan.read(stdout_cap + 1)
                stderr_buf = stderr_chan.read(stderr_cap + 1)
                rc = stdout_chan.channel.recv_exit_status()
            except (paramiko.SSHException, socket.error) as exc:
                raise OSError(f"SCP exec failed: {exc}") from exc
        truncated_stdout = len(stdout_buf) > stdout_cap
        truncated_stderr = len(stderr_buf) > stderr_cap
        return ExecResult(
            returncode=rc,
            stdout=bytes(stdout_buf[:stdout_cap]),
            stderr=bytes(stderr_buf[:stderr_cap]),
            truncated_stdout=truncated_stdout,
            truncated_stderr=truncated_stderr,
        )

    # -- FileBackend interface -----------------------------------------------

    def list_dir(self, path: str) -> list[FileItem]:
        path = self.normalize(path)
        output = self._exec(f"LANG=C LC_ALL=C ls -la {shlex.quote(path)}")
        return _parse_ls_la(output)

    def stat(self, path: str) -> FileItem:
        path = self.normalize(path)
        qpath = shlex.quote(path)
        if self._caps.has_stat_gnu:
            output = self._exec(
                f"stat --format='%n|%s|%Y|%f|%U|%G|%F' {qpath}"
            )
            return _parse_stat_gnu(output)
        # Fallback: ls -ld
        output = self._exec(f"LANG=C LC_ALL=C ls -ld {qpath}")
        items = _parse_ls_la(output)
        if not items:
            raise OSError(f"Cannot stat {path}: no output from ls -ld")
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

    def is_dir(self, path: str) -> bool:
        _, code = self._exec_raw(f"test -d {shlex.quote(self.normalize(path))}")
        return code == 0

    def exists(self, path: str) -> bool:
        _, code = self._exec_raw(f"test -e {shlex.quote(self.normalize(path))}")
        return code == 0

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
        self._exec(
            f"mv {shlex.quote(self.normalize(src))} {shlex.quote(self.normalize(dst))}"
        )

    def open_read(self, path: str) -> IO[bytes]:
        path = self.normalize(path)
        qpath = shlex.quote(path)

        if self._caps.transfer_method == "base64":
            output, code = self._exec_raw(
                f"base64 < {qpath}", TRANSFER_TIMEOUT
            )
            if code != 0:
                raise OSError(f"Cannot read {path}: base64 failed (exit {code})")
            try:
                data = base64.b64decode(
                    output.replace("\n", "").replace("\r", "").replace(" ", "")
                )
            except Exception as exc:
                raise OSError(f"Cannot decode {path}: {exc}") from exc
        else:
            # Raw cat — works for text; binary may be corrupted by encoding
            output, code = self._exec_raw(f"cat {qpath}", TRANSFER_TIMEOUT)
            if code != 0:
                raise OSError(f"Cannot read {path}: cat failed (exit {code})")
            data = output.encode("utf-8")

        buf = io.BytesIO(data)
        buf.seek(0)
        return buf

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        path = self.normalize(path)
        if append:
            try:
                with self.open_read(path) as f:
                    existing = f.read()
            except OSError:
                existing = b""
            writer = _SpooledWriter(self._exec, path, self._caps, append=False)
            writer.write(existing)
            return writer
        return _SpooledWriter(self._exec, path, self._caps)

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
        raise OSError(
            f"{type(self).__name__} does not expose file version history"
        )

    def copy(self, src: str, dst: str) -> None:
        """Server-side shell cp via SSH exec_command."""
        src = self.normalize(src)
        dst = self.normalize(dst)
        output, code = self._exec_raw(
            f"cp -p -- {shlex.quote(src)} {shlex.quote(dst)} 2>&1"
        )
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
        output, code = self._exec_raw(
            f"{tool} {shlex.quote(path)} 2>/dev/null"
        )
        if code != 0 or not output:
            return ""
        digest = output.split()[0] if output.split() else ""
        if digest and all(c in "0123456789abcdef" for c in digest.lower()):
            return f"{algorithm}:{digest.lower()}"
        return ""

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
