"""SSH/SFTP session implementing the FileBackend protocol."""

from __future__ import annotations

import functools
import hashlib
import logging
import os
import posixpath
import shlex
import socket
import stat as stat_module
import subprocess
import threading
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import IO, TYPE_CHECKING

import paramiko

from core import removal_cancel
from core.backend import SessionLifecycle
from core.client_identity import SSH_LOCAL_VERSION, apply_paramiko_banner_override
from core.exec_util import COMMAND_NOT_FOUND, digest_from_sum_output
from core.path_policy import MAX_RECURSIVE_DELETE_DEPTH, check_tree_depth, safe_join
from core.profiles import ConnectionProfile
from core.proxy import ProxyConfig, create_direct_socket, create_proxy_socket
from core.redaction import redact_text
from core.ssh_config import expand_proxy_command
from core.subprocess_env import clean_child_env
from models.file_item import FileItem
from security.protocol_line_split import split_lf_only_stream

if TYPE_CHECKING:
    from models.exec_result import ExecResult
    from models.interactive_shell import InteractiveShell

# Apply the class-level banner patch defensively on import, so a
# standalone invocation of this module (tests, scripts) doesn't depend
# on main.py having run first.
apply_paramiko_banner_override()

log = logging.getLogger(__name__)

HELPER_STDOUT_CAP = 4 * 1024 * 1024
HELPER_STDERR_CAP = 256 * 1024


def _read_limited_stream(stream, cap: int, label: str) -> bytes:
    data = stream.read(cap + 1)
    if isinstance(data, str):
        raw = data.encode("utf-8", errors="replace")
    else:
        raw = bytes(data)
    if len(raw) > cap:
        raise OSError(f"{label} exceeds {cap} byte cap")
    return raw


# What paramiko raises when the SFTP channel or the transport under it is
# gone: SFTPClient turns EOF into SSHException("Server connection dropped")
# (sftp_client._read_response); neither is an OSError.
_SFTP_CONNECTION_ERRORS = (paramiko.SSHException, EOFError)


def _sftp_errors_as_oserror(fn):
    """Re-raise what paramiko raises for a bad answer from ``fn`` as
    ``OSError``, the backend contract every caller (pane, transfers,
    compare) handles: a lost connection, a protocol violation
    (paramiko.SFTPError) and a name or link target that is not UTF-8
    (paramiko decodes those strictly)."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except _SFTP_CONNECTION_ERRORS as exc:
            detail = str(exc) or type(exc).__name__
            raise OSError(f"SFTP {fn.__name__}: connection to the server failed: {detail}") from exc
        except (paramiko.SFTPError, UnicodeError) as exc:
            raise OSError(f"SFTP {fn.__name__}: unusable answer from the server: {exc}") from exc

    return wrapper


def _listdir_attr(sftp: paramiko.SFTPClient, path: str) -> list[paramiko.SFTPAttributes]:
    """``sftp.listdir_attr(path)`` with names decoded leniently.

    SFTP v3 names are bytes and OpenSSH sends them as stored, so a latin-1
    name is ordinary; paramiko decodes each strictly as UTF-8
    (Message.get_text) and one such name made the whole folder unlistable
    with UnicodeDecodeError. This is paramiko's listdir_attr loop with
    ``errors="replace"`` - the FTP backend's choice for the same case: the
    entry shows, and addressing it fails cleanly on the server.
    """
    from paramiko.sftp import CMD_CLOSE, CMD_HANDLE, CMD_NAME, CMD_OPENDIR, CMD_READDIR

    def text(raw: bytes) -> str:
        return raw.decode("utf-8", errors="replace")

    t, msg = sftp._request(CMD_OPENDIR, sftp._adjust_cwd(path))
    if t != CMD_HANDLE:
        raise paramiko.SFTPError("Expected handle")
    handle = msg.get_binary()
    entries: list[paramiko.SFTPAttributes] = []
    while True:
        try:
            t, msg = sftp._request(CMD_READDIR, handle)
        except EOFError:  # end of the directory
            break
        if t != CMD_NAME:
            raise paramiko.SFTPError("Expected name response")
        for _ in range(msg.get_int()):
            filename = text(msg.get_string())
            longname = text(msg.get_string())
            attr = paramiko.SFTPAttributes._from_msg(msg, filename, longname)
            if filename not in (".", ".."):
                entries.append(attr)
    sftp._request(CMD_CLOSE, handle)
    return entries


#: known_hosts key type -> the host key algorithms that verify such a key.
#: An "ssh-rsa" entry is negotiated as rsa-sha2-512/256 (same key, SHA-2
#: signatures); paramiko no longer offers SHA-1 "ssh-rsa" by default.
_HOST_KEY_ALGORITHMS = {
    "ssh-rsa": ("rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"),
}


def _wait_readable(chan, timeout: float) -> bool:
    """Wait up to *timeout* s for *chan* to signal data (paramiko's pipe
    behind ``fileno``). Only a wait: that pipe can miss a wake-up."""
    import select as _select

    rlist, _, _ = _select.select([chan], [], [], timeout)
    return chan in rlist


def drain_exec_channel(
    chan,
    *,
    timeout: float | None,
    stdout_cap: int,
    stderr_cap: int,
    label: str,
) -> "ExecResult":
    """Read an exec channel's stdout and stderr to the end, each clipped
    at its cap, and return the :class:`~models.exec_result.ExecResult`.

    Both streams are drained together: reading one to its end while the
    other is unread deadlocks once the remote fills the channel window.
    Bytes above a cap are read and discarded so the remote can finish.
    Raises ``TimeoutError`` (an OSError) when the command has not exited
    after *timeout* seconds - the channel timeout only bounds a blocking
    recv, which this loop never makes.
    """
    from models.exec_result import ExecResult

    stdout_buf = bytearray()
    stderr_buf = bytearray()
    stdout_truncated = False
    stderr_truncated = False
    deadline = time.monotonic() + timeout if timeout is not None else None
    while True:
        if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
            break
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError(f"{label}: the command did not finish within {timeout:g} s")
        # Readiness is asked of the channel itself; the wait is only a
        # wait. paramiko's pipe behind fileno() can miss a wake-up (measured
        # under load: not readable 97 times in a row with data pending), and
        # a loop that read only after a wake-up never read again.
        if not (chan.recv_ready() or chan.recv_stderr_ready()):
            _wait_readable(chan, 0.1)
        if chan.recv_ready():
            room = stdout_cap - len(stdout_buf)
            if room > 0:
                chunk = chan.recv(min(65536, room))
                if chunk:
                    stdout_buf.extend(chunk)
            else:
                # Cap reached — drain to keep the remote
                # from blocking on a full pipe, but discard.
                chan.recv(65536)
                stdout_truncated = True
        if chan.recv_stderr_ready():
            room = stderr_cap - len(stderr_buf)
            if room > 0:
                chunk = chan.recv_stderr(min(65536, room))
                if chunk:
                    stderr_buf.extend(chunk)
            else:
                chan.recv_stderr(65536)
                stderr_truncated = True
    # Final drain after exit-status arrives.
    while chan.recv_ready():
        room = stdout_cap - len(stdout_buf)
        if room <= 0:
            chan.recv(65536)
            stdout_truncated = True
            continue
        stdout_buf.extend(chan.recv(min(65536, room)))
    while chan.recv_stderr_ready():
        room = stderr_cap - len(stderr_buf)
        if room <= 0:
            chan.recv_stderr(65536)
            stderr_truncated = True
            continue
        stderr_buf.extend(chan.recv_stderr(min(65536, room)))
    return ExecResult(
        returncode=chan.recv_exit_status(),
        stdout=bytes(stdout_buf),
        stderr=bytes(stderr_buf),
        truncated_stdout=stdout_truncated,
        truncated_stderr=stderr_truncated,
    )


class CleanEnvProxyCommand(paramiko.ProxyCommand):
    """paramiko's ProxyCommand, but the command gets a clean environment.

    paramiko starts it with ``subprocess.Popen`` and no ``env``, so it
    inherits this process's - in a frozen one-file build that includes
    LD_LIBRARY_PATH pointing at the extraction folder, and a ``bash -c``,
    ``nc`` or ``ssh -W`` jump resolves its libraries against the bundled
    ones (dist/axross-full 0.13.22: ``bash -c true`` "symbol lookup
    error"). paramiko's ``__init__`` takes no environment, so this one
    sets the same three attributes its send/recv/close use (a test holds
    them equal to paramiko's) and starts the process itself."""

    def __init__(self, command_line: str) -> None:
        # Deliberately not super().__init__(): it would start the command
        # with the inherited environment.
        self.cmd = shlex.split(command_line)
        self.process = subprocess.Popen(
            self.cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            env=clean_child_env(),
        )
        self.timeout = None


class HostKeyVerificationError(paramiko.SSHException):
    """Base class for SSH host key verification errors."""


class UnknownHostKeyError(HostKeyVerificationError):
    """Raised when a server host key is not present in known_hosts."""

    def __init__(self, host: str, key_type: str, fingerprint_sha256: str):
        super().__init__(f"Unknown host key for {host} ({key_type}, SHA256:{fingerprint_sha256})")
        self.host = host
        self.key_type = key_type
        self.fingerprint_sha256 = fingerprint_sha256


class HostKeyMismatchError(HostKeyVerificationError):
    """Raised when a server host key does not match known_hosts."""

    def __init__(self, host: str, key_type: str, fingerprint_sha256: str):
        super().__init__(f"Host key mismatch for {host} ({key_type}, SHA256:{fingerprint_sha256})")
        self.host = host
        self.key_type = key_type
        self.fingerprint_sha256 = fingerprint_sha256


class RevokedHostKeyError(HostKeyMismatchError):
    """Raised when known_hosts marks the server host key ``@revoked``."""

    def __init__(self, host: str, key_type: str, fingerprint_sha256: str):
        super().__init__(host, key_type, fingerprint_sha256)
        self.args = (f"Host key for {host} is revoked ({key_type}, SHA256:{fingerprint_sha256})",)


class KnownHosts(paramiko.HostKeys):
    """An OpenSSH known_hosts file, read line by line.

    paramiko's HostKeys.load raises InvalidHostKey for a line with a
    marker (``@cert-authority``, ``@revoked``) or a broken key, which
    failed every connect. Here a broken line is skipped, a
    ``@cert-authority`` line too (paramiko cannot check host
    certificates), and a ``@revoked`` key is remembered and refused for
    every host, never loaded as a trusted key. Lookup semantics stay
    paramiko's: the first key of a type listed for a host wins.
    """

    def __init__(self) -> None:
        super().__init__()
        self._revoked: set[bytes] = set()

    def load(self, filename) -> None:
        trusted: list[paramiko.hostkeys.HostKeyEntry] = []
        with open(filename, encoding="utf-8", errors="replace") as fh:
            for lineno, raw in enumerate(fh, 1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                marker = None
                if line.startswith("@"):
                    marker, _, line = line.partition(" ")
                    line = line.strip()
                entry = self._parse(line, lineno)
                if entry is None:
                    continue
                if marker == "@revoked":
                    self._revoked.add(entry.key.asbytes())
                elif marker is None:
                    trusted.append(entry)
                else:
                    log.debug("known_hosts line %d: %s line skipped", lineno, marker)
        for entry in trusted:
            if self.is_revoked(entry.key):
                continue
            key_type = entry.key.get_name()
            for host in entry.hostnames:
                known = self.lookup(host)
                if known is None or key_type not in known:
                    self.add(host, key_type, entry.key)

    @staticmethod
    def _parse(line: str, lineno: int):
        try:
            entry = paramiko.hostkeys.HostKeyEntry.from_line(line, lineno)
        except Exception as exc:  # noqa: BLE001 - one bad line must not void the file
            log.debug("known_hosts line %d skipped: %s", lineno, exc)
            return None
        if entry is None or entry.key is None:
            return None
        return entry

    def is_revoked(self, key: paramiko.PKey) -> bool:
        return key.asbytes() in self._revoked

    def save(self, filename) -> None:
        # Rewriting would drop comments, marker lines and key types
        # paramiko does not know; append_known_host adds a line instead.
        raise NotImplementedError("known_hosts is only appended to")


def load_known_hosts(path: Path) -> KnownHosts:
    """The known_hosts at *path*; empty when it is missing or unreadable."""
    host_keys = KnownHosts()
    if not path.exists():
        return host_keys
    try:
        host_keys.load(str(path))
        log.debug("Loaded known_hosts from %s", path)
    except OSError as e:
        log.warning("Could not load known_hosts: %s", e)
    return host_keys


def _hashes_host_names(path: Path) -> bool:
    """True when known_hosts already stores hashed host names (HashKnownHosts)."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                fields = raw.split()
                if fields and fields[0].startswith("@"):
                    fields = fields[1:]
                if fields and fields[0].startswith("|1|"):
                    return True
    except OSError:
        pass
    return False


def append_known_host(path: Path, alias: str, key: paramiko.PKey) -> None:
    """Add one ``alias keytype base64`` line at the end of known_hosts.

    The rest of the file and its mode stay as they are; a new file is
    created 0600 (a new parent folder 0700). The host name is hashed
    when the file already hashes its host names.
    """
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    name = paramiko.HostKeys.hash_host(alias) if _hashes_host_names(path) else alias
    line = f"{name} {key.get_name()} {key.get_base64()}\n".encode()
    fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        size = os.fstat(fd).st_size
        if size and os.pread(fd, 1, size - 1) != b"\n":
            line = b"\n" + line
        os.write(fd, line)
    finally:
        os.close(fd)


def _private_key_classes() -> list[type[paramiko.PKey]]:
    classes = [paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey]
    # DSSKey was removed in paramiko 4.x
    if hasattr(paramiko, "DSSKey"):
        classes.append(paramiko.DSSKey)
    return classes


def load_private_key(path: str, passphrase: str) -> paramiko.PKey:
    """Load the private key at *path*, trying every key format.

    An encrypted key without its passphrase, or with a wrong one, raises
    PasswordRequiredException (naming the file), so a caller can ask for
    the passphrase; any other unreadable key raises SSHException. Both
    used to end in one "Cannot load key", and Quick Connect never knew a
    passphrase was what was missing."""
    passphrase_arg = passphrase or None
    encrypted = False
    for cls in _private_key_classes():
        try:
            return cls.from_private_key_file(path, password=passphrase_arg)
        except paramiko.PasswordRequiredException:
            encrypted = True
        except paramiko.SSHException:
            continue
    if passphrase_arg is not None and not encrypted:
        # A wrong passphrase fails like a damaged file ("Bad password or
        # corrupt", "checkints do not match"); without one, an encrypted
        # key says so.
        for cls in _private_key_classes():
            try:
                cls.from_private_key_file(path, password=None)
            except paramiko.PasswordRequiredException:
                encrypted = True
                break
            except paramiko.SSHException:
                continue
            break  # it loads without a passphrase: not an encrypted key
    if encrypted:
        if passphrase_arg is None:
            raise paramiko.PasswordRequiredException(
                f"The key {path} is encrypted: it needs its passphrase"
            )
        raise paramiko.PasswordRequiredException(f"Wrong passphrase for the key {path}")
    raise paramiko.SSHException(f"Cannot load key from {path}")


class SSHSession(SessionLifecycle):
    """SFTP file backend over SSH, implementing the FileBackend protocol."""

    def __init__(self, profile: ConnectionProfile):
        self._profile = profile
        self._transport: paramiko.Transport | None = None
        self._home_dir: str = "/"
        self._thread_local = threading.local()
        self._thread_sftp: dict[int, paramiko.SFTPClient] = {}
        self._sftp_lock = threading.Lock()
        self._known_hosts_path = Path.home() / ".ssh" / "known_hosts"

    @property
    def name(self) -> str:
        return f"{self._profile.username}@{self._profile.host}"

    @property
    def connected(self) -> bool:
        return self._transport is not None and self._transport.is_active()

    @property
    def transport(self) -> paramiko.Transport | None:
        return self._transport

    @property
    def sftp(self) -> paramiko.SFTPClient:
        sftp = self._get_sftp_client()
        if sftp is None:
            raise ConnectionError("Not connected")
        return sftp

    def connect(
        self,
        password: str = "",
        key_passphrase: str = "",
        on_unknown_host: Callable[[UnknownHostKeyError], bool] | None = None,
        resolve_profile: object | None = None,
    ) -> None:
        """Establish SSH connection and open SFTP channel."""
        profile = self._profile
        family = self._socket_family()

        try:
            # Create socket (ProxyCommand, SOCKS/HTTP proxy, or direct)
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
                        f"SFTP proxy_type={profile.proxy_type!r} requires "
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

            log.info("Creating SSH transport to %s:%d", profile.host, profile.port)
            self._transport = paramiko.Transport(sock)
            self._transport.local_version = SSH_LOCAL_VERSION
            self._prefer_known_host_key_types()
            self._transport.start_client(timeout=10.0)
            self._verify_host_key(on_unknown_host=on_unknown_host)
            # Keepalive off by default — a fixed 30-s cadence is a
            # cross-session fingerprint. Opt-in per profile. See
            # docs/OPSEC.md #2.
            if profile.ssh_keepalive_interval > 0:
                self._transport.set_keepalive(profile.ssh_keepalive_interval)

            # Authenticate
            self._authenticate(password, key_passphrase)

            # Open one default SFTP channel for the current thread
            self._get_sftp_client()

            # Determine home directory
            try:
                self._home_dir = self.sftp.normalize(".")
            except Exception as e:
                log.warning("Could not determine home directory, defaulting to /: %s", e)
                self._home_dir = "/"

            log.info("SFTP session established. Home: %s", self._home_dir)
        except Exception:
            self.disconnect()
            raise

    def _socket_family(self) -> int:
        return {
            "auto": socket.AF_UNSPEC,
            "ipv4": socket.AF_INET,
            "ipv6": socket.AF_INET6,
        }.get(self._profile.address_family, socket.AF_UNSPEC)

    def _load_host_keys(self) -> KnownHosts:
        return load_known_hosts(self._known_hosts_path)

    def _host_key_aliases(self) -> list[str]:
        if self._profile.port == 22:
            return [self._profile.host]
        return [f"[{self._profile.host}]:{self._profile.port}"]

    def _prefer_known_host_key_types(self) -> None:
        """Offer the host key types known_hosts holds for this host first.

        A server has several host keys; paramiko's default order picks
        ECDSA/Ed25519 before RSA. With only the (correct) RSA key on
        record the negotiated ECDSA key then failed the check as a false
        mismatch. OpenSSH (HostKeyAlgorithms) and paramiko's SSHClient do
        the same reordering. Only the ORDER changes: a server without
        the known type still negotiates another one, and the check after
        start_client still refuses it.
        """
        if not self._transport:
            return
        host_keys = self._load_host_keys()
        known: set[str] = set()
        for alias in self._host_key_aliases():
            entry = host_keys.lookup(alias)
            if entry is None:
                continue
            for key_type in entry.keys():
                known.update(_HOST_KEY_ALGORITHMS.get(key_type, (key_type,)))
            # _verify_host_key decides on the first alias with an entry.
            break
        if not known:
            return
        options = self._transport.get_security_options()
        offered = list(options.key_types)
        first = [k for k in offered if k in known]
        if first:
            options.key_types = first + [k for k in offered if k not in known]

    @staticmethod
    def _fingerprint_sha256(key: paramiko.PKey) -> str:
        digest = hashlib.sha256(key.asbytes()).digest()
        import base64

        return base64.b64encode(digest).decode("ascii").rstrip("=")

    def _verify_host_key(
        self,
        on_unknown_host: Callable[[UnknownHostKeyError], bool] | None = None,
    ) -> None:
        """Verify the negotiated remote host key against known_hosts."""
        if not self._transport:
            raise ConnectionError("Transport not initialized")

        remote_key = self._transport.get_remote_server_key()
        key_type = remote_key.get_name()
        fingerprint = self._fingerprint_sha256(remote_key)
        host_keys = self._load_host_keys()
        if host_keys.is_revoked(remote_key):
            raise RevokedHostKeyError(self._host_key_aliases()[0], key_type, fingerprint)

        for alias in self._host_key_aliases():
            known = host_keys.lookup(alias)
            if known is None:
                continue
            if host_keys.check(alias, remote_key):
                log.info("Verified host key for %s", alias)
                return
            raise HostKeyMismatchError(alias, key_type, fingerprint)

        error = UnknownHostKeyError(self._host_key_aliases()[0], key_type, fingerprint)
        if on_unknown_host and on_unknown_host(error):
            self.trust_current_host_key()
            # Log type + full SHA256 fingerprint so future forensics can
            # detect a MITM flip that the user may have blindly accepted.
            log.info(
                "Trusted new host key for %s (%s, SHA256:%s)",
                error.host,
                key_type,
                fingerprint,
            )
            return
        raise error

    def trust_current_host_key(self) -> None:
        """Persist the currently negotiated host key to known_hosts."""
        if not self._transport:
            raise ConnectionError("Transport not initialized")

        remote_key = self._transport.get_remote_server_key()
        append_known_host(self._known_hosts_path, self._host_key_aliases()[0], remote_key)

    def _authenticate(self, password: str, key_passphrase: str) -> None:
        """Authenticate using the method specified in the profile."""
        profile = self._profile

        if profile.auth_type == "agent":
            log.info("Authenticating via SSH agent")
            agent = paramiko.Agent()
            agent_keys = agent.get_keys()
            if not agent_keys:
                raise paramiko.AuthenticationException("No keys available from SSH agent")

            for key in agent_keys:
                try:
                    self._transport.auth_publickey(profile.username, key)
                    log.info("Authenticated with agent key: %s", key.get_name())
                    return
                except paramiko.AuthenticationException:
                    continue
            raise paramiko.AuthenticationException("All SSH agent keys rejected")

        elif profile.auth_type == "key":
            key_path = profile.key_file
            if not key_path:
                raise ValueError("No key file specified")

            log.info("Authenticating with key file: %s", key_path)
            pkey = self._load_private_key(key_path, key_passphrase)
            self._transport.auth_publickey(profile.username, pkey)

        else:  # password
            pw = password or profile.get_password() or ""
            # Username is PII — keep at DEBUG so it doesn't ship to
            # centralised log aggregators by default, matching the
            # convention WinRM uses (see commit 9385438).
            log.info("Authenticating with password")
            log.debug("Auth-as user: %s", profile.username)
            self._transport.auth_password(profile.username, pw)

    def _load_private_key(self, path: str, passphrase: str) -> paramiko.PKey:
        """Load a private key, trying multiple formats."""
        return load_private_key(path, passphrase)

    def disconnect(self) -> None:
        """Close SFTP channel and SSH transport."""
        with self._sftp_lock:
            channels = list({id(client): client for client in self._thread_sftp.values()}.values())
            self._thread_sftp.clear()
            self._thread_local = threading.local()

        for channel in channels:
            try:
                channel.close()
            except Exception as exc:
                log.debug("SFTP channel close raised: %s", exc, exc_info=True)

        if self._transport:
            try:
                self._transport.close()
            except Exception as exc:
                log.debug("SSH transport close raised: %s", exc, exc_info=True)
            self._transport = None
            log.info("SSH session disconnected: %s", self.name)

        log.info("Disconnected from %s", self._profile.host)

    def open_sftp_channel(self) -> paramiko.SFTPClient:
        """Open an additional SFTP channel on the same transport.

        Useful for parallel operations (e.g., transfers while browsing).
        """
        if not self._transport or not self._transport.is_active():
            raise ConnectionError("Transport is not active")
        return self._open_sftp_client()

    @staticmethod
    def _channel_open(client: paramiko.SFTPClient | None) -> bool:
        """Whether *client*'s channel can still carry requests. A channel
        the server or this side closed stays dead; the transport (and the
        session's other channels) can be fine."""
        if client is None:
            return False
        try:
            channel = client.get_channel()
        except Exception:  # noqa: BLE001 - a broken client is a closed one
            return False
        return channel is not None and not channel.closed and not channel.eof_received

    def _get_sftp_client(self) -> paramiko.SFTPClient | None:
        """This thread's SFTP client on the session's transport. A client
        whose channel died is replaced: the connection manager shares a
        session whose transport is alive with every pane on the host, so
        a dead cached channel failed each of them until the last pane
        closed the session."""
        if not self._transport or not self._transport.is_active():
            return None

        thread_id = threading.get_ident()
        existing = getattr(self._thread_local, "sftp", None)
        if self._channel_open(existing):
            return existing

        with self._sftp_lock:
            existing = self._thread_sftp.get(thread_id)
            if not self._channel_open(existing):
                if existing is not None:
                    log.info("SFTP channel to %s was closed; opening a new one", self.name)
                    try:
                        existing.close()
                    except Exception as exc:  # noqa: BLE001 - it is dead already
                        log.debug("Closing the dead SFTP client raised: %s", exc)
                existing = self._open_sftp_client()
                self._thread_sftp[thread_id] = existing
            self._thread_local.sftp = existing
            return existing

    def _open_sftp_client(self) -> paramiko.SFTPClient:
        """A new SFTP channel. A server that refuses the SFTP subsystem
        (SSH and SCP working, SFTP switched off - common on NAS boxes)
        answers by closing the channel; paramiko then says only
        "Channel closed.", which reads like a dropped connection."""
        try:
            return paramiko.SFTPClient.from_transport(self._transport)
        except paramiko.ChannelException as exc:
            # The server would not open one more channel at all - not an
            # SFTP question (ChannelException is an SSHException, so it
            # must come first).
            raise OSError(
                f"{self.name}: the server refused to open another channel"
                f" ({exc.code}: {exc.text or 'no reason given'})."
                " SSH servers limit the channels per connection (OpenSSH"
                " MaxSessions, 10 by default); every pane, terminal and transfer"
                " on this host uses one. Close some of them, or raise the limit"
                " on the server."
            ) from exc
        except (paramiko.SSHException, EOFError) as exc:
            if self._transport is not None and self._transport.is_active():
                raise OSError(
                    f"{self.name}: the server refused the SFTP subsystem"
                    f" ({exc or 'channel closed'})."
                    " SSH works, so SFTP is probably switched off on the server (on a"
                    " Synology NAS: Control Panel > File Services > FTP > Enable SFTP"
                    " service). Use the SCP protocol for this host, or enable SFTP."
                ) from exc
            raise

    # --- FileBackend implementation ---

    def _list_attrs(self, path: str) -> list[paramiko.SFTPAttributes]:
        """The folder's entries; a name that is not UTF-8 does not make the
        whole folder unlistable (see :func:`_listdir_attr`)."""
        sftp = self.sftp
        try:
            return sftp.listdir_attr(path)
        except UnicodeDecodeError:
            log.debug("SFTP %s holds a name that is not UTF-8; listing it leniently", path)
            return _listdir_attr(sftp, path)

    @_sftp_errors_as_oserror
    def list_dir(self, path: str) -> list[FileItem]:
        items: list[FileItem] = []
        for attr in self._list_attrs(path):
            items.append(self._attr_to_item(attr))
        from core.path_policy import drop_unsafe_names

        return drop_unsafe_names(items, origin=f"SFTP {path}")

    @_sftp_errors_as_oserror
    def stat(self, path: str) -> FileItem:
        attr = self.sftp.lstat(path)
        name = posixpath.basename(path) or path
        return self._attr_to_item(attr, name_override=name)

    @_sftp_errors_as_oserror
    def is_dir(self, path: str) -> bool:
        """False only for "not found" (or a file on the way); a refused,
        failed or timed-out lstat is an OSError - the transfer manager
        and remove() pick folder or file from this answer."""
        try:
            attr = self.sftp.lstat(path)
        except (FileNotFoundError, NotADirectoryError):
            return False
        return stat_module.S_ISDIR(attr.st_mode or 0)

    @_sftp_errors_as_oserror
    def exists(self, path: str) -> bool:
        try:
            self.sftp.lstat(path)
            return True
        except FileNotFoundError:
            return False

    @_sftp_errors_as_oserror
    def mkdir(self, path: str) -> None:
        self.sftp.mkdir(path)

    @_sftp_errors_as_oserror
    def remove(self, path: str, recursive: bool = False) -> None:
        if self.is_dir(path):
            if recursive:
                self._rmtree(path)
            else:
                self.sftp.rmdir(path)
        else:
            self.sftp.remove(path)

    _MAX_TREE_DEPTH = MAX_RECURSIVE_DELETE_DEPTH

    def _rmtree(self, path: str, depth: int = 0) -> None:
        """Recursively remove a directory tree via SFTP."""
        check_tree_depth(path, depth, self._MAX_TREE_DEPTH)
        children = []
        for attr in self._list_attrs(path):
            try:
                child = safe_join(self, path, attr.filename)
            except ValueError as exc:
                raise OSError(
                    f"Cannot recursively remove {path}: unsafe child name {attr.filename!r}: {exc}"
                ) from exc
            children.append((attr, child))
        for attr, child in children:
            removal_cancel.checkpoint(child)  # the pane's Cancel stops here
            if stat_module.S_ISDIR(attr.st_mode or 0):
                self._rmtree(child, depth + 1)
            else:
                self.sftp.remove(child)
            removal_cancel.removed(child)
        self.sftp.rmdir(path)

    @_sftp_errors_as_oserror
    def rename(self, src: str, dst: str) -> None:
        posix_rename = getattr(self.sftp, "posix_rename", None)
        if posix_rename is not None:
            try:
                posix_rename(src, dst)
                return
            except OSError as e:
                log.debug("posix-rename %s -> %s failed, falling back: %s", src, dst, e)
        self.sftp.rename(src, dst)

    @_sftp_errors_as_oserror
    def open_read(self, path: str) -> IO[bytes]:
        # Pipelined, bounded read-ahead: see core.sftp_io.
        from core.sftp_io import open_read_ahead

        return open_read_ahead(lambda: self.sftp.open(path, "rb"))

    @_sftp_errors_as_oserror
    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        # WRITEs go out without waiting for each answer (one round trip per
        # 32 KiB otherwise); every answer is still checked: core.sftp_io.
        from core.sftp_io import PipelinedWriter

        return PipelinedWriter(self.sftp.open(path, "ab" if append else "wb"), append=append)

    def normalize(self, path: str) -> str:
        try:
            return self.sftp.normalize(path)
        except (OSError, UnicodeError, paramiko.SFTPError, *_SFTP_CONNECTION_ERRORS):
            return posixpath.normpath(path)

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        return posixpath.join(*parts)

    def parent(self, path: str) -> str:
        return posixpath.dirname(path) or "/"

    def home(self) -> str:
        return self._home_dir

    @_sftp_errors_as_oserror
    def chmod(self, path: str, mode: int) -> None:
        self.sftp.chmod(path, mode)

    @_sftp_errors_as_oserror
    def readlink(self, path: str) -> str:
        target = self.sftp.readlink(path) or ""
        if isinstance(target, bytes):
            # paramiko hands back the raw bytes of a target that is not
            # UTF-8 (sftp_client._to_unicode); names are decoded leniently.
            target = target.decode("utf-8", errors="replace")
        return target

    # SFTP speaks symlinks natively (paramiko's sftp.symlink); hardlinks
    # aren't in the SFTP v3 spec, so we fall back to a shell ``ln``
    # invocation and flag only symlinks as supported-without-caveats.
    supports_symlinks = True
    supports_hardlinks = True

    def symlink(self, target: str, link_path: str) -> None:
        """Create a symlink on the remote host. paramiko's argument
        order is ``(source, dest)`` — ``source`` is where the link
        POINTS TO, ``dest`` is where the link is created. We mirror
        os.symlink's order (target, link_path)."""
        try:
            self.sftp.symlink(target, link_path)
        except OSError:
            raise
        except Exception as exc:  # noqa: BLE001 — paramiko IOError etc.
            raise OSError(
                f"SFTP symlink({target!r} → {link_path!r}): {exc}",
            ) from exc

    def hardlink(self, target: str, link_path: str) -> None:
        """Hardlink via a remote ``ln`` shell call — SFTP v3 has no
        native hardlink operation. Fails cleanly when the remote
        host lacks ``ln`` or the two paths live on different
        filesystems (errors bubble up as OSError from the shell)."""
        if not self._transport or not self._transport.is_active():
            raise OSError("SSH hardlink: transport not active")
        chan = self._transport.open_session()
        try:
            chan.exec_command(
                f"ln -- {shlex.quote(target)} {shlex.quote(link_path)}",
            )
            err = _read_limited_stream(
                chan.makefile_stderr("rb"),
                HELPER_STDERR_CAP,
                "SSH hardlink stderr",
            )
            rc = chan.recv_exit_status()
        finally:
            chan.close()
        if rc != 0:
            raise OSError(
                f"SSH hardlink({target!r} → {link_path!r}) rc={rc}: "
                f"{err.decode('utf-8', errors='replace').strip()}"
            )

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        try:
            stats = self.sftp.statvfs(path)
            block_size = stats.f_frsize or stats.f_bsize or 0
            if block_size > 0:
                total = stats.f_blocks * block_size
                free = stats.f_bavail * block_size
                used = total - (stats.f_bfree * block_size)
                return (total, used, free)
        except Exception as e:
            log.debug("statvfs unavailable for %s: %s", path, e)

        try:
            if not self._transport or not self._transport.is_active():
                return (0, 0, 0)
            chan = self._transport.open_session()
            chan.exec_command(f"df -Pk -- {shlex.quote(path)}")
            output = _read_limited_stream(
                chan.makefile("rb"),
                HELPER_STDOUT_CAP,
                "SSH df stdout",
            ).decode("utf-8", errors="replace")
            _read_limited_stream(
                chan.makefile_stderr("rb"),
                HELPER_STDERR_CAP,
                "SSH df stderr",
            )
            chan.close()
            lines = [line.strip() for line in split_lf_only_stream(output) if line.strip()]
            if len(lines) < 2:
                return (0, 0, 0)
            parts = lines[-1].split()
            if len(parts) >= 4:
                total = int(parts[1]) * 1024
                used = int(parts[2]) * 1024
                free = int(parts[3]) * 1024
                return (total, used, free)
        except Exception as e:
            log.debug("df fallback unavailable for %s: %s", path, e)
        return (0, 0, 0)

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
        """Run a shell command on the remote host, return an
        :class:`~models.exec_result.ExecResult`.

        ``cmd`` is sent verbatim to the remote ``/bin/sh`` (or whatever
        the user's login shell is). Caller is responsible for escaping
        substituted arguments — use ``shlex.quote()`` for any path or
        user-supplied value spliced into the command string.

        ``stdin`` is fed to the remote process before its stdout/stderr
        are read. Pass ``None`` to skip stdin entirely.

        ``stdout_cap`` / ``stderr_cap`` clip each stream after that many
        bytes; the corresponding ``truncated_*`` flag on the result
        tells the caller a clip happened. Defaults are generous (1 MiB
        / 64 KiB) so most ``show``-style output round-trips intact.

        ``env`` keys are validated against ``[A-Za-z_][A-Za-z0-9_]*`` so
        a tainted key can't smuggle a second ``export`` line. Values
        are sent through paramiko's ``update_environment`` channel call
        — most sshd configs ignore client-set env unless ``AcceptEnv``
        whitelists the key, so don't rely on env propagation as a
        security boundary.

        Raises ``OSError`` on transport failure, NOT on a non-zero
        remote exit code; use ``.check()`` on the result for the latter.
        A command that outlives *timeout* raises ``TimeoutError``.
        """
        if not self._transport or not self._transport.is_active():
            raise OSError("SSH exec: transport not active")
        log.info(
            "SSH exec on %s@%s: %s%s",
            self._profile.username,
            self._profile.host,
            cmd[:120],
            "..." if len(cmd) > 120 else "",
        )
        if env:
            import re as _re

            for k, v in env.items():
                if not _re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k):
                    raise OSError(
                        f"SSH exec: env key {k!r} must match "
                        "[A-Za-z_][A-Za-z0-9_]* (refusing to send)"
                    )
                # F39: a tainted VALUE with embedded NUL would terminate
                # the C-string the SSH agent forwards; CR/LF would land
                # in some sshd logs as a forged log line. Symmetry with
                # the key allow-list — both halves of the env tuple are
                # equally adversary-controllable in practice.
                if "\x00" in v or "\r" in v or "\n" in v:
                    raise OSError(
                        f"SSH exec: env value for {k!r} must not contain "
                        "NUL/CR/LF (refusing to send). F39."
                    )
        chan = self._transport.open_session()
        try:
            if timeout is not None:
                chan.settimeout(timeout)
            if env:
                # paramiko's update_environment is best-effort; sshd
                # silently drops unwhitelisted keys.
                for k, v in env.items():
                    try:
                        chan.update_environment({k: v})
                    except paramiko.SSHException:
                        pass
            chan.exec_command(cmd)
            if stdin:
                try:
                    chan.sendall(stdin)
                except OSError as exc:
                    log.debug("SSH exec stdin sendall failed: %s", exc)
                try:
                    chan.shutdown_write()
                except OSError:
                    pass
            return drain_exec_channel(
                chan,
                timeout=timeout,
                stdout_cap=stdout_cap,
                stderr_cap=stderr_cap,
                label="SSH exec",
            )
        finally:
            try:
                chan.close()
            except Exception:  # noqa: BLE001
                pass

    def interactive_shell(
        self,
        *,
        term: str = "xterm-256color",
        cols: int = 80,
        rows: int = 24,
        env: dict[str, str] | None = None,
    ) -> "InteractiveShell":
        """Open a NEW interactive-shell channel on the existing SSH
        transport — multiplexing.

        The transport stays the same one used for SFTP and the
        FileBackend ops; we just open a second SSH channel on it,
        request a PTY, and invoke the user's login shell. File ops
        and the shell run concurrently against the same TCP
        connection + the same auth handshake.

        Use it like this::

            sess = SSHSession(profile)
            sess.connect(...)
            with sess.interactive_shell() as shell:
                shell.write(b"uname -a\\n")
                print(shell.read_until(b"$ ", timeout=5).decode())
            # File ops on ``sess`` continue to work — only the
            # shell channel was closed.

        ``env`` honours the same NUL/CR/LF guards as ``exec()``;
        most sshd configs ignore client-set env unless
        ``AcceptEnv`` whitelists the key.
        """
        from models.interactive_shell import InteractiveShell

        if not self._transport or not self._transport.is_active():
            raise OSError("SSH interactive_shell: transport not active")
        if env:
            import re as _re

            for k, v in env.items():
                if not _re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k):
                    raise OSError(
                        f"SSH interactive_shell: env key {k!r} must match [A-Za-z_][A-Za-z0-9_]*"
                    )
                if "\x00" in v or "\r" in v or "\n" in v:
                    raise OSError(
                        f"SSH interactive_shell: env value for {k!r} must not contain NUL/CR/LF"
                    )
        if "\r" in term or "\n" in term or "\x00" in term:
            raise ValueError("SSH interactive_shell: term must not contain NUL/CR/LF")
        chan = self._transport.open_session()
        try:
            chan.get_pty(term=term, width=int(cols), height=int(rows))
            if env:
                for k, v in env.items():
                    try:
                        chan.update_environment({k: v})
                    except paramiko.SSHException:
                        log.debug(
                            "SSH interactive_shell: env key %s rejected by sshd (likely AcceptEnv)",
                            k,
                        )
            chan.invoke_shell()
        except Exception:
            try:
                chan.close()
            except Exception:  # noqa: BLE001
                pass
            raise
        label = f"{self._profile.username}@{self._profile.host}:{self._profile.port}"
        log.info(
            "SSH interactive shell opened on %s (%dx%d %s) — multiplexed "
            "alongside %d existing channel(s) on the transport",
            label,
            cols,
            rows,
            term,
            len(self._transport._channels.values()) - 1
            if hasattr(self._transport, "_channels")
            else 0,
        )
        return InteractiveShell(chan, label=label)

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError(f"{type(self).__name__} does not expose file version history")

    def copy(self, src: str, dst: str) -> None:
        """Server-side copy via ``cp -p``. O(0) client bytes."""
        if not self._transport or not self._transport.is_active():
            raise ConnectionError("SSH transport not active")
        try:
            chan = self._transport.open_session()
            # Plain cp copies INTO an existing folder dst (review B6 twin).
            from core.telnet_client import copy_command

            chan.exec_command(copy_command(src, dst, preserve=True))
            stderr = _read_limited_stream(
                chan.makefile_stderr("rb"),
                HELPER_STDERR_CAP,
                "SSH copy stderr",
            ).decode("utf-8", errors="replace")
            rc = chan.recv_exit_status()
            chan.close()
            if rc != 0:
                raise OSError(f"cp {src} -> {dst} failed: rc={rc} stderr={stderr!r}")
        except paramiko.SSHException as exc:
            raise OSError(f"copy failed: {exc}") from exc

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        """Exec ``sha256sum`` / ``md5sum`` on the remote and parse the
        output. Cheap compared to SFTP streaming the whole file to us.

        Falls back to returning ``""`` when the requested algorithm
        lacks a CLI tool on the remote — caller then has the option to
        do a client-side streaming hash via :meth:`open_read`.
        """
        tool = {
            "sha256": "sha256sum",
            "sha1": "sha1sum",
            "md5": "md5sum",
        }.get(algorithm)
        if not tool:
            return ""
        if not self._transport or not self._transport.is_active():
            raise ConnectionError("SSH transport not active")
        try:
            chan = self._transport.open_session()
            chan.exec_command(f"{tool} -- {shlex.quote(path)}")
            # paramiko's makefile("r") still yields bytes on some
            # builds; decode explicitly so the f-string below doesn't
            # embed a ``b'...'`` repr.
            output = _read_limited_stream(
                chan.makefile("rb"),
                HELPER_STDOUT_CAP,
                "SSH checksum stdout",
            ).decode("utf-8", errors="replace")
            stderr = _read_limited_stream(
                chan.makefile_stderr("rb"),
                HELPER_STDERR_CAP,
                "SSH checksum stderr",
            ).decode("utf-8", errors="replace")
            rc = chan.recv_exit_status()
            chan.close()
            if rc in COMMAND_NOT_FOUND:
                # No such tool on this host: "" lets the caller hash the
                # stream, as documented above.
                log.debug("%s unavailable on %s: %s", tool, self._profile.host, stderr.strip())
                return ""
            if rc != 0:
                raise OSError(f"{tool} failed on {path}: rc={rc} stderr={stderr!r}")
            hex_digest = digest_from_sum_output(output, algorithm)
            if not hex_digest:
                return ""
            return f"{algorithm}:{hex_digest}"
        except paramiko.SSHException as exc:
            raise OSError(f"checksum failed: {exc}") from exc

    def _attr_to_item(self, attr: paramiko.SFTPAttributes, name_override: str = "") -> FileItem:
        mode = attr.st_mode or 0
        is_link = stat_module.S_ISLNK(mode)
        is_dir = stat_module.S_ISDIR(mode)

        mtime = attr.st_mtime or 0
        modified = datetime.fromtimestamp(mtime) if mtime else datetime.fromtimestamp(0)
        atime = attr.st_atime or 0
        accessed = datetime.fromtimestamp(atime) if atime else None

        return FileItem(
            name=name_override or attr.filename,
            size=attr.st_size or 0,
            modified=modified,
            permissions=mode & 0o7777,
            is_dir=is_dir,
            is_link=is_link,
            owner=str(attr.st_uid) if attr.st_uid is not None else "",
            group=str(attr.st_gid) if attr.st_gid is not None else "",
            accessed=accessed,
        )
