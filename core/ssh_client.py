"""SSH/SFTP session implementing the FileBackend protocol."""
from __future__ import annotations

import hashlib
import logging
import posixpath
import shlex
import socket
import stat as stat_module
import threading
from datetime import datetime
from pathlib import Path
from typing import IO
from collections.abc import Callable

import paramiko

from core.client_identity import SSH_LOCAL_VERSION, apply_paramiko_banner_override
from core.profiles import ConnectionProfile
from core.proxy import ProxyConfig, create_direct_socket, create_proxy_socket
from core.ssh_config import expand_proxy_command
from models.file_item import FileItem

# Apply the class-level banner patch defensively on import, so a
# standalone invocation of this module (tests, scripts) doesn't depend
# on main.py having run first.
apply_paramiko_banner_override()

log = logging.getLogger(__name__)


class HostKeyVerificationError(paramiko.SSHException):
    """Base class for SSH host key verification errors."""


class UnknownHostKeyError(HostKeyVerificationError):
    """Raised when a server host key is not present in known_hosts."""

    def __init__(self, host: str, key_type: str, fingerprint_sha256: str):
        super().__init__(
            f"Unknown host key for {host} ({key_type}, SHA256:{fingerprint_sha256})"
        )
        self.host = host
        self.key_type = key_type
        self.fingerprint_sha256 = fingerprint_sha256


class HostKeyMismatchError(HostKeyVerificationError):
    """Raised when a server host key does not match known_hosts."""

    def __init__(self, host: str, key_type: str, fingerprint_sha256: str):
        super().__init__(
            f"Host key mismatch for {host} ({key_type}, SHA256:{fingerprint_sha256})"
        )
        self.host = host
        self.key_type = key_type
        self.fingerprint_sha256 = fingerprint_sha256


class SSHSession:
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

            log.info("Creating SSH transport to %s:%d", profile.host, profile.port)
            self._transport = paramiko.Transport(sock)
            self._transport.local_version = SSH_LOCAL_VERSION
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

    def _load_host_keys(self) -> paramiko.HostKeys:
        host_keys = paramiko.HostKeys()
        if not self._known_hosts_path.exists():
            return host_keys
        try:
            host_keys.load(str(self._known_hosts_path))
            log.debug("Loaded known_hosts from %s", self._known_hosts_path)
        except (OSError, paramiko.SSHException) as e:
            log.warning("Could not load known_hosts: %s", e)
        return host_keys

    def _host_key_aliases(self) -> list[str]:
        if self._profile.port == 22:
            return [self._profile.host]
        return [f"[{self._profile.host}]:{self._profile.port}"]

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
                error.host, key_type, fingerprint,
            )
            return
        raise error

    def trust_current_host_key(self) -> None:
        """Persist the currently negotiated host key to known_hosts."""
        if not self._transport:
            raise ConnectionError("Transport not initialized")

        remote_key = self._transport.get_remote_server_key()
        host_keys = self._load_host_keys()
        aliases = self._host_key_aliases()

        self._known_hosts_path.parent.mkdir(parents=True, exist_ok=True)
        for alias in aliases[:1]:
            host_keys.add(alias, remote_key.get_name(), remote_key)
        host_keys.save(str(self._known_hosts_path))
        try:
            self._known_hosts_path.chmod(0o600)
        except OSError:
            log.debug("Could not set permissions on %s", self._known_hosts_path, exc_info=True)

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
        key_classes = [
            paramiko.Ed25519Key,
            paramiko.ECDSAKey,
            paramiko.RSAKey,
        ]
        # DSSKey was removed in paramiko 4.x
        if hasattr(paramiko, "DSSKey"):
            key_classes.append(paramiko.DSSKey)
        passphrase_arg = passphrase or None

        for cls in key_classes:
            try:
                return cls.from_private_key_file(path, password=passphrase_arg)
            except (paramiko.SSHException, paramiko.PasswordRequiredException):
                continue

        raise paramiko.SSHException(f"Cannot load key from {path}")

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
        return paramiko.SFTPClient.from_transport(self._transport)

    def _get_sftp_client(self) -> paramiko.SFTPClient | None:
        if not self._transport or not self._transport.is_active():
            return None

        thread_id = threading.get_ident()
        existing = getattr(self._thread_local, "sftp", None)
        if existing is not None:
            return existing

        with self._sftp_lock:
            existing = self._thread_sftp.get(thread_id)
            if existing is None:
                existing = paramiko.SFTPClient.from_transport(self._transport)
                self._thread_sftp[thread_id] = existing
            self._thread_local.sftp = existing
            return existing

    # --- FileBackend implementation ---

    def list_dir(self, path: str) -> list[FileItem]:
        items: list[FileItem] = []
        for attr in self.sftp.listdir_attr(path):
            items.append(self._attr_to_item(attr))
        return items

    def stat(self, path: str) -> FileItem:
        attr = self.sftp.lstat(path)
        name = posixpath.basename(path) or path
        return self._attr_to_item(attr, name_override=name)

    def is_dir(self, path: str) -> bool:
        try:
            attr = self.sftp.lstat(path)
            return stat_module.S_ISDIR(attr.st_mode or 0)
        except OSError:
            return False

    def exists(self, path: str) -> bool:
        try:
            self.sftp.lstat(path)
            return True
        except FileNotFoundError:
            return False

    def mkdir(self, path: str) -> None:
        self.sftp.mkdir(path)

    def remove(self, path: str, recursive: bool = False) -> None:
        if self.is_dir(path):
            if recursive:
                self._rmtree(path)
            else:
                self.sftp.rmdir(path)
        else:
            self.sftp.remove(path)

    def _rmtree(self, path: str) -> None:
        """Recursively remove a directory tree via SFTP."""
        for attr in self.sftp.listdir_attr(path):
            child = posixpath.join(path, attr.filename)
            if stat_module.S_ISDIR(attr.st_mode or 0):
                self._rmtree(child)
            else:
                self.sftp.remove(child)
        self.sftp.rmdir(path)

    def rename(self, src: str, dst: str) -> None:
        posix_rename = getattr(self.sftp, "posix_rename", None)
        if posix_rename is not None:
            try:
                posix_rename(src, dst)
                return
            except OSError as e:
                log.debug("posix-rename %s -> %s failed, falling back: %s", src, dst, e)
        self.sftp.rename(src, dst)

    def open_read(self, path: str) -> IO[bytes]:
        return self.sftp.open(path, "rb")

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        return self.sftp.open(path, "ab" if append else "wb")

    def normalize(self, path: str) -> str:
        try:
            return self.sftp.normalize(path)
        except OSError:
            return posixpath.normpath(path)

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        return posixpath.join(*parts)

    def parent(self, path: str) -> str:
        return posixpath.dirname(path) or "/"

    def home(self) -> str:
        return self._home_dir

    def chmod(self, path: str, mode: int) -> None:
        self.sftp.chmod(path, mode)

    def readlink(self, path: str) -> str:
        return self.sftp.readlink(path) or ""

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
            err = chan.makefile_stderr("r").read()
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
            output = chan.makefile("r").read()
            _ = chan.makefile_stderr("r").read()
            chan.close()
            lines = [line.strip() for line in output.splitlines() if line.strip()]
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
        """
        from models.exec_result import ExecResult
        if not self._transport or not self._transport.is_active():
            raise OSError("SSH exec: transport not active")
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
            # Read stdout + stderr concurrently up to their caps. We do
            # this with select() to avoid the deadlock where a chatty
            # remote fills its stderr pipe while we're blocked on stdout.
            import select as _select
            stdout_buf = bytearray()
            stderr_buf = bytearray()
            stdout_truncated = False
            stderr_truncated = False
            while True:
                if chan.exit_status_ready() and not chan.recv_ready() \
                        and not chan.recv_stderr_ready():
                    break
                rlist, _, _ = _select.select([chan], [], [], 0.1)
                if chan in rlist:
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
                    chan.recv(65536); stdout_truncated = True
                    continue
                stdout_buf.extend(chan.recv(min(65536, room)))
            while chan.recv_stderr_ready():
                room = stderr_cap - len(stderr_buf)
                if room <= 0:
                    chan.recv_stderr(65536); stderr_truncated = True
                    continue
                stderr_buf.extend(chan.recv_stderr(min(65536, room)))
            rc = chan.recv_exit_status()
        finally:
            try:
                chan.close()
            except Exception:  # noqa: BLE001
                pass
        return ExecResult(
            returncode=rc,
            stdout=bytes(stdout_buf),
            stderr=bytes(stderr_buf),
            truncated_stdout=stdout_truncated,
            truncated_stderr=stderr_truncated,
        )

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError(
            f"{type(self).__name__} does not expose file version history"
        )

    def copy(self, src: str, dst: str) -> None:
        """Server-side copy via ``cp -p``. O(0) client bytes."""
        if not self._transport or not self._transport.is_active():
            raise ConnectionError("SSH transport not active")
        try:
            chan = self._transport.open_session()
            chan.exec_command(
                f"cp -p -- {shlex.quote(src)} {shlex.quote(dst)}"
            )
            stderr = chan.makefile_stderr("rb").read().decode(
                "utf-8", errors="replace")
            rc = chan.recv_exit_status()
            chan.close()
            if rc != 0:
                raise OSError(
                    f"cp {src} -> {dst} failed: rc={rc} stderr={stderr!r}"
                )
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
            output = chan.makefile("rb").read().decode("utf-8", errors="replace")
            stderr = chan.makefile_stderr("rb").read().decode("utf-8", errors="replace")
            rc = chan.recv_exit_status()
            chan.close()
            if rc != 0:
                raise OSError(
                    f"{tool} failed on {path}: rc={rc} stderr={stderr!r}"
                )
            hex_digest = output.split()[0] if output else ""
            if not hex_digest:
                return ""
            return f"{algorithm}:{hex_digest.lower()}"
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
