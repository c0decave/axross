"""Rsync backend implementing the FileBackend protocol.

Supports two operational modes:

1. **Browse mode** — uses ``rsync --list-only`` to enumerate files and
   directories on a remote rsync server (rsyncd) or via SSH transport.
2. **Transfer engine** — uses rsync as an optimised delta-transfer
   mechanism between local and/or remote paths, with real-time progress
   callback support via ``--progress`` output parsing.

The backend shells out to the ``rsync`` binary via :mod:`subprocess`.
No third-party Python packages are required beyond a working rsync
installation on the host system.
"""
from __future__ import annotations

import io
import logging
import os
import posixpath
import re
import shlex
import shutil
import stat as stat_module
import subprocess
import tempfile
from datetime import datetime
from typing import IO, Callable

from models.file_item import FileItem


# Env vars we actually want to forward to rsync / ssh. Everything
# else (AWS_*, *_TOKEN, *_KEY, GITHUB_*, editor/shell personalisation)
# stays in the parent process. See docs/OPSEC.md finding #9.
_ENV_ALLOWLIST = (
    "HOME", "PATH", "USER", "LOGNAME",
    "LANG", "LC_ALL", "TZ",
    "SSH_AUTH_SOCK",  # required for ssh-agent auth to keep working
)


def _build_allowlisted_env() -> dict[str, str]:
    """Return an os.environ subset limited to the allow-list above.

    Guarantees a non-empty ``PATH`` even if the caller ran with one
    unset — rsync needs ``ssh`` / shell binaries discoverable.
    """
    env: dict[str, str] = {}
    for key in _ENV_ALLOWLIST:
        value = os.environ.get(key)
        if value is not None:
            env[key] = value
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    return env


# ---- proxy helpers ----------------------------------------------------- #

def _resolve_nc_with_proxy_support() -> str:
    """Return the path to a ``netcat`` build that supports ``-X``
    (SOCKS proxy) and ``-x host:port`` (proxy address). On most Linux
    distros this is OpenBSD nc (``/usr/bin/nc`` from ``netcat-openbsd``).
    On systems where only ncat (Nmap project) is installed, ``-X`` has
    different semantics; we explicitly prefer the OpenBSD variant.

    Raises :class:`OSError` when no suitable nc is found, with a
    pointer to the package that provides one.
    """
    candidates = ("/usr/bin/nc.openbsd", "/usr/bin/netcat", "/usr/bin/nc")
    import subprocess
    for path in candidates:
        if not os.path.exists(path):
            continue
        try:
            r = subprocess.run([path, "-h"], capture_output=True, text=True, timeout=2)
        except (subprocess.TimeoutExpired, OSError):
            continue
        merged = (r.stdout or "") + (r.stderr or "")
        # OpenBSD nc spells the SOCKS proxy flags in its help output.
        if "-X" in merged and "-x" in merged and "proxy" in merged.lower():
            return path
    raise OSError(
        "No netcat with SOCKS-proxy support found on PATH. Install "
        "the OpenBSD variant (Debian/Ubuntu: ``netcat-openbsd``; "
        "Arch: ``openbsd-netcat``; Fedora: ``netcat``).",
    )


def _nc_proxy_scheme(proxy_type: str) -> str:
    if proxy_type == "socks5":
        return "5"
    if proxy_type == "socks4":
        return "4"
    if proxy_type == "http":
        return "connect"
    raise ValueError(f"Unknown proxy_type: {proxy_type}")


def _nc_proxy_address(proxy) -> str:
    """Format ``host:port`` for OpenBSD nc's ``-x`` flag, bracketing
    IPv6 literals so the port separator stays unambiguous.
    """
    import socket as _socket
    host = proxy.host
    try:
        _socket.inet_pton(_socket.AF_INET6, host)
        return f"[{host}]:{int(proxy.port)}"
    except OSError:
        return f"{host}:{int(proxy.port)}"


def _build_rsync_connect_prog(proxy, daemon_port: int) -> str:
    """Build the ``RSYNC_CONNECT_PROG`` value for rsync-daemon mode.

    rsync 3.0+ recognises this env var and replaces its direct TCP
    connect with a child process whose stdio is the daemon channel.
    We hand it an nc invocation that does the SOCKS / HTTP dial-out
    and connects to the rsync daemon's port.

    Note: rsync substitutes only ``%H`` (host) into the env-var
    string — *not* ``%P``. The man page is explicit:

        The string may contain the escape "%H" to represent the
        hostname specified in the rsync command.

    The daemon port has to be baked into the connect-prog string at
    build time. We pass ``daemon_port`` (typically 873, or the
    profile's override) so each session gets the correct value.
    """
    nc = _resolve_nc_with_proxy_support()
    scheme = _nc_proxy_scheme(proxy.proxy_type)
    proxy_addr = _nc_proxy_address(proxy)
    # OpenBSD nc does not propagate -x user:pass auth to SOCKS/HTTP
    # in every build; we warn rather than silently drop the auth bit.
    if proxy.username:
        log.warning(
            "RSYNC_CONNECT_PROG: nc does not propagate proxy auth "
            "credentials to the daemon-mode connect. Use rsync-over-SSH "
            "if your proxy requires authentication.",
        )
    return (
        f"{shlex.quote(nc)} -X {scheme} -x {shlex.quote(proxy_addr)} "
        f"%H {int(daemon_port)}"
    )


def _build_ssh_proxy_command(proxy) -> str:
    """Build the value for ``ssh -o ProxyCommand=...`` so the SSH
    dial-out underneath rsync-over-SSH (or any ssh) routes through
    the proxy. ``%h`` and ``%p`` are openssh's placeholders for the
    target host and port — ssh substitutes them at dial time.
    """
    nc = _resolve_nc_with_proxy_support()
    scheme = _nc_proxy_scheme(proxy.proxy_type)
    proxy_addr = _nc_proxy_address(proxy)
    return f"{nc} -X {scheme} -x {proxy_addr} %h %p"


def _redact_rsync_cmd(cmd: list[str]) -> str:
    """Redact sensitive flags before logging.

    rsync's ``-e "ssh -i /path/to/key"`` carries a private-key path
    that shouldn't land in shared log stores. Absolute paths to
    ``-i`` key files and any ``--password-file`` argument are masked.
    """
    out: list[str] = []
    redact_next = False
    for arg in cmd:
        if redact_next:
            out.append("<REDACTED>")
            redact_next = False
            continue
        if arg.startswith("-e ") and "-i " in arg:
            # Inner "ssh -i /path" — hide the key path.
            out.append(re.sub(r"-i\s+\S+", "-i <REDACTED>", arg))
        elif arg == "--password-file":
            out.append(arg)
            redact_next = True
        elif arg.startswith("--password-file="):
            out.append("--password-file=<REDACTED>")
        else:
            out.append(arg)
    return " ".join(out)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex for parsing ``rsync --list-only`` output lines.
#
# Typical lines look like:
#   drwxr-xr-x        4,096 2024/01/15 10:30:00 dirname
#   -rw-r--r--      123,456 2024/01/15 10:30:00 filename
#   lrwxrwxrwx           12 2024/01/15 10:30:00 link -> target
#
# Module listing (no path yet) returns lines like:
#   modulename      a description
# ---------------------------------------------------------------------------
_LIST_RE = re.compile(
    r"^(?P<perms>[dlcbps-][rwxstSTlL-]{9})\s+"
    r"(?P<size>[\d,]+)\s+"
    r"(?P<date>\d{4}/\d{2}/\d{2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<name>.+)$"
)

_MODULE_RE = re.compile(r"^(?P<name>\S+)\s+(?P<desc>.*)$")

# Regex for parsing ``--progress`` output.
# Example:   1,234,567  42%   12.34MB/s    0:00:03
_PROGRESS_RE = re.compile(
    r"^\s*(?P<bytes>[\d,]+)\s+(?P<pct>\d+)%\s+(?P<rate>\S+)\s+(?P<eta>\S+)"
)


def _parse_permissions(perm_str: str) -> int:
    """Convert an ``rwxrwxrwx`` string (9 chars) to a numeric mode."""
    if len(perm_str) < 9:
        return 0
    # Take the last 9 characters (skip type char if present)
    p = perm_str[-9:]
    mode = 0
    bits = (
        stat_module.S_IRUSR, stat_module.S_IWUSR, stat_module.S_IXUSR,
        stat_module.S_IRGRP, stat_module.S_IWGRP, stat_module.S_IXGRP,
        stat_module.S_IROTH, stat_module.S_IWOTH, stat_module.S_IXOTH,
    )
    for ch, bit in zip(p, bits):
        if ch not in ("-", "l", "L", "S", "T"):
            mode |= bit
        # Handle special bits encoded in execute positions
        if ch in ("s", "S") and bit == stat_module.S_IXUSR:
            mode |= stat_module.S_ISUID
            if ch == "s":
                mode |= bit
        elif ch in ("s", "S") and bit == stat_module.S_IXGRP:
            mode |= stat_module.S_ISGID
            if ch == "s":
                mode |= bit
        elif ch in ("t", "T") and bit == stat_module.S_IXOTH:
            mode |= stat_module.S_ISVTX
            if ch == "t":
                mode |= bit
    return mode


class _RsyncWriter:
    """Write to a temporary file; upload via rsync on close."""

    def __init__(self, session: "RsyncSession", remote_path: str):
        self._session = session
        self._remote_path = remote_path
        self._tmp = tempfile.NamedTemporaryFile(delete=False)
        self._closed = False

    # -- IO[bytes] interface --------------------------------------------------

    def write(self, data: bytes) -> int:
        return self._tmp.write(data)

    def read(self, n: int = -1) -> bytes:
        return self._tmp.read(n)

    def seek(self, pos: int, whence: int = 0) -> int:
        return self._tmp.seek(pos, whence)

    def tell(self) -> int:
        return self._tmp.tell()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._tmp.close()
        try:
            self._session._upload(self._tmp.name, self._remote_path)
        finally:
            try:
                os.unlink(self._tmp.name)
            except OSError:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class RsyncSession:
    """Rsync backend implementing the FileBackend protocol.

    Supports both native rsync daemon protocol (``rsync://``) and
    SSH-tunnelled rsync (``rsync -e ssh``).
    """

    def __init__(
        self,
        host: str,
        port: int = 873,
        module: str = "",
        username: str = "",
        password: str = "",
        ssh_mode: bool = False,
        ssh_key: str = "",
        preserve_metadata: bool = False,
        proxy_type: str = "none",
        proxy_host: str = "",
        proxy_port: int = 0,
        proxy_username: str = "",
        proxy_password: str = "",
    ):
        self._host = host
        self._port = port
        self._module = module.strip("/")
        self._username = username
        self._password = password
        self._ssh_mode = ssh_mode
        self._ssh_key = ssh_key
        self._preserve_metadata = preserve_metadata
        from core.proxy import ProxyConfig
        self._proxy = ProxyConfig(
            proxy_type=proxy_type or "none",
            host=proxy_host,
            port=int(proxy_port or 0),
            username=proxy_username,
            password=proxy_password,
        )
        self._connected = False

        self._rsync_bin = shutil.which("rsync")
        if self._rsync_bin is None:
            raise OSError(
                "rsync binary not found on PATH. "
                "Please install rsync to use this backend."
            )

        # Verify connectivity by listing the module root.
        self._probe_connection()

    # --------------------------------------------------------------------- #
    #  Properties                                                            #
    # --------------------------------------------------------------------- #

    @property
    def name(self) -> str:
        if self._ssh_mode:
            user = f"{self._username}@" if self._username else ""
            base_path = "/" if not self._module else f"/{self._module.strip('/')}"
            return f"{user}{self._host}:{base_path} (rsync/ssh)"
        return f"rsync://{self._host}/{self._module}"

    @property
    def connected(self) -> bool:
        return self._connected

    # --------------------------------------------------------------------- #
    #  Connection lifecycle                                                  #
    # --------------------------------------------------------------------- #

    def _probe_connection(self) -> None:
        """Probe the rsync server by listing the module root."""
        try:
            url = self._build_url("/")
            self._run_rsync(["--list-only", url])
            self._connected = True
            log.info(
                "rsync connected: %s (ssh=%s, port=%d)",
                self.name, self._ssh_mode, self._port,
            )
        except OSError as exc:
            self._connected = False
            raise OSError(
                f"Cannot connect to rsync server {self._host}: {exc}"
            ) from exc

    def close(self) -> None:
        """Mark the session as closed (rsync is stateless)."""
        self._connected = False
        log.info("rsync session closed: %s", self.name)

    def disconnect(self) -> None:
        self.close()

    # --------------------------------------------------------------------- #
    #  URL / command helpers                                                 #
    # --------------------------------------------------------------------- #

    def _build_url(self, path: str) -> str:
        """Build a remote rsync URL for *path*.

        For native rsync daemon: ``rsync://[user@]host[:port]/module/path``
        For SSH mode: ``[user@]host::module/path`` or ``[user@]host:/path``
        """
        clean = path.lstrip("/")

        if self._ssh_mode:
            user = f"{self._username}@" if self._username else ""
            base_path = "/" if not self._module else f"/{self._module.strip('/')}"
            remote_path = base_path if not clean else posixpath.join(base_path, clean)
            return f"{user}{self._host}:{remote_path}"

        # Native rsync daemon URL
        user = f"{self._username}@" if self._username else ""
        port = f":{self._port}" if self._port != 873 else ""
        module = self._module
        if module and clean:
            return f"rsync://{user}{self._host}{port}/{module}/{clean}"
        if module:
            return f"rsync://{user}{self._host}{port}/{module}/"
        return f"rsync://{user}{self._host}{port}/"

    def _archive_flags(self) -> list[str]:
        """Flags equivalent to archive mode, minus the metadata that
        would leak local UID/GID/perms/mtime to the receiver.

        ``-a`` expands to ``-rlptgoD`` which is wonderful for genuine
        backup flows but reveals the client's UID scheme and umask.
        Default flips to a neutral ``-rlt --chmod=ugo=rwX --no-owner
        --no-group --no-perms`` shape unless the profile's
        ``rsync_preserve_metadata`` toggle is on. See docs/OPSEC.md #6.
        """
        if self._preserve_metadata:
            return ["-a"]
        return [
            "-rlt",
            "--no-owner",
            "--no-group",
            "--no-perms",
            "--chmod=ugo=rwX",
        ]

    def _base_args(self) -> list[str]:
        """Return base rsync arguments common to all commands."""
        assert self._rsync_bin is not None
        args: list[str] = [self._rsync_bin]

        if self._ssh_mode:
            ssh_cmd = "ssh"
            if self._port != 22:
                ssh_cmd += f" -p {self._port}"
            if self._ssh_key:
                ssh_cmd += f" -i {shlex.quote(self._ssh_key)}"
            ssh_cmd += " -o BatchMode=yes"
            # Defensive ``getattr`` — unit tests sometimes construct
            # RsyncSession via ``object.__new__`` and set only the
            # attrs they care about, so a missing ``_proxy`` shouldn't
            # crash this method.
            proxy = getattr(self, "_proxy", None)
            if proxy is not None and proxy.enabled:
                # Inject ProxyCommand so the underlying ssh dial-out
                # itself routes through SOCKS / HTTP. See
                # docs/PROXY_SUPPORT.md for the nc / netcat-bsd
                # availability check.
                pc = _build_ssh_proxy_command(proxy)
                ssh_cmd += f" -o ProxyCommand={shlex.quote(pc)}"
            args += ["-e", ssh_cmd]
        else:
            if self._port != 873:
                args += ["--port", str(self._port)]

        return args

    def _build_env(self) -> dict[str, str]:
        """Build environment dict, injecting RSYNC_PASSWORD if needed.

        Also wires the proxy:

        * For rsync-over-SSH the proxy is on the ``-e ssh -o ProxyCommand=...``
          line in :meth:`_base_args`, no env var needed.
        * For native rsync-daemon mode (``rsync://``) we set
          ``RSYNC_CONNECT_PROG`` so rsync 3.0+ pipes the daemon TCP
          connection through ``nc -X 5 -x proxy:port`` (or HTTP
          equivalent). Without this, the daemon connect would bypass
          the proxy entirely.

        Do NOT clone the full local ``os.environ`` — see docs/OPSEC.md #9.
        """
        env = _build_allowlisted_env()
        if self._password and not self._ssh_mode:
            env["RSYNC_PASSWORD"] = self._password
        proxy = getattr(self, "_proxy", None)
        if proxy is not None and proxy.enabled and not self._ssh_mode:
            env["RSYNC_CONNECT_PROG"] = _build_rsync_connect_prog(
                proxy, self._port,
            )
        return env

    def _run_rsync(
        self,
        extra_args: list[str],
        *,
        capture: bool = True,
        timeout: int = 60,
    ) -> str:
        """Execute rsync with the given extra arguments.

        Returns captured stdout on success. Raises :class:`OSError` on
        non-zero exit or timeout.
        """
        cmd = self._base_args() + extra_args
        log.debug("rsync command: %s", _redact_rsync_cmd(cmd))

        try:
            result = subprocess.run(
                cmd,
                env=self._build_env(),
                capture_output=capture,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise OSError(f"rsync timed out after {timeout}s") from exc
        except FileNotFoundError as exc:
            raise OSError("rsync binary not found") from exc

        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            raise OSError(
                f"rsync exited with code {result.returncode}: {stderr}"
            )

        return result.stdout or ""

    # --------------------------------------------------------------------- #
    #  FileBackend — listing / stat                                          #
    # --------------------------------------------------------------------- #

    def list_dir(self, path: str) -> list[FileItem]:
        """List directory contents via ``rsync --list-only``."""
        url = self._build_url(path)
        # Ensure trailing slash so rsync lists contents, not the dir itself
        if not url.endswith("/"):
            url += "/"

        output = self._run_rsync(["--list-only", url])
        items: list[FileItem] = []

        for line in output.splitlines():
            line = line.rstrip()
            if not line:
                continue

            m = _LIST_RE.match(line)
            if m:
                entry_name = m.group("name")
                # rsync may include a relative path prefix — take basename
                entry_name = posixpath.basename(entry_name.rstrip("/"))
                if entry_name in (".", ".."):
                    continue

                perm_str = m.group("perms")
                size_str = m.group("size").replace(",", "")
                date_str = m.group("date")
                time_str = m.group("time")

                is_dir = perm_str.startswith("d")
                is_link = perm_str.startswith("l")
                link_target = ""
                if is_link and " -> " in m.group("name"):
                    entry_name, _, link_target = m.group("name").rpartition(" -> ")
                    entry_name = posixpath.basename(entry_name.rstrip("/"))

                try:
                    size = int(size_str)
                except ValueError:
                    size = 0

                try:
                    modified = datetime.strptime(
                        f"{date_str} {time_str}", "%Y/%m/%d %H:%M:%S"
                    )
                except ValueError:
                    modified = datetime.fromtimestamp(0)

                permissions = _parse_permissions(perm_str)

                items.append(FileItem(
                    name=entry_name,
                    size=size,
                    modified=modified,
                    is_dir=is_dir,
                    is_link=is_link,
                    link_target=link_target,
                    permissions=permissions,
                ))
            else:
                # Might be a module listing line (when listing server root)
                mm = _MODULE_RE.match(line)
                if mm and not line.startswith(" "):
                    mod_name = mm.group("name")
                    if mod_name and not mod_name.startswith("#"):
                        items.append(FileItem(
                            name=mod_name,
                            is_dir=True,
                        ))

        log.debug("list_dir(%s): %d entries", path, len(items))
        return items

    def stat(self, path: str) -> FileItem:
        """Stat a single path by listing its parent directory."""
        name = posixpath.basename(path.rstrip("/"))
        if not name:
            # Root directory
            return FileItem(name="/", is_dir=True)

        parent = self.parent(path)
        entries = self.list_dir(parent)
        for entry in entries:
            if entry.name == name:
                return entry

        raise OSError(f"Not found: {path}")

    def is_dir(self, path: str) -> bool:
        try:
            item = self.stat(path)
            return item.is_dir
        except OSError:
            return False

    def exists(self, path: str) -> bool:
        try:
            self.stat(path)
            return True
        except OSError:
            return False

    # --------------------------------------------------------------------- #
    #  FileBackend — mutations                                               #
    # --------------------------------------------------------------------- #

    def mkdir(self, path: str) -> None:
        """Create a remote directory.

        Rsync cannot create directories directly on a daemon. We create a
        local temp directory and rsync it to the remote side.
        """
        tmpdir = tempfile.mkdtemp()
        try:
            url = self._build_url(path)
            if not url.endswith("/"):
                url += "/"
            self._run_rsync(["-r", tmpdir + "/", url])
            log.info("mkdir: %s", path)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def remove(self, path: str, recursive: bool = False) -> None:
        """Remove a remote file or directory.

        Uses ``--delete`` with an empty source directory to remove remote
        content, then removes the directory itself.
        """
        if self.is_dir(path):
            if not recursive:
                # Check if directory is empty
                contents = self.list_dir(path)
                if contents:
                    raise OSError(
                        f"Directory not empty: {path} "
                        f"(use recursive=True to force)"
                    )

            # Sync an empty directory with --delete to purge remote contents
            tmpdir = tempfile.mkdtemp()
            try:
                url = self._build_url(path)
                if not url.endswith("/"):
                    url += "/"
                self._run_rsync(
                    ["-r", "--delete", tmpdir + "/", url],
                    timeout=120,
                )
            finally:
                shutil.rmtree(tmpdir, ignore_errors=True)

            log.info("remove dir: %s (recursive=%s)", path, recursive)
        else:
            # For a single file, download nothing and delete the remote.
            # Use --remove-source-files approach via a filter trick:
            # rsync from an empty dir with --delete to the parent, including
            # only the target file.
            parent = self.parent(path)
            name = posixpath.basename(path)
            tmpdir = tempfile.mkdtemp()
            try:
                url = self._build_url(parent)
                if not url.endswith("/"):
                    url += "/"
                self._run_rsync(
                    [
                        "-r", "--delete",
                        "--include", name,
                        "--exclude", "*",
                        tmpdir + "/",
                        url,
                    ],
                    timeout=60,
                )
            finally:
                shutil.rmtree(tmpdir, ignore_errors=True)

            log.info("remove file: %s", path)

    def rename(self, src: str, dst: str) -> None:
        """Rename / move a remote path.

        Rsync does not support server-side rename. We download, re-upload
        under the new name, then delete the original.
        """
        tmpdir = tempfile.mkdtemp()
        try:
            local_path = os.path.join(tmpdir, "payload")
            src_url = self._build_url(src)
            dst_url = self._build_url(dst)

            flags = self._archive_flags()
            if self.is_dir(src):
                # Copy entire directory tree
                self._run_rsync(
                    [*flags, src_url + "/", local_path + "/"],
                    timeout=300,
                )
                self._run_rsync(
                    [*flags, local_path + "/", dst_url + "/"],
                    timeout=300,
                )
            else:
                self._run_rsync(
                    [*flags, src_url, local_path],
                    timeout=300,
                )
                self._run_rsync(
                    [*flags, local_path, dst_url],
                    timeout=300,
                )

            # Remove original
            self.remove(src, recursive=True)
            log.info("rename: %s -> %s", src, dst)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    # --------------------------------------------------------------------- #
    #  FileBackend — read / write                                            #
    # --------------------------------------------------------------------- #

    def open_read(self, path: str) -> IO[bytes]:
        """Download a remote file to a temp file and return a file handle."""
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.close()

        url = self._build_url(path)
        try:
            self._run_rsync([url, tmp.name], timeout=300)
        except OSError:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
            raise

        fh = open(tmp.name, "rb")
        # Wrap so the temp file is cleaned up when the handle is closed
        return _TempFileReader(fh, tmp.name)

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        """Return a writable handle; data is uploaded on close()."""
        writer = _RsyncWriter(self, path)
        if append:
            try:
                handle = self.open_read(path)
                data = handle.read()
                handle.close()
                writer.write(data)
            except OSError:
                pass
        return writer

    def _upload(self, local_path: str, remote_path: str) -> None:
        """Upload a local file to a remote path."""
        url = self._build_url(remote_path)
        self._run_rsync([local_path, url], timeout=300)
        log.debug("uploaded %s -> %s", local_path, remote_path)

    # --------------------------------------------------------------------- #
    #  FileBackend — path helpers                                            #
    # --------------------------------------------------------------------- #

    def normalize(self, path: str) -> str:
        return posixpath.normpath(path) or "/"

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        return posixpath.join(*parts)

    def parent(self, path: str) -> str:
        return posixpath.dirname(path.rstrip("/")) or "/"

    def home(self) -> str:
        return "/"

    # --------------------------------------------------------------------- #
    #  FileBackend — optional / unsupported operations                       #
    # --------------------------------------------------------------------- #

    def chmod(self, path: str, mode: int) -> None:
        raise OSError("rsync backend does not support remote chmod")

    def readlink(self, path: str) -> str:
        """Attempt to read a symlink target from the listing metadata."""
        item = self.stat(path)
        if item.is_link and item.link_target:
            return item.link_target
        raise OSError(f"Not a symlink or target unknown: {path}")

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError(
            f"{type(self).__name__} does not expose file version history"
        )

    def copy(self, src: str, dst: str) -> None:
        """Rsync has no same-module server-side copy."""
        raise OSError("Rsync has no server-side copy primitive")

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        """Rsync computes rolling + strong checksums internally but does
        not expose them as a standalone CLI output. No cheap native."""
        return ""

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        raise OSError("rsync backend does not support disk usage queries")

    # ------------------------------------------------------------------
    # Rsync-specific verbs (API_GAPS round 2)
    # ------------------------------------------------------------------

    def dry_run(self, src_path: str, dst_local_path: str, *,
                delete: bool = False,
                bandwidth_limit_kbps: int | None = None,
                timeout: float = 60.0) -> dict:
        """Run ``rsync --dry-run`` from this session's remote (or
        local, if ``src_path`` is local) path to ``dst_local_path``
        and return a parsed summary. NOTHING is transferred or
        modified — useful for "what would happen if I synced now?"
        triage.

        Returns ``{would_transfer: int, would_delete: int,
        would_create_dir: int, files: list[str], raw_stdout: str}``.
        ``files`` is the list of paths rsync says it would touch
        (capped at 1000 entries; raw stdout always preserved).

        ``delete`` adds ``--delete`` to also preview deletions
        (default OFF — destructive verb, off by default).
        ``bandwidth_limit_kbps`` maps to ``--bwlimit=KBPS``;
        meaningless for a dry-run but kept for symmetry with
        live ``rsync_transfer``.
        """
        import subprocess as _sp
        args = self._base_args() + [
            "--dry-run", "--itemize-changes", "--archive",
            "--out-format=%i %n",
        ]
        if delete:
            args.append("--delete")
        if bandwidth_limit_kbps:
            args.append(f"--bwlimit={int(bandwidth_limit_kbps)}")
        # Source: rsync URL into the session; destination: local path.
        args.append(self._build_url(src_path))
        args.append(dst_local_path)
        try:
            proc = _sp.run(args, capture_output=True, text=True,
                           timeout=float(timeout))
        except _sp.TimeoutExpired as exc:
            raise OSError(f"rsync dry-run timed out: {exc}") from exc
        if proc.returncode not in (0, 23, 24):  # 23/24 = partial transfer (acceptable in dry-run)
            raise OSError(
                f"rsync dry-run rc={proc.returncode}: {proc.stderr.strip()[:300]}"
            )
        return _parse_rsync_itemized(proc.stdout)

    def delete_preview(self, src_path: str, dst_local_path: str, *,
                       timeout: float = 60.0) -> list[str]:
        """Convenience: run a dry-run with ``--delete`` and return only
        the list of paths that WOULD be deleted on the destination.
        Empty list = nothing would be deleted."""
        result = self.dry_run(src_path, dst_local_path,
                              delete=True, timeout=timeout)
        # Itemized lines for deletes start with ``*deleting``.
        return [
            line.split(" ", 1)[1]
            for line in result["raw_stdout"].splitlines()
            if line.startswith("*deleting")
        ]


def _parse_rsync_itemized(out: str) -> dict:
    """Parse ``rsync -i --out-format='%i %n'`` lines into a summary
    dict. The ``%i`` itemize code is 11 characters; the first byte
    indicates the operation type (``<`` send, ``>`` receive, ``c``
    create, ``*`` deleting, ``.`` no-change)."""
    files: list[str] = []
    would_transfer = 0
    would_delete = 0
    would_create_dir = 0
    for line in out.splitlines():
        if not line or len(line) < 12:
            continue
        code = line[:11]
        path = line[12:].strip() if len(line) > 12 else ""
        if code.startswith("*deleting"):
            would_delete += 1
        elif code.startswith("cd"):
            would_create_dir += 1
        elif code[0] in ("<", ">"):
            would_transfer += 1
        if path and len(files) < 1000:
            files.append(path)
    return {
        "would_transfer": would_transfer,
        "would_delete": would_delete,
        "would_create_dir": would_create_dir,
        "files": files,
        "raw_stdout": out,
    }

    # --------------------------------------------------------------------- #
    #  Transfer engine — class method for rsync-based copies                 #
    # --------------------------------------------------------------------- #

    @classmethod
    def rsync_transfer(
        cls,
        source: str,
        dest: str,
        *,
        archive: bool = True,
        compress: bool = True,
        delete: bool = False,
        partial: bool = True,
        bwlimit: int | None = None,
        excludes: list[str] | None = None,
        extra_args: list[str] | None = None,
        ssh_port: int | None = None,
        ssh_key: str | None = None,
        password: str | None = None,
        progress_callback: Callable[[int, int, float, str], None] | None = None,
        timeout: int = 3600,
    ) -> None:
        """Run an rsync transfer between *source* and *dest*.

        This is a standalone class method that can be used independently
        of a ``RsyncSession`` instance — for example, to efficiently copy
        between two local paths or between a local path and an SSH host.

        Parameters
        ----------
        source:
            Source path (local or ``user@host:/path``).
        dest:
            Destination path.
        archive:
            Use ``-a`` (archive mode: recursive, preserve permissions,
            symlinks, times, group, owner, devices, specials).
        compress:
            Use ``-z`` (compress during transfer).
        delete:
            Use ``--delete`` (remove extraneous files on dest).
        partial:
            Use ``--partial`` (keep partially transferred files).
        bwlimit:
            Bandwidth limit in KB/s.
        excludes:
            List of ``--exclude`` patterns.
        extra_args:
            Additional raw rsync arguments.
        ssh_port:
            SSH port (only for remote transfers over SSH).
        ssh_key:
            Path to SSH private key.
        password:
            Rsync daemon password (set via ``RSYNC_PASSWORD``).
        progress_callback:
            Called with ``(bytes_transferred, percent, rate_str, eta_str)``
            for each progress update.
        timeout:
            Maximum wall-clock seconds for the transfer.
        """
        rsync_bin = shutil.which("rsync")
        if rsync_bin is None:
            raise OSError("rsync binary not found on PATH")

        cmd: list[str] = [rsync_bin]

        if archive:
            cmd.append("-a")
        if compress:
            cmd.append("-z")
        if delete:
            cmd.append("--delete")
        if partial:
            cmd.append("--partial")
        if bwlimit is not None:
            cmd += ["--bwlimit", str(bwlimit)]

        # SSH transport options
        if ssh_port or ssh_key:
            ssh_cmd = "ssh"
            if ssh_port:
                ssh_cmd += f" -p {ssh_port}"
            if ssh_key:
                ssh_cmd += f" -i {shlex.quote(ssh_key)}"
            ssh_cmd += " -o BatchMode=yes"
            cmd += ["-e", ssh_cmd]

        # Exclude patterns
        for pattern in (excludes or []):
            cmd += ["--exclude", pattern]

        # Progress output
        if progress_callback is not None:
            cmd.append("--progress")

        # Additional raw arguments
        if extra_args:
            cmd += extra_args

        cmd += [source, dest]

        # Same allow-list as the session-level _build_env: do not
        # ship AWS_*/GITHUB_*/*_TOKEN vars through to rsync (or on
        # through ssh via SendEnv). See docs/OPSEC.md #9.
        env = _build_allowlisted_env()
        if password:
            env["RSYNC_PASSWORD"] = password

        log.info("rsync_transfer: %s -> %s", source, dest)
        log.debug("rsync_transfer cmd: %s", _redact_rsync_cmd(cmd))

        if progress_callback is not None:
            cls._run_with_progress(cmd, env, timeout, progress_callback)
        else:
            try:
                result = subprocess.run(
                    cmd, env=env, capture_output=True, text=True,
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired as exc:
                raise OSError(
                    f"rsync transfer timed out after {timeout}s"
                ) from exc

            if result.returncode != 0:
                stderr = (result.stderr or "").strip()
                raise OSError(
                    f"rsync transfer failed (exit {result.returncode}): "
                    f"{stderr}"
                )

        log.info("rsync_transfer complete: %s -> %s", source, dest)

    @classmethod
    def _run_with_progress(
        cls,
        cmd: list[str],
        env: dict[str, str],
        timeout: int,
        callback: Callable[[int, int, float, str], None],
    ) -> None:
        """Run rsync with ``--progress`` and parse output in real time."""
        proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                line = line.rstrip()
                m = _PROGRESS_RE.match(line)
                if m:
                    transferred = int(m.group("bytes").replace(",", ""))
                    pct = int(m.group("pct"))
                    rate = m.group("rate")
                    eta = m.group("eta")
                    try:
                        callback(transferred, pct, rate, eta)
                    except Exception:
                        log.warning(
                            "progress_callback raised an exception",
                            exc_info=True,
                        )

            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise OSError(
                f"rsync transfer timed out after {timeout}s"
            )

        if proc.returncode != 0:
            stderr = (proc.stderr.read() if proc.stderr else "").strip()
            raise OSError(
                f"rsync transfer failed (exit {proc.returncode}): {stderr}"
            )


class _TempFileReader:
    """File-like wrapper that deletes the backing temp file on close."""

    def __init__(self, fh: IO[bytes], tmp_path: str):
        self._fh = fh
        self._tmp_path = tmp_path

    def read(self, n: int = -1) -> bytes:
        return self._fh.read(n)

    def seek(self, pos: int, whence: int = 0) -> int:
        return self._fh.seek(pos, whence)

    def tell(self) -> int:
        return self._fh.tell()

    def close(self) -> None:
        self._fh.close()
        try:
            os.unlink(self._tmp_path)
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    # Forward common attributes so duck-typing works
    @property
    def name(self) -> str:
        return self._tmp_path

    @property
    def closed(self) -> bool:
        return self._fh.closed
