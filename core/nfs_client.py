"""NFS backend implementing the FileBackend protocol via mount wrapper.

Uses system mount.nfs to mount the NFS export, then operates on the
mounted filesystem like local files.  No Python packages required —
just the system nfs-utils (mount.nfs).

Requires: nfs-utils (system package)
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import stat as stat_module
import subprocess
import tempfile
from datetime import datetime
from typing import IO

from core import posix_compat
from core.backend import SessionLifecycle
from core.path_policy import confined_path
from core.subprocess_env import clean_child_env
from models.file_item import FileItem
from security.protocol_line_split import split_lf_only_stream

log = logging.getLogger(__name__)


#: Mount options that keep a server's files from acting on this machine:
#: no set-uid/set-gid, no device nodes, nothing executable from the export.
_SAFE_MOUNT_OPTIONS = "nosuid,nodev,noexec"

# A host name, IPv4 or bracketed IPv6 address - nothing mount(8) could
# read as an option or a second argument.
_HOST_RE = re.compile(r"[A-Za-z0-9_.:\[\]%-]+")


def _validate_mount_source(host: str, export: str) -> None:
    if not host or host.startswith("-") or not _HOST_RE.fullmatch(host):
        raise ValueError(f"NFS host {host!r} is not a host name or address")
    if not export.startswith("/") or any(ord(c) < 32 or c == "\x7f" for c in export):
        raise ValueError(f"NFS export {export!r} must be an absolute path without control characters")


def _nfs_available() -> bool:
    """Check if mount.nfs is available on the system."""
    return shutil.which("mount.nfs") is not None or shutil.which("mount") is not None


class NfsSession(SessionLifecycle):
    """NFS backend using system mount.

    Mounts the remote NFS export to a local temp directory and provides
    file operations on the mounted filesystem.
    """

    def __init__(
        self,
        host: str,
        export_path: str,
        port: int = 2049,
        version: int = 3,
        mount_point: str = "",
        proxy_type: str = "none",
        proxy_host: str = "",
        proxy_port: int = 0,
        proxy_username: str = "",
        proxy_password: str = "",
    ):
        from core.proxy import LocalTunnel, proxy_config_from_kwargs, refuse_unsupported_proxy

        _validate_mount_source(host, export_path)
        cfg = proxy_config_from_kwargs(
            {
                "proxy_type": proxy_type,
                "proxy_host": proxy_host,
                "proxy_port": proxy_port,
                "proxy_username": proxy_username,
                "proxy_password": proxy_password,
            }
        )
        self._tunnel = None
        self._mount_host, self._mount_port = host, port
        if cfg is not None:
            if version < 4:
                refuse_unsupported_proxy(
                    "NFSv3",
                    proxy_type,
                    proxy_host,
                    "NFSv3 negotiates mountd / portmap / statd on several ports, which one "
                    "proxied connection cannot carry. Set the profile's NFS version to 4.",
                )
            # NFSv4 is a single TCP port: the kernel mounts the loopback end of
            # a tunnel and every byte goes through the proxy. The kernel's own
            # socket belongs to root, hence allow_root_peers.
            self._tunnel = LocalTunnel(cfg, host, port, allow_root_peers=True).start()
            self._mount_host, self._mount_port = self._tunnel.host, self._tunnel.port
        self._host = host
        self._export = export_path.rstrip("/") or "/"
        self._port = port
        self._version = version
        self._own_mount = False

        if mount_point:
            self._mount_point = mount_point
        else:
            self._mount_point = tempfile.mkdtemp(prefix="axross-nfs-")
            self._own_mount = True

        self._mounted = False
        try:
            self._connect()
        except BaseException:
            self._close_tunnel()
            raise

    def _run(self, cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
        """Run a command, prepending sudo if not root."""
        if posix_compat.effective_uid() != 0:
            cmd = ["sudo", "-n"] + cmd
        log.debug("Running: %s", " ".join(cmd))
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=check,
            timeout=30,
            env=clean_child_env(),
        )

    def _connect(self) -> None:
        """Mount the NFS export."""
        # With a proxy the kernel dials the loopback tunnel, not the server.
        source = f"{self._mount_host}:{self._export}"
        # NFSv4 does not use a separate MOUNT protocol, so passing
        # mountport= only makes sense for v3. Including it on v4 causes
        # mount.nfs to reject the request ("Protocol not supported").
        port = self._mount_port
        if self._version >= 4:
            opts = f"vers={self._version},port={port},nolock,tcp"
        else:
            opts = f"vers={self._version},port={port},mountport={port},nolock,tcp"
        # Mounted as root: without these a set-uid binary on the export is
        # a local root shell for anyone on this machine.
        opts = f"{opts},{_SAFE_MOUNT_OPTIONS}"

        try:
            self._run(["mount", "-t", "nfs", "-o", opts, "--", source, self._mount_point])
            self._mounted = True
            log.info("NFS mounted: %s -> %s", source, self._mount_point)
        except subprocess.CalledProcessError as e:
            stderr = e.stderr.strip() if e.stderr else str(e)
            raise OSError(f"Failed to mount NFS {source}: {stderr}") from e

    def local_path(self, path: str) -> str:
        """The mounted path on this machine (see core.storage_identity)."""
        return self._full_path(path)

    def _full_path(self, path: str, *, follow: bool = True) -> str:
        """Convert virtual path to real mounted path, confined to the mount
        even through server-planted symlinks (see confined_path)."""
        return confined_path(self._mount_point, path, follow=follow)

    @property
    def name(self) -> str:
        return f"{self._host}:{self._export} (NFS)"

    @property
    def connected(self) -> bool:
        if not self._mounted:
            return False
        try:
            os.listdir(self._mount_point)
            return True
        except OSError:
            return False

    def close(self) -> None:
        self.disconnect()

    def disconnect(self) -> None:
        if self._mounted:
            try:
                self._run(["umount", self._mount_point], check=False)
                self._mounted = False
                log.info("NFS unmounted: %s", self._mount_point)
            except Exception as e:
                log.error("Failed to unmount NFS: %s", e)
        if self._own_mount and os.path.isdir(self._mount_point):
            try:
                os.rmdir(self._mount_point)
            except OSError:
                pass
        self._close_tunnel()

    def _close_tunnel(self) -> None:
        tunnel = getattr(self, "_tunnel", None)
        if tunnel is not None:
            tunnel.close()
            self._tunnel = None

    def list_dir(self, path: str) -> list[FileItem]:
        full = self._full_path(path)
        items: list[FileItem] = []
        try:
            for entry_name in os.listdir(full):
                entry_path = os.path.join(full, entry_name)
                try:
                    st = os.stat(entry_path, follow_symlinks=False)
                    atime = (
                        datetime.fromtimestamp(st.st_atime) if getattr(st, "st_atime", 0) else None
                    )
                    birth = getattr(st, "st_birthtime", 0)
                    ctime = datetime.fromtimestamp(birth) if birth else None
                    items.append(
                        FileItem(
                            name=entry_name,
                            size=st.st_size,
                            modified=datetime.fromtimestamp(st.st_mtime),
                            is_dir=stat_module.S_ISDIR(st.st_mode),
                            permissions=st.st_mode & 0o7777,
                            accessed=atime,
                            created=ctime,
                        )
                    )
                except OSError as e:
                    log.debug("Cannot stat %s: %s", entry_path, e)
        except OSError as e:
            raise OSError(f"Cannot list {path}: {e}") from e
        return sorted(items, key=lambda i: (not i.is_dir, i.name.lower()))

    def stat(self, path: str) -> FileItem:
        full = self._full_path(path, follow=False)
        try:
            st = os.stat(full, follow_symlinks=False)
            name = os.path.basename(path.rstrip("/")) or "/"
            accessed = datetime.fromtimestamp(st.st_atime) if getattr(st, "st_atime", 0) else None
            birth = getattr(st, "st_birthtime", 0)
            created = datetime.fromtimestamp(birth) if birth else None
            return FileItem(
                name=name,
                size=st.st_size,
                modified=datetime.fromtimestamp(st.st_mtime),
                is_dir=stat_module.S_ISDIR(st.st_mode),
                permissions=st.st_mode & 0o7777,
                accessed=accessed,
                created=created,
            )
        except OSError as e:
            raise OSError(f"Cannot stat {path}: {e}") from e

    def is_dir(self, path: str) -> bool:
        try:
            return os.path.isdir(self._full_path(path))
        except PermissionError:
            return False

    def exists(self, path: str) -> bool:
        return os.path.lexists(self._full_path(path, follow=False))

    def mkdir(self, path: str) -> None:
        os.makedirs(self._full_path(path), exist_ok=True)

    def remove(self, path: str, recursive: bool = False) -> None:
        full = self._full_path(path, follow=False)
        if os.path.islink(full):
            os.remove(full)  # the link, never what it points at
        elif os.path.isdir(full):
            if recursive:
                shutil.rmtree(full)
            else:
                os.rmdir(full)
        else:
            os.remove(full)

    def rename(self, old_path: str, new_path: str) -> None:
        os.rename(self._full_path(old_path, follow=False), self._full_path(new_path, follow=False))

    def open_read(self, path: str) -> IO[bytes]:
        return open(self._full_path(path), "rb")

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        mode = "ab" if append else "wb"
        parent = os.path.dirname(self._full_path(path))
        os.makedirs(parent, exist_ok=True)
        return open(self._full_path(path), mode)

    def normalize(self, path: str) -> str:
        return os.path.normpath("/" + path)

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        if not parts:
            return "/"
        result = parts[0]
        for p in parts[1:]:
            if p.startswith("/"):
                result = p
            else:
                result = result.rstrip("/") + "/" + p
        return result

    def parent(self, path: str) -> str:
        p = path.rstrip("/")
        if "/" not in p:
            return "/"
        return p.rsplit("/", 1)[0] or "/"

    def home(self) -> str:
        return "/"

    def chmod(self, path: str, mode: int) -> None:
        os.chmod(self._full_path(path), mode)

    def readlink(self, path: str) -> str:
        return os.readlink(self._full_path(path, follow=False))

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError(f"{type(self).__name__} does not expose file version history")

    def copy(self, src: str, dst: str) -> None:
        """Server-side copy over the mounted FS (kernel-buffered)."""
        shutil.copy2(self._full_path(src), self._full_path(dst))

    # ------------------------------------------------------------------
    # NFS-specific verbs (API_GAPS round 2)
    # ------------------------------------------------------------------

    @staticmethod
    def exports_list(host: str, *, timeout: float = 5.0) -> list[dict]:
        """Query the remote NFS server for its export list via
        ``showmount -e``. Returns one dict per export
        ``[{"path": "/srv/share", "clients": ["10.0.0.0/24", "*"]}, ...]``.

        Static method so a script can browse before mounting::

            for ex in axross.NfsSession.exports_list("10.0.0.5"):
                print(ex["path"], ex["clients"])

        Requires ``showmount`` on PATH (Debian/Ubuntu: ``apt install
        nfs-common``; Arch: ``pacman -S nfs-utils``). Raises ``OSError``
        when the binary is missing OR when the server doesn't expose
        mountd (NFSv4-only servers don't — they advertise exports
        through the pseudo-root ``/`` instead).
        """
        # Validate input BEFORE the binary lookup so a CR/LF check
        # fires even when showmount isn't installed (defends against
        # ``except OSError`` callers that would otherwise mask the
        # smuggling guard with the not-installed message).
        if "\r" in host or "\n" in host or " " in host:
            raise ValueError("exports_list host must not contain CR/LF/space")
        showmount = shutil.which("showmount")
        if not showmount:
            raise OSError(
                "exports_list requires the system 'showmount' binary "
                "(install nfs-common / nfs-utils)"
            )
        proc = subprocess.run(
            [showmount, "-e", "--no-headers", host],
            capture_output=True,
            text=True,
            timeout=float(timeout),
            env=clean_child_env(),
        )
        if proc.returncode != 0:
            stderr = proc.stderr.strip() or "showmount returned non-zero"
            raise OSError(f"showmount -e {host}: {stderr}")
        out: list[dict] = []
        for line in split_lf_only_stream(proc.stdout):
            line = line.strip()
            if not line:
                continue
            # ``/srv/share <clients-spec>`` — split on first whitespace.
            parts = line.split(None, 1)
            path = parts[0]
            clients = parts[1].split(",") if len(parts) > 1 else ["*"]
            out.append({"path": path, "clients": [c.strip() for c in clients]})
        return out

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        """Stream-hash via the local mount. No cheap native hash, but
        reading from the mounted filesystem is kernel-buffered so cost
        is comparable to a local sha256sum."""
        import hashlib

        try:
            h = hashlib.new(algorithm)
        except ValueError as exc:
            raise OSError(f"Unsupported algorithm: {algorithm}") from exc
        with open(self._full_path(path), "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return f"{algorithm}:{h.hexdigest()}"

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        usage = shutil.disk_usage(self._full_path(path))
        return (usage.total, usage.used, usage.free)
