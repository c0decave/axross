"""NFS backend implementing the FileBackend protocol via mount wrapper.

Uses system mount.nfs to mount the NFS export, then operates on the
mounted filesystem like local files.  No Python packages required —
just the system nfs-utils (mount.nfs).

Requires: nfs-utils (system package)
"""
from __future__ import annotations

import io
import logging
import os
import shutil
import stat as stat_module
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import IO

from models.file_item import FileItem

log = logging.getLogger(__name__)


def _nfs_available() -> bool:
    """Check if mount.nfs is available on the system."""
    return shutil.which("mount.nfs") is not None or shutil.which("mount") is not None


class NfsSession:
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
    ):
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
        self._connect()

    def _run(self, cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
        """Run a command, prepending sudo if not root."""
        if os.geteuid() != 0:
            cmd = ["sudo", "-n"] + cmd
        log.debug("Running: %s", " ".join(cmd))
        return subprocess.run(
            cmd, capture_output=True, text=True, check=check, timeout=30,
        )

    def _connect(self) -> None:
        """Mount the NFS export."""
        source = f"{self._host}:{self._export}"
        # NFSv4 does not use a separate MOUNT protocol, so passing
        # mountport= only makes sense for v3. Including it on v4 causes
        # mount.nfs to reject the request ("Protocol not supported").
        if self._version >= 4:
            opts = f"vers={self._version},port={self._port},nolock,tcp"
        else:
            opts = (
                f"vers={self._version},port={self._port},"
                f"mountport={self._port},nolock,tcp"
            )

        try:
            self._run(["mount", "-t", "nfs", "-o", opts, source, self._mount_point])
            self._mounted = True
            log.info("NFS mounted: %s -> %s", source, self._mount_point)
        except subprocess.CalledProcessError as e:
            stderr = e.stderr.strip() if e.stderr else str(e)
            raise OSError(f"Failed to mount NFS {source}: {stderr}") from e

    def _full_path(self, path: str) -> str:
        """Convert virtual path to real mounted path."""
        clean = path.lstrip("/")
        full = os.path.join(self._mount_point, clean)
        normalized = os.path.abspath(full)
        mount_root = os.path.abspath(self._mount_point)
        if os.path.commonpath([mount_root, normalized]) != mount_root:
            raise PermissionError(f"Path traversal detected: {path}")
        return normalized

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

    def list_dir(self, path: str) -> list[FileItem]:
        full = self._full_path(path)
        items: list[FileItem] = []
        try:
            for entry_name in os.listdir(full):
                entry_path = os.path.join(full, entry_name)
                try:
                    st = os.stat(entry_path, follow_symlinks=False)
                    atime = (
                        datetime.fromtimestamp(st.st_atime)
                        if getattr(st, "st_atime", 0) else None
                    )
                    birth = getattr(st, "st_birthtime", 0)
                    ctime = datetime.fromtimestamp(birth) if birth else None
                    items.append(FileItem(
                        name=entry_name,
                        size=st.st_size,
                        modified=datetime.fromtimestamp(st.st_mtime),
                        is_dir=stat_module.S_ISDIR(st.st_mode),
                        permissions=st.st_mode & 0o7777,
                        accessed=atime,
                        created=ctime,
                    ))
                except OSError as e:
                    log.debug("Cannot stat %s: %s", entry_path, e)
        except OSError as e:
            raise OSError(f"Cannot list {path}: {e}") from e
        return sorted(items, key=lambda i: (not i.is_dir, i.name.lower()))

    def stat(self, path: str) -> FileItem:
        full = self._full_path(path)
        try:
            st = os.stat(full, follow_symlinks=False)
            name = os.path.basename(path.rstrip("/")) or "/"
            accessed = (
                datetime.fromtimestamp(st.st_atime) if getattr(st, "st_atime", 0) else None
            )
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
        return os.path.isdir(self._full_path(path))

    def exists(self, path: str) -> bool:
        return os.path.lexists(self._full_path(path))

    def mkdir(self, path: str) -> None:
        os.makedirs(self._full_path(path), exist_ok=True)

    def remove(self, path: str, recursive: bool = False) -> None:
        full = self._full_path(path)
        if os.path.isdir(full):
            if recursive:
                shutil.rmtree(full)
            else:
                os.rmdir(full)
        else:
            os.remove(full)

    def rename(self, old_path: str, new_path: str) -> None:
        os.rename(self._full_path(old_path), self._full_path(new_path))

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
        return os.readlink(self._full_path(path))

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError(
            f"{type(self).__name__} does not expose file version history"
        )

    def copy(self, src: str, dst: str) -> None:
        """Server-side copy over the mounted FS (kernel-buffered)."""
        shutil.copy2(self._full_path(src), self._full_path(dst))

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
