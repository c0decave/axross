from __future__ import annotations

import grp
import logging
import os
import pwd
import shutil
import stat as stat_module
from datetime import datetime
from pathlib import Path
from typing import IO

from models.file_item import FileItem

log = logging.getLogger(__name__)


class LocalFS:
    """Local filesystem backend implementing the FileBackend protocol."""

    # POSIX filesystems support both link flavours; the UI uses these
    # flags to decide whether to show the "New Symlink…" / "New
    # Hardlink…" context-menu entries.
    supports_symlinks = True
    supports_hardlinks = True

    @property
    def name(self) -> str:
        return "Local"

    def list_dir(self, path: str) -> list[FileItem]:
        items: list[FileItem] = []
        try:
            with os.scandir(path) as it:
                for entry in it:
                    try:
                        items.append(self._entry_to_item(entry))
                    except OSError as e:
                        log.warning("Cannot stat %s: %s", entry.path, e)
        except OSError as e:
            log.error("Cannot list %s: %s", path, e)
            raise
        return items

    def stat(self, path: str) -> FileItem:
        st = os.lstat(path)
        name = os.path.basename(path) or path
        return self._stat_to_item(name, st)

    def is_dir(self, path: str) -> bool:
        try:
            return stat_module.S_ISDIR(os.lstat(path).st_mode)
        except OSError:
            return False

    def exists(self, path: str) -> bool:
        return os.path.lexists(path)

    def mkdir(self, path: str) -> None:
        os.makedirs(path, exist_ok=True)

    def remove(self, path: str, recursive: bool = False) -> None:
        st = os.lstat(path)
        if stat_module.S_ISLNK(st.st_mode):
            os.remove(path)
        elif stat_module.S_ISDIR(st.st_mode):
            if recursive:
                shutil.rmtree(path)
            else:
                os.rmdir(path)
        else:
            os.remove(path)

    def rename(self, src: str, dst: str) -> None:
        os.rename(src, dst)

    def open_read(self, path: str) -> IO[bytes]:
        return open(path, "rb")

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        return open(path, "ab" if append else "wb")

    def normalize(self, path: str) -> str:
        return os.path.normpath(os.path.abspath(path))

    def separator(self) -> str:
        return os.sep

    def join(self, *parts: str) -> str:
        return os.path.join(*parts)

    def parent(self, path: str) -> str:
        return str(Path(path).parent)

    def home(self) -> str:
        return str(Path.home())

    def chmod(self, path: str, mode: int) -> None:
        os.chmod(path, mode)

    def readlink(self, path: str) -> str:
        return os.readlink(path)

    def symlink(self, target: str, link_path: str) -> None:
        """Create a symlink at *link_path* pointing to *target*.

        ``target`` may be absolute or relative. We do NOT pre-validate
        that *target* exists — dangling symlinks are a legitimate
        POSIX pattern (``ln -s /future/path foo`` before creating
        the target is common). The OS will raise :class:`OSError` on
        invalid paths or when *link_path* already exists."""
        os.symlink(target, link_path)

    def hardlink(self, target: str, link_path: str) -> None:
        """Create a hardlink at *link_path* pointing at the same inode
        as *target*. Both paths must live on the same filesystem —
        :class:`OSError` (EXDEV) when they don't, which the UI
        surfaces as a clear "cross-device link" message."""
        os.link(target, link_path)

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        usage = shutil.disk_usage(path)
        return (usage.total, usage.used, usage.free)

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError(
            f"{type(self).__name__} does not expose file version history"
        )

    def copy(self, src: str, dst: str) -> None:
        """Server-side copy via shutil.copy2 (preserves timestamps)."""
        shutil.copy2(src, dst)

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        """Stream-hash the file. No native shortcut on a plain mount."""
        import hashlib
        try:
            h = hashlib.new(algorithm)
        except ValueError as exc:
            raise OSError(f"Unsupported checksum algorithm: {algorithm}") from exc
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return f"{algorithm}:{h.hexdigest()}"

    def _entry_to_item(self, entry: os.DirEntry) -> FileItem:
        st = entry.stat(follow_symlinks=False)
        return self._stat_to_item(entry.name, st, full_path=entry.path)

    def _stat_to_item(self, name: str, st: os.stat_result, full_path: str = "") -> FileItem:
        is_link = stat_module.S_ISLNK(st.st_mode)
        is_dir = stat_module.S_ISDIR(st.st_mode)
        link_target = ""
        if is_link and full_path:
            try:
                link_target = os.readlink(full_path)
            except OSError:
                pass

        try:
            owner = pwd.getpwuid(st.st_uid).pw_name
        except (KeyError, AttributeError):
            owner = str(getattr(st, "st_uid", ""))

        try:
            group = grp.getgrgid(st.st_gid).gr_name
        except (KeyError, AttributeError):
            group = str(getattr(st, "st_gid", ""))

        accessed = (
            datetime.fromtimestamp(st.st_atime) if getattr(st, "st_atime", 0) else None
        )
        created = None
        # On Linux st_ctime is inode-change-time; on macOS/Windows it
        # is birthtime. Prefer explicit birthtime when the platform
        # exposes it.
        birth = getattr(st, "st_birthtime", 0)
        if birth:
            created = datetime.fromtimestamp(birth)
        return FileItem(
            name=name,
            size=st.st_size,
            modified=datetime.fromtimestamp(st.st_mtime),
            permissions=st.st_mode & 0o7777,
            is_dir=is_dir,
            is_link=is_link,
            link_target=link_target,
            owner=owner,
            group=group,
            accessed=accessed,
            created=created,
        )
