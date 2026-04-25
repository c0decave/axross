from __future__ import annotations

import stat as stat_module
from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class FileItem:
    """Represents a single file or directory entry, local or remote."""

    name: str
    size: int = 0
    modified: datetime = field(default_factory=lambda: datetime.fromtimestamp(0))
    permissions: int = 0
    is_dir: bool = False
    is_link: bool = False
    link_target: str = ""
    owner: str = ""
    group: str = ""
    # Optional last-access time. ``None`` when the backend does not
    # report an atime (most cloud protocols — S3, Dropbox, Google
    # Drive, Azure Blob, OneDrive — only have creation/modification).
    # Populated by POSIX-family backends (LocalFS, SFTP, NFS, iSCSI,
    # SCP, Telnet) and any backend that sets BackendCapabilities.has_atime.
    accessed: datetime | None = None
    # Optional creation time (ctime-as-birth on platforms that have it;
    # creationTime on cloud backends that report one). ``None`` when
    # not available. Distinct from ``modified`` because many cloud
    # backends only update mtime on content change but keep ctime
    # pinned to upload time.
    created: datetime | None = None

    @property
    def permissions_str(self) -> str:
        """Return rwxrwxrwx style permission string."""
        mode = self.permissions
        parts = []
        for who in (stat_module.S_IRUSR, stat_module.S_IWUSR, stat_module.S_IXUSR,
                     stat_module.S_IRGRP, stat_module.S_IWGRP, stat_module.S_IXGRP,
                     stat_module.S_IROTH, stat_module.S_IWOTH, stat_module.S_IXOTH):
            parts.append(bool(mode & who))
        chars = "rwxrwxrwx"
        return "".join(c if p else "-" for c, p in zip(chars, parts))

    @property
    def type_char(self) -> str:
        if self.is_link:
            return "l"
        if self.is_dir:
            return "d"
        return "-"

    @property
    def mode_str(self) -> str:
        return f"{self.type_char}{self.permissions_str}"

    @property
    def size_human(self) -> str:
        if self.is_dir:
            return ""
        size = self.size
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if abs(size) < 1024:
                if unit == "B":
                    return f"{size} {unit}"
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"
