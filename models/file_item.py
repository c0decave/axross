from __future__ import annotations

import stat as stat_module
from dataclasses import dataclass, field
from datetime import datetime


def _local_wall_clock(value):
    """An aware datetime as naive local wall clock time; anything else as is."""
    if getattr(value, "tzinfo", None) is None:
        return value
    try:
        return value.astimezone().replace(tzinfo=None)
    except (OverflowError, OSError, ValueError):
        # datetime.min / max placeholders cannot be shifted; their
        # wall clock reading is as good as any.
        return value.replace(tzinfo=None)


def local_time(seconds, default=None):
    """``datetime.fromtimestamp(seconds)`` - or *default* (the epoch when
    None) for a time no datetime holds: a file stamped in the year 33658
    (mtime 1e12) or before year 1 made fromtimestamp raise ValueError, and
    the whole folder could not be listed, compared or copied."""
    try:
        return datetime.fromtimestamp(seconds)
    except (ValueError, OverflowError, OSError, TypeError):
        return datetime.fromtimestamp(0) if default is None else default


def _permission_string(mode: int) -> str:
    bits = (
        stat_module.S_IRUSR, stat_module.S_IWUSR, stat_module.S_IXUSR,
        stat_module.S_IRGRP, stat_module.S_IWGRP, stat_module.S_IXGRP,
        stat_module.S_IROTH, stat_module.S_IWOTH, stat_module.S_IXOTH,
    )
    return "".join(c if mode & bit else "-" for c, bit in zip("rwxrwxrwx", bits))


#: ``rwxrwxrwx`` of every mode's low nine bits: the Permissions column
#: draws one per row, and building it bit by bit cost 3 us each.
_PERMISSION_STRINGS = tuple(_permission_string(mode) for mode in range(0o1000))

#: The rows a file pane puts in front of a listing (FilePaneWidget._fetch_listing).
NAV_NAMES = frozenset({".", ".."})


@dataclass(frozen=True, slots=True)
class FileItem:
    """Represents a single file or directory entry, local or remote.

    Timestamp contract (``modified``, ``accessed``, ``created``): a naive
    datetime is LOCAL wall clock time — what ``datetime.fromtimestamp``
    returns and what LocalFS, the pane's date column and ``.timestamp()``
    assume. A backend whose protocol reports UTC must hand over an AWARE
    datetime (``tzinfo=timezone.utc``), never a naive UTC one; aware
    values are converted to local wall clock time here, so every item
    from every backend compares and sorts on one clock.
    """

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
    # The platform or protocol marks the entry hidden without a leading
    # dot: FILE_ATTRIBUTE_HIDDEN (Windows, SMB, WinRM) or UF_HIDDEN
    # (macOS / BSD chflags). Set only from data the listing already
    # carries; a backend that cannot know leaves it False and the dot
    # rule of :attr:`is_hidden` decides alone.
    attr_hidden: bool = False
    # The entry is there (the directory listing names it) but its
    # attributes could not be read: a mount point the user may not stat
    # (a FUSE mount without allow_other, a root-only NFS export), a name
    # that vanished in between. The listing still shows it - an entry
    # left out of a listing is one a recursive copy, move or delete never
    # sees - and this holds why its size, time and mode are unknown.
    stat_error: str = ""

    # Slots: ~140 instead of ~340 bytes per entry (no __dict__) - a
    # listing of 100,000 entries holds 20 MB less.

    def __post_init__(self) -> None:
        # One test for the common case (every time naive or None) before
        # the per-field work: built ~100,000 times per big listing.
        if (getattr(self.modified, "tzinfo", None) is None
                and getattr(self.accessed, "tzinfo", None) is None
                and getattr(self.created, "tzinfo", None) is None):
            return
        for name in ("modified", "accessed", "created"):
            value = getattr(self, name)
            if getattr(value, "tzinfo", None) is not None:
                object.__setattr__(self, name, _local_wall_clock(value))

    @property
    def is_nav(self) -> bool:
        """The pane's own rows "." (this folder) and ".." (the parent):
        navigation and drop targets, never an entry to select, copy, rename
        or delete."""
        return self.name in NAV_NAMES

    @property
    def is_hidden(self) -> bool:
        """Hidden from a listing unless the user asks for hidden files: a
        dot name (the Unix convention, on every backend) or the backend's
        hidden flag (:attr:`attr_hidden`)."""
        return self.attr_hidden or self.name.startswith(".")

    @property
    def permissions_str(self) -> str:
        """Return rwxrwxrwx style permission string."""
        return _PERMISSION_STRINGS[self.permissions & 0o777]

    @property
    def type_char(self) -> str:
        if self.is_link:
            return "l"
        if self.is_dir:
            return "d"
        return "-"

    @property
    def mode_str(self) -> str:
        if self.stat_error:
            return f"{self.type_char}?????????"
        return f"{self.type_char}{self.permissions_str}"

    @property
    def size_human(self) -> str:
        if self.is_dir:
            return ""
        if self.stat_error:
            return "?"
        from core.i18n import format_decimal

        size: float = self.size
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if abs(size) < 1024:
                if unit == "B":
                    return f"{size} {unit}"
                # The language's decimal mark: "1,1 MB" in German.
                return f"{format_decimal(size)} {unit}"
            size /= 1024
        return f"{format_decimal(size)} PB"
