from __future__ import annotations

from typing import IO, Protocol, runtime_checkable

from models.file_item import FileItem


@runtime_checkable
class FileBackend(Protocol):
    """Interface for file system backends (local and remote)."""

    @property
    def name(self) -> str:
        """Human-readable name for this backend (e.g. 'Local' or 'user@host')."""
        ...

    def list_dir(self, path: str) -> list[FileItem]:
        """List directory contents. Raises OSError on failure."""
        ...

    def stat(self, path: str) -> FileItem:
        """Get file/directory info. Raises OSError on failure."""
        ...

    def is_dir(self, path: str) -> bool:
        """Check if path is a directory."""
        ...

    def exists(self, path: str) -> bool:
        """Check if path exists."""
        ...

    def mkdir(self, path: str) -> None:
        """Create a directory. Raises OSError on failure."""
        ...

    def remove(self, path: str, recursive: bool = False) -> None:
        """Remove a file or directory. If recursive=True, remove directory tree."""
        ...

    def rename(self, src: str, dst: str) -> None:
        """Rename/move a file or directory."""
        ...

    def open_read(self, path: str) -> IO[bytes]:
        """Open a file for reading. Caller must close the returned handle."""
        ...

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        """Open a file for writing. Caller must close the returned handle."""
        ...

    def normalize(self, path: str) -> str:
        """Normalize a path (resolve .., ., etc.)."""
        ...

    def separator(self) -> str:
        """Return the path separator for this backend."""
        ...

    def join(self, *parts: str) -> str:
        """Join path components using this backend's separator."""
        ...

    def parent(self, path: str) -> str:
        """Return the parent directory of the given path."""
        ...

    def home(self) -> str:
        """Return the home/default directory."""
        ...

    def chmod(self, path: str, mode: int) -> None:
        """Change file permissions. mode is octal (e.g. 0o755)."""
        ...

    def readlink(self, path: str) -> str:
        """Read symlink target. Raises OSError if not a symlink."""
        ...

    # Optional creation primitives. These are NOT universally
    # implemented — S3 / IMAP / most cloud backends have no symlink
    # or hardlink concept. Backends that do support them expose the
    # method AND set the matching ``supports_*`` class attribute so
    # the UI can hide the action cleanly. Callers probe with
    # ``getattr(backend, 'supports_symlinks', False)`` rather than
    # catching an AttributeError.
    supports_symlinks: bool = False
    supports_hardlinks: bool = False

    def symlink(self, target: str, link_path: str) -> None:
        """Create a symbolic link at *link_path* pointing to *target*.

        Raises :class:`OSError` on backends that don't model symlinks.
        LocalFS + SFTP-over-SSH override this.
        """
        ...

    def hardlink(self, target: str, link_path: str) -> None:
        """Create a hard link at *link_path* to the same inode as
        *target*. Raises :class:`OSError` on backends that don't
        model hardlinks. LocalFS overrides this.
        """
        ...

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        """Return (total, used, free) bytes for the filesystem containing path.
        Returns (0, 0, 0) if not supported."""
        ...

    def list_versions(self, path: str) -> list:
        """Return historical versions of *path*, newest first.

        Backends with native versioning (S3, Azure Blob, Dropbox,
        GDrive, OneDrive, WebDAV DeltaV) populate this. Backends
        without versioning return ``[]``. Each element is a
        :class:`models.file_version.FileVersion`.
        """
        ...

    def open_version_read(self, path: str, version_id: str):
        """Open a historical version of *path* for streaming read.

        Returns a binary file-like handle. The handle MUST be closed
        by the caller.

        Raises :class:`OSError` when the backend has no versioning
        or the version_id no longer exists.
        """
        ...

    def copy(self, src: str, dst: str) -> None:
        """Server-side copy of *src* to *dst* within this backend.

        Backends with native copy (S3 CopyObject, WebDAV COPY, Azure
        Copy Blob, shell ``cp``) MUST implement this without streaming
        bytes through the client — that is the whole point of the
        primitive. Backends without a native copy raise
        :class:`OSError` and callers should fall back to
        :func:`core.server_ops.copy_via_stream` which wires
        open_read + open_write.

        Raises :class:`OSError` when the operation is not supported
        or the underlying protocol fails. ``rename()`` remains the
        move primitive.
        """
        ...

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        """Return a hex-encoded checksum of the file's content.

        Implementations SHOULD use a native server-side checksum when
        available (S3 ETag, WebDAV DAV:getetag, Azure Content-MD5,
        Dropbox content_hash, Google Drive md5Checksum, ssh shell
        sha256sum) instead of streaming the file. The *algorithm*
        argument is a hint: backends MAY return whatever native
        algorithm they provide and mark it in the return format
        (e.g. "md5:abc..."). Callers that need a specific algorithm
        must compare the prefix.

        Returns ``""`` when the backend has no cheap checksum and
        computing one would require a full read — transfer_worker
        handles full-read checksums itself in that case.

        Raises :class:`OSError` on the underlying protocol failure.
        """
        ...
