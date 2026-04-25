"""Point-in-time version record for backends that expose a history.

Backends with native versioning (S3 with bucket versioning enabled,
Azure Blob versioning, Dropbox, Google Drive, OneDrive, WebDAV with
RFC 3253 DeltaV) return a list of these from
``FileBackend.list_versions(path)``. The Virtual Snapshot Browser
(phase 4e) shows them as a uniform timeline across protocols.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class FileVersion:
    """One historical revision of a file."""

    # Backend-specific handle used to fetch this version's bytes.
    # S3 VersionId, Dropbox rev, Drive revision id, Azure x-ms-version-id,
    # OneDrive itemId:versionId, WebDAV DAV:version-name.
    version_id: str
    # When this version was committed on the server.
    modified: datetime = field(default_factory=lambda: datetime.fromtimestamp(0))
    # Bytes in this version. Zero when the backend didn't populate it.
    size: int = 0
    # True for the version currently returned by a plain read on the
    # file's path. False for historical revisions.
    is_current: bool = False
    # Optional user-friendly label (Dropbox rev string, Drive
    # modifiedByMe, etc.). Falls back to version_id when empty.
    label: str = ""
