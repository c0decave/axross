"""Cross-protocol symlink (``xlink``) payload shape.

An xlink is a small JSON file on any backend whose content points at a
resource living on a (possibly different) backend. It's a
user-visible answer to "POSIX symlinks don't exist on FTP/S3/SMB,
but I still want a pointer that the file manager understands."

Layout
------
Link files end in ``.axlink`` and contain exactly this JSON:

    {
      "schema": "axross-link",
      "version": 1,
      "target_url": "sftp://host/abs/path",
      "display_name": "my pointer",
      "created_at": "2026-04-17T12:00:00"
    }

Anything else is not a valid xlink and :func:`core.xlink.read_xlink`
will raise.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


SCHEMA_TAG = "axross-link"
SCHEMA_VERSION = 1
LINK_SUFFIX = ".axlink"


@dataclass(frozen=True)
class CrossProtocolLink:
    """Parsed xlink payload."""

    target_url: str
    display_name: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    version: int = SCHEMA_VERSION
