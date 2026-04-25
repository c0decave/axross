"""Cross-protocol symlinks — pointers that work where POSIX symlinks don't.

FTP, SMB (2+), S3, WebDAV, cloud drives... most lack a portable symlink
primitive. This module defines a tiny ``.axlink`` file format that
*any* backend can store because it's just a small JSON blob. The GUI
renders those files as arrows and follows them on double-click.

Shape
-----
Link file suffix: ``.axlink``
Payload:

    {
      "schema": "axross-link",
      "version": 1,
      "target_url": "sftp://host/abs/path",
      "display_name": "...",
      "created_at": "ISO-8601"
    }

The target_url is an opaque reference. How it gets resolved to a live
backend is outside this module's job — the UI owns that mapping
because it also owns the saved connection profiles. This module only
creates/reads/identifies link files.

Why JSON, not a magic binary header
-----------------------------------
Users poking at the file in a third-party client should see something
human-readable, and we want the file to round-trip cleanly through
every text-safe backend (IMAP, WebDAV). A binary magic would have
made content sniffing marginally faster but debugging messier.
"""
from __future__ import annotations

import io
import json
import logging
import posixpath
from datetime import datetime
from typing import Any

from models.xlink import (
    SCHEMA_TAG,
    SCHEMA_VERSION,
    LINK_SUFFIX,
    CrossProtocolLink,
)

log = logging.getLogger("core.xlink")

# A well-formed xlink is a ~200-byte JSON blob. 64 KiB is a
# generous ceiling that still protects clients from OOM if a
# malicious actor plants a multi-MB file with the .axlink suffix.
MAX_LINK_SIZE = 64 * 1024

# Allow-list of URL schemes an xlink is permitted to point at. The
# list covers every backend axross can actually open, plus our
# internal ``axross-link:`` and ``ax-cas:`` schemes. Everything
# else (``file:``, ``javascript:``, ``data:``, ``vbscript:``,
# ``chrome-extension:``, etc.) is rejected at parse time — the UI
# never has to decide whether a resolved link is safe to follow,
# because a link pointing somewhere dangerous can't round-trip
# through :func:`read_xlink` in the first place.
ALLOWED_TARGET_SCHEMES: frozenset[str] = frozenset({
    "sftp", "scp",
    "ftp", "ftps",
    "smb", "cifs",
    "http", "https",   # WebDAV lives here
    "webdav", "webdavs",
    "s3",
    "rsync",
    "nfs",
    "iscsi",
    "imap", "imaps",
    "telnet",
    "azure-blob", "azure-files",
    "onedrive", "sharepoint",
    "gdrive",
    "dropbox",
    "axross-link",
    "ax-cas",
})


def _validate_target_url(url: str) -> None:
    """Raise :class:`ValueError` if *url*'s scheme isn't on the allow-list."""
    if not isinstance(url, str) or not url:
        raise ValueError("target_url must be a non-empty string")
    # Reject embedded NUL and control chars before any scheme probe.
    if "\x00" in url:
        raise ValueError("target_url contains NUL byte")
    # Extract the scheme manually (urlparse is too permissive — it
    # accepts ``javascript:alert(1)`` and calls the scheme
    # ``javascript``, which we then explicitly reject — but it also
    # tolerates invalid forms we'd rather fail on).
    if ":" not in url:
        raise ValueError(f"target_url has no scheme: {url[:64]!r}")
    scheme, _, _rest = url.partition(":")
    scheme = scheme.strip().lower()
    if not scheme or any(c.isspace() for c in scheme):
        raise ValueError(f"target_url scheme malformed: {scheme!r}")
    if scheme not in ALLOWED_TARGET_SCHEMES:
        raise ValueError(
            f"target_url scheme {scheme!r} is not in the allow-list; "
            f"allowed: {sorted(ALLOWED_TARGET_SCHEMES)}"
        )


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _encode(link: CrossProtocolLink) -> bytes:
    payload: dict[str, Any] = {
        "schema": SCHEMA_TAG,
        "version": link.version,
        "target_url": link.target_url,
        "display_name": link.display_name,
        "created_at": link.created_at.isoformat(timespec="seconds"),
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _decode(raw: bytes) -> CrossProtocolLink:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"xlink payload is not UTF-8: {exc}") from exc
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ValueError(f"xlink payload is not JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("xlink payload must be a JSON object")
    if data.get("schema") != SCHEMA_TAG:
        raise ValueError(
            f"xlink schema mismatch: expected {SCHEMA_TAG!r}, "
            f"got {data.get('schema')!r}"
        )
    version = int(data.get("version") or 0)
    if version < 1 or version > SCHEMA_VERSION:
        raise ValueError(
            f"xlink version {version} is not supported by this build "
            f"(max {SCHEMA_VERSION})"
        )
    target = data.get("target_url")
    if not isinstance(target, str) or not target:
        raise ValueError("xlink target_url must be a non-empty string")
    # Refuse dangerous schemes (file://, javascript:, data:, ...).
    # Catches backends that plant malicious .axlink payloads before
    # the UI ever sees the parsed object.
    _validate_target_url(target)
    created_raw = data.get("created_at", "")
    try:
        created = datetime.fromisoformat(created_raw)
    except (TypeError, ValueError):
        created = datetime.now()
    return CrossProtocolLink(
        target_url=target,
        display_name=str(data.get("display_name") or ""),
        created_at=created,
        version=version,
    )


def _ensure_link_suffix(path: str) -> str:
    """Append .axlink if missing. Canonical form avoids foot-guns where
    some backends hide dotfiles."""
    if path.endswith(LINK_SUFFIX):
        return path
    return path + LINK_SUFFIX


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_xlink_path(path: str) -> bool:
    """Quick check by filename. Doesn't hit the network."""
    return path.endswith(LINK_SUFFIX)


def is_xlink(backend, path: str) -> bool:
    """Reliable check — reads the file and validates the schema.

    Returns False on any IO error or schema mismatch. Use this before
    trying to :func:`read_xlink` when you only have a guess.
    """
    if not is_xlink_path(path):
        return False
    try:
        handle = backend.open_read(path)
    except OSError as exc:
        log.debug("is_xlink: open_read(%s) failed: %s", path, exc)
        return False
    # Pre-bind so the post-finally code never hits NameError if the read
    # itself raises (OSError mid-transfer, decoder quirks, etc.).
    raw: bytes = b""
    try:
        # Guard against a malicious / huge file. A link payload is a
        # tiny JSON blob; anything beyond MAX_LINK_SIZE is not an xlink
        # we want to parse.
        raw = handle.read(MAX_LINK_SIZE + 1)
    except OSError as exc:
        log.debug("is_xlink: read(%s) failed: %s", path, exc)
        return False
    finally:
        try:
            handle.close()
        except Exception as close_exc:
            log.debug("xlink: handle close failed: %s", close_exc)
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="replace")
    if len(raw) > MAX_LINK_SIZE:
        log.warning("is_xlink: %s exceeds %d bytes — refusing to parse",
                    path, MAX_LINK_SIZE)
        return False
    try:
        _decode(raw)
    except ValueError as exc:
        log.debug("is_xlink: %s failed schema check: %s", path, exc)
        return False
    return True


def create_xlink(backend, path: str, target_url: str,
                 display_name: str = "") -> str:
    """Write a new ``.axlink`` file at *path* pointing at *target_url*.

    Returns the final on-disk path (``path`` with ``.axlink`` suffix).
    Rejects target URLs whose scheme isn't in
    :data:`ALLOWED_TARGET_SCHEMES` so we never *write* something a
    parser would later refuse to load.
    """
    if not target_url:
        raise ValueError("target_url must be non-empty")
    _validate_target_url(target_url)
    final = _ensure_link_suffix(path)
    link = CrossProtocolLink(
        target_url=target_url,
        display_name=display_name or posixpath.basename(path.rstrip("/")),
    )
    data = _encode(link)
    handle = backend.open_write(final)
    try:
        handle.write(data)
    finally:
        handle.close()
    return final


def read_xlink(backend, path: str) -> CrossProtocolLink:
    """Parse the ``.axlink`` file at *path*.

    Raises :class:`OSError` on IO failure and :class:`ValueError` on
    schema mismatch — the distinction lets callers tell "link is
    missing" from "link exists but is corrupt".
    """
    handle = backend.open_read(path)
    # Pre-bind to avoid a NameError on post-finally access if read raises.
    raw: bytes | str = b""
    try:
        raw = handle.read(MAX_LINK_SIZE + 1)
    finally:
        try:
            handle.close()
        except Exception as close_exc:
            log.debug("xlink: handle close failed: %s", close_exc)
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="replace")
    if len(raw) > MAX_LINK_SIZE:
        raise ValueError(
            f"xlink payload at {path} exceeds {MAX_LINK_SIZE} bytes"
        )
    return _decode(raw)


def target_of(backend, path: str) -> str:
    """Shortcut: ``read_xlink(...).target_url``. Raises on failure."""
    return read_xlink(backend, path).target_url


# ---------------------------------------------------------------------------
# Pure parse/dump — useful in UI code that already has the bytes
# ---------------------------------------------------------------------------

def decode(raw: bytes) -> CrossProtocolLink:
    """Public parser for raw xlink payload bytes."""
    return _decode(raw)


def encode(link: CrossProtocolLink) -> bytes:
    """Public serializer for a :class:`CrossProtocolLink`."""
    return _encode(link)


# Re-export so callers only need to import from core.xlink.
__all__ = [
    "CrossProtocolLink",
    "LINK_SUFFIX",
    "SCHEMA_TAG",
    "SCHEMA_VERSION",
    "create_xlink",
    "decode",
    "encode",
    "is_xlink",
    "is_xlink_path",
    "read_xlink",
    "target_of",
]
