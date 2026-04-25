"""Central validator for filenames and paths returned by remote backends.

Threat model
------------
The user connects to a backend they don't necessarily trust (shared
S3 bucket, partner FTP, a WebDAV share run by someone else). Every
backend's ``list_dir`` returns :class:`FileItem` objects whose
``name`` and ``path`` attributes are **attacker-controlled strings**.

Without validation those strings flow into:

* SQLite rows (core.cas, core.metadata_index) — a path with NUL or
  wildcard characters pollutes ``LIKE`` queries on unrelated terms.
* Trash sidecar ``original_path`` — an attacker who can write to the
  trash dir could then restore a file to a name containing
  path-traversal fragments.
* Thumbnail cache keys — fine (hashed), but the abs_path still
  flows to ``os.stat``, so NUL bytes hit the kernel boundary.
* xlink ``display_name`` and ``target_url`` — rendered in the UI.

This module is the one place where backend-supplied strings get
sanity-checked before they're allowed into any of those sinks.

API
---
:func:`validate_remote_name`   raise on bad, return on ok.
:func:`is_safe_remote_name`    same, but returns bool.
:func:`sanitize_for_display`   strip dangerous chars, return a safe
                                version suitable for UI display (never
                                for fs ops — use validate instead).

What counts as "bad"
--------------------
* NUL bytes — end-of-string in every C API we eventually call.
* ASCII control chars (0x01-0x1f, 0x7f) except TAB/CR/LF.
* Path separators ``/`` and backslash — we're validating a single
  component; separators are not allowed in names.
* ``.`` and ``..`` — traversal / parent refs.
* Unicode bidi override chars (U+202A..E, U+2066..9) — filename
  spoofing (``"exe.nettol".pdf`` rendered as ``"file.exe"``).
* Total UTF-8 byte length > :data:`MAX_REMOTE_NAME_BYTES` (default
  512). Longer names are almost always hostile probes.

What is allowed
---------------
* All printable Unicode except the control categories above.
* Emoji, CJK, Arabic, RTL scripts (they're fine on their own — only
  the invisible *override* controls are blocked).
* Spaces and punctuation.
"""
from __future__ import annotations

import logging
from typing import Final

log = logging.getLogger("core.remote_name")


MAX_REMOTE_NAME_BYTES: Final[int] = 512
MAX_REMOTE_PATH_BYTES: Final[int] = 4096


# Bidi override / isolate controls — used in filename spoofing.
# (U+202A LRE .. U+202E RLO, U+2066 LRI .. U+2069 PDI)
_BIDI_OVERRIDES = frozenset(chr(c) for c in (
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
    0x2066, 0x2067, 0x2068, 0x2069,
))

# ASCII control chars we reject. TAB (0x09), LF (0x0a), CR (0x0d) are
# tolerated because some backends put them in fake metadata; we can
# deal with them elsewhere. DEL (0x7f) rejected.
_BAD_CONTROLS = frozenset(chr(c) for c in range(32) if c not in (9, 10, 13))
_BAD_CONTROLS = _BAD_CONTROLS | {chr(0x7f)}


class RemoteNameError(ValueError):
    """Raised when a backend-supplied name fails the validator."""


def validate_remote_name(
    name: str,
    *,
    max_bytes: int = MAX_REMOTE_NAME_BYTES,
    allow_separators: bool = False,
) -> None:
    """Raise :class:`RemoteNameError` if *name* is unsafe.

    *name* is expected to be a **single path component** — pass
    ``allow_separators=True`` to validate a whole path instead
    (still rejects traversal and NUL bytes).
    """
    if not isinstance(name, str):
        raise RemoteNameError(f"name must be str, got {type(name).__name__}")
    if not name:
        raise RemoteNameError("empty name")
    encoded = name.encode("utf-8", errors="replace")
    if len(encoded) > max_bytes:
        raise RemoteNameError(
            f"name exceeds {max_bytes} bytes (utf-8, got {len(encoded)})"
        )
    if "\x00" in name:
        raise RemoteNameError("name contains NUL byte")
    bad_ctrl = set(name) & _BAD_CONTROLS
    if bad_ctrl:
        points = ",".join(f"U+{ord(c):04X}" for c in sorted(bad_ctrl))
        raise RemoteNameError(f"name contains control chars: {points}")
    bad_bidi = set(name) & _BIDI_OVERRIDES
    if bad_bidi:
        points = ",".join(f"U+{ord(c):04X}" for c in sorted(bad_bidi))
        raise RemoteNameError(f"name contains bidi override chars: {points}")

    if allow_separators:
        # Whole-path validation: still reject traversal + empty
        # components.
        parts = [p for p in name.replace("\\", "/").split("/") if p]
        if not parts and name.strip("/\\") == "":
            # "/" alone is ok (it's "root" in most protocols)
            return
        for part in parts:
            if part in (".", ".."):
                raise RemoteNameError(
                    f"path contains traversal component: {part!r}"
                )
        return

    # Single-component validation.
    if "/" in name or "\\" in name:
        raise RemoteNameError("name contains path separator")
    if name in (".", ".."):
        raise RemoteNameError(f"name is reserved: {name!r}")


def is_safe_remote_name(
    name: object,
    *,
    max_bytes: int = MAX_REMOTE_NAME_BYTES,
    allow_separators: bool = False,
) -> bool:
    """Non-raising variant of :func:`validate_remote_name`."""
    if not isinstance(name, str):
        return False
    try:
        validate_remote_name(name, max_bytes=max_bytes,
                             allow_separators=allow_separators)
    except RemoteNameError:
        return False
    return True


def sanitize_for_display(name: str, *, replacement: str = "\ufffd") -> str:
    """Return a version safe to render in the UI.

    NUL bytes, ASCII controls and bidi overrides are replaced with
    *replacement* (U+FFFD by default). The result is STILL NOT safe
    to pass to a filesystem op — that needs :func:`validate_remote_name`.
    This is strictly a display filter.
    """
    if not isinstance(name, str):
        return ""
    bad = _BAD_CONTROLS | _BIDI_OVERRIDES | {"\x00"}
    if not (set(name) & bad):
        return name
    return "".join(replacement if c in bad else c for c in name)


__all__ = [
    "MAX_REMOTE_NAME_BYTES",
    "MAX_REMOTE_PATH_BYTES",
    "RemoteNameError",
    "is_safe_remote_name",
    "sanitize_for_display",
    "validate_remote_name",
]
