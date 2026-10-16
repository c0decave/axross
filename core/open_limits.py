"""Maximum file size the viewers and editors will open.

One user-configurable number (MB) shared by the text editor, the hex
editor, the double-click decision in the file pane and the elevated
viewer. Stored in ``~/.config/axross/settings.json`` next to other
small preferences; read on every use so a change applies immediately
and across panes without a restart.

The viewers read the whole file into memory, which is why a cap exists
at all; the ceiling below keeps a typo from asking for the moon.

:func:`read_setting` / :func:`write_setting` give other small preferences
(the metadata tools' write mode and confirmation) a place in the same
file instead of a store of their own.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from pathlib import Path

log = logging.getLogger(__name__)

MIB = 1024 * 1024
DEFAULT_MAX_OPEN_MB = 32
MIN_MAX_OPEN_MB = 1
MAX_MAX_OPEN_MB = 4096

SETTINGS_PATH = Path.home() / ".config" / "axross" / "settings.json"
_KEY = "max_open_mb"
_LOCK = threading.Lock()


def _valid(value: object) -> bool:
    # bool is an int subclass; ``true`` in a hand-edited file is not a size.
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and MIN_MAX_OPEN_MB <= value <= MAX_MAX_OPEN_MB
    )


def _read_all() -> dict:
    try:
        raw = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return raw if isinstance(raw, dict) else {}


def max_open_mb() -> int:
    """Configured limit in MB; the default when unset or invalid."""
    value = _read_all().get(_KEY)
    return value if _valid(value) else DEFAULT_MAX_OPEN_MB


def max_open_bytes() -> int:
    return max_open_mb() * MIB


def describe_limit() -> str:
    """Human text for messages, e.g. ``"32 MB"``."""
    return f"{max_open_mb()} MB"


def set_max_open_mb(mb: int) -> None:
    """Persist a new limit. Raises ``ValueError`` outside
    [MIN_MAX_OPEN_MB, MAX_MAX_OPEN_MB] and ``TypeError`` for non-integers."""
    if isinstance(mb, bool) or not isinstance(mb, int):
        raise TypeError(f"max open size must be an integer number of MB, got {mb!r}")
    if not _valid(mb):
        raise ValueError(f"max open size must be {MIN_MAX_OPEN_MB}-{MAX_MAX_OPEN_MB} MB, got {mb}")
    write_setting(_KEY, mb)
    log.info("Open size limit set to %d MB", mb)


def read_setting(key: str, default=None):
    """One value of ``settings.json``, or *default* when it is missing or
    the file cannot be read. Callers validate the type themselves: the file
    is hand-editable."""
    return _read_all().get(key, default)


def write_setting(key: str, value) -> None:
    """Store one JSON value in ``settings.json``, keeping every other key.

    The small preferences of several features share this file (the open
    size limit, the metadata tools' write mode); the write is atomic and
    the file stays 0600."""
    with _LOCK:
        data = _read_all()
        data[key] = value
        target_dir = SETTINGS_PATH.parent
        target_dir.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=target_dir, prefix=".settings.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as tmp:
                tmp.write(json.dumps(data, indent=2) + "\n")
            os.replace(tmp_name, SETTINGS_PATH)
            os.chmod(SETTINGS_PATH, 0o600)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise


__all__ = [
    "DEFAULT_MAX_OPEN_MB",
    "MAX_MAX_OPEN_MB",
    "MIN_MAX_OPEN_MB",
    "describe_limit",
    "max_open_bytes",
    "max_open_mb",
    "read_setting",
    "set_max_open_mb",
    "write_setting",
]
