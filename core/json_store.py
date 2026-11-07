"""Reading a JSON store before writing it back: the step where a broken or
unreadable file must not turn into a file that holds only the new key.

Several stores are read, changed and written whole (settings.json's small
preferences, session.json's window object, the language). Reading them for
display may degrade to "nothing stored"; reading them to write must not:

- missing: an empty object, the write creates the file;
- not JSON or not an object (a hand-edit gone wrong, a truncated write):
  the file is set aside under a unique name - the user's data is kept and
  the write starts from an empty object;
- unreadable (permissions, I/O, larger than *max_bytes*): OSError, and the
  caller writes nothing.
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from pathlib import Path

log = logging.getLogger(__name__)


def set_aside(path: Path | str) -> Path:
    """Rename *path* to a unique ``NAME.unreadable-STAMP-ID`` sibling and
    return it. OSError when the rename fails."""
    target = Path(path)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    aside = target.with_name(f"{target.name}.unreadable-{stamp}-{uuid.uuid4().hex[:8]}")
    os.rename(target, aside)
    log.warning("Unreadable %s kept as %s", target, aside)
    return aside


def read_for_merge(path: Path | str, *, max_bytes: int | None = None) -> dict:
    """The JSON object stored in *path*, to change and write back (see the
    module's rules). OSError when it exists but cannot be read."""
    target = Path(path)
    try:
        if max_bytes is not None and target.stat().st_size > max_bytes:
            raise OSError(f"{target} exceeds {max_bytes} bytes")
        raw_bytes = target.read_bytes()
    except FileNotFoundError:
        return {}
    try:
        data = json.loads(raw_bytes.decode("utf-8"))
    except (ValueError, RecursionError):
        data = None
    if isinstance(data, dict):
        return data
    set_aside(target)
    return {}


_SAVE_FAILURE_LISTENERS: list = []


def on_save_failure(callback) -> None:
    """Call *callback(what, error_text)* when a store could not be saved
    (the main window shows it: a bookmark that seems added but is not
    on disk is gone at the next start)."""
    _SAVE_FAILURE_LISTENERS.append(callback)


def report_save_failure(what: str, exc: BaseException) -> None:
    """Log that the store *what* was not saved, and tell the listeners."""
    log.error("Failed to save %s: %s", what, exc)
    for callback in list(_SAVE_FAILURE_LISTENERS):
        try:
            callback(what, str(exc))
        except Exception:  # noqa: BLE001 - a listener must not break the save path
            log.debug("save-failure listener failed", exc_info=True)


__all__ = ["on_save_failure", "read_for_merge", "report_save_failure", "set_aside"]
