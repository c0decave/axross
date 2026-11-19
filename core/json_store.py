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
import secrets
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


def set_aside_if_unchanged(path: Path | str, raw: bytes) -> Path | None:
    """:func:`set_aside` *path* only while it still holds *raw* (the bytes
    that could not be read), under the store's lock: another process may
    have set the same broken file aside and saved a good one meanwhile -
    renaming that one away lost every entry it held. Returns the new name,
    ``None`` when the file was replaced or is gone (nothing is moved).
    OSError when the rename fails."""
    from core.secure_storage import locked_store_update

    target = Path(path)
    with locked_store_update(target):
        try:
            now = target.read_bytes()
        except FileNotFoundError:
            return None
        if now != raw:
            log.info("%s was replaced since it was read: not set aside", target)
            return None
        return set_aside(target)


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
    if set_aside_if_unchanged(target, raw_bytes) is None and target.exists():
        # Replaced since the read (another process set it aside and saved):
        # merge with what is there now.
        return read_for_merge(target, max_bytes=max_bytes)
    return {}


def temp_sibling(path: Path | str) -> Path:
    """A fresh temp file name beside *path*, named as core's atomic writes
    name theirs (``.tmp-<12 hex>.tmp``, core.atomic_io): unique per save,
    so two processes saving the same store never share one, and swept by
    core.atomic_recovery when a save was killed half way."""
    return Path(path).with_name(f".tmp-{secrets.token_hex(6)}.tmp")


def write_private(path: Path | str, data: str | bytes) -> None:
    """Write *data* (text as UTF-8) to *path* atomically as a 0600 file:
    a temp file of this save's own (:func:`temp_sibling`, created
    exclusively, never through a link), then a rename over *path*. A
    failure leaves the old file and no temp file. The folder must exist."""
    target = Path(path)
    payload = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    tmp = temp_sibling(target)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        try:
            view = memoryview(payload)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass


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


__all__ = [
    "on_save_failure",
    "read_for_merge",
    "report_save_failure",
    "set_aside",
    "set_aside_if_unchanged",
    "temp_sibling",
    "write_private",
]
