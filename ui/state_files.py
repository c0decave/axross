"""The window's state files (session.json, recents, the viewers' sizes): read
bounded and strictly, written atomically and privately.

Out of ui.main_window so that a window of its own (the viewers'
ui.viewer_window, the standalone Media Player and System Information) keeps
its state without importing the whole main window.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path

from core import posix_compat

log = logging.getLogger(__name__)

MAX_UI_STATE_BYTES = 1024 * 1024


def _read_json_file(path: Path | str, *, max_bytes: int = MAX_UI_STATE_BYTES):
    """Parsed JSON of ``path``. Raises OSError (unreadable, too large) or
    ValueError (not UTF-8: UnicodeDecodeError, not JSON: JSONDecodeError,
    nested past the recursion limit); callers catch both."""
    target = Path(path)
    if target.stat().st_size > max_bytes:
        raise OSError(f"{target} exceeds {max_bytes} bytes")
    text = target.read_bytes().decode("utf-8")
    try:
        return json.loads(text)
    except RecursionError as exc:
        # Python 3.11's C decoder honours the recursion limit: a file nested
        # some thousand levels deep raised RecursionError past the callers.
        raise ValueError(f"{target} is nested too deeply") from exc


def _write_private_text(path: Path | str, text: str, *, private_dir: bool = True) -> None:
    """Write *text* to *path* atomically as a 0600 file.

    *private_dir* (axross' own config folder) also creates the folder and
    makes it 0700. A folder the user picked (an export) is left exactly
    as it is: its mode is not ours to change."""
    target = Path(path)
    if private_dir:
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(target.parent, 0o700)
        except OSError:
            log.debug("Could not set permissions on %s", target.parent, exc_info=True)
    fd, temp_name = tempfile.mkstemp(
        dir=target.parent,
        prefix=f".{target.name}.",
        suffix=".tmp",
    )
    try:
        try:
            posix_compat.fchmod_private(fd, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            handle.write(text)
        os.replace(temp_name, target)
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass
    except BaseException:
        if fd != -1:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


__all__ = ["MAX_UI_STATE_BYTES", "_read_json_file", "_write_private_text"]
