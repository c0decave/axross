"""A media file probed in a separate process before Qt Multimedia opens it.

Qt Multimedia's FFmpeg backend demuxes and decodes inside axross (on its
own threads, so a hang there does not hold the window - a crash ends the
program). Playing in a child process would need the frames carried back to
the window; what is cheap is a look first: ffprobe - when it is installed -
opens the file in a child the way a player starts it (the container, the
streams, a few packets for their parameters) with a time bound. A file whose
probe crashes or hangs is refused with the reason. A probe that merely
cannot read the file refuses nothing: Qt says why itself.

The guard is partial: the system's ffprobe is another FFmpeg build than the
one Qt bundles, and a file can hold its trap past what a probe reads.

Pure Python, no Qt.
"""

from __future__ import annotations

import logging
import os
import threading

from core import metadata_formats as MF

log = logging.getLogger(__name__)

#: Seconds the probe of one file may take.
PROBE_SECONDS = 10.0
#: Largest answer of the probe read.
_MAX_OUTPUT = 256 * 1024
#: Results kept: (path, size, mtime ns) -> refusal (None: may be played).
_CACHE_SIZE = 512

_cache: dict = {}
_lock = threading.Lock()


def _key(path: str):
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (os.path.abspath(path), st.st_size, st.st_mtime_ns)


def probe_refusal(path: str, *, cancel: threading.Event | None = None) -> str | None:
    """Why the local media file at *path* is not handed to Qt Multimedia
    (its probe crashed or did not end), or ``None``: it may be played -
    also when ffprobe is not installed or could not read the file."""
    ffprobe = MF.ffprobe_path()
    key = _key(path)
    if not ffprobe or key is None:
        return None
    with _lock:
        if key in _cache:
            return _cache[key]
    argv = [
        ffprobe, "-hide_banner", "-v", "error",
        "-protocol_whitelist", "file",
        "-show_entries", "format=format_name:stream=codec_type",
        "-of", "json",
        MF._ff_input(path),
    ]
    reason = None
    try:
        code, _out, _err = MF.run_bounded(argv, timeout=PROBE_SECONDS, max_output=_MAX_OUTPUT,
                                          cancel=cancel)
    except MF.FormatError as exc:
        if cancel is not None and cancel.is_set():
            return None  # nobody waits for the answer; not remembered
        if "timed out" in str(exc):
            reason = (f"the media probe (ffprobe) did not finish with this file in "
                      f"{PROBE_SECONDS:g} s: it is not played")
        else:
            log.debug("media probe of %s: %s", path, exc)
    except OSError as exc:
        log.debug("media probe of %s could not start: %s", path, exc)
        return None
    else:
        if code < 0:
            reason = (f"the file made the media probe (ffprobe) crash (signal {-code}): "
                      "it is not played")
    with _lock:
        if len(_cache) >= _CACHE_SIZE:
            _cache.clear()
        _cache[key] = reason
    if reason is not None:
        log.warning("Media file refused: %s: %s", path, reason)
    return reason


def available() -> bool:
    """Whether files are probed here (ffprobe is installed)."""
    return bool(MF.ffprobe_path())


def known(path: str) -> tuple[bool, str | None]:
    """``(True, refusal)`` when *path* as it is now was probed already (or
    needs no probe: no ffprobe, no such file), ``(False, None)`` when a
    :func:`probe_refusal` would start ffprobe."""
    if not MF.ffprobe_path():
        return True, None
    key = _key(path)
    if key is None:
        return True, None
    with _lock:
        if key in _cache:
            return True, _cache[key]
    return False, None


def forget() -> None:
    """Drop the remembered results (tests)."""
    with _lock:
        _cache.clear()


__all__ = ["PROBE_SECONDS", "available", "forget", "known", "probe_refusal"]
