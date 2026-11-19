"""The process's umask, read without changing it (no Qt: the headless
exports use it through core.archive)."""

from __future__ import annotations

import os

_FALLBACK_UMASK: int | None = None


def process_umask() -> int:
    """This process's umask, read without changing it where possible.

    os.umask() can only be read by setting it, which for a moment lets
    another thread create a file with the wrong mode; /proc avoids that.

    Read anew on every call - the umask can change while axross runs (a
    bracket such as adb's key generation, a script) - but as raw bytes:
    a text-mode read of the ~60 lines cost ~80 µs, twice per copied file.
    """
    global _FALLBACK_UMASK
    try:
        fd = os.open("/proc/self/status", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            data = os.read(fd, 16384)
        finally:
            os.close(fd)
        at = data.find(b"\nUmask:")
        if at >= 0:
            return int(data[at + 7 : data.index(b"\n", at + 7)].strip(), 8)
    except (OSError, ValueError, IndexError):
        pass
    if _FALLBACK_UMASK is None:
        current = os.umask(0o022)
        os.umask(current)
        _FALLBACK_UMASK = current
    return _FALLBACK_UMASK
