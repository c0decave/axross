"""Keep a one-file bundle reading its own modules after its file is replaced.

PyInstaller reads a module imported late (a context menu, a dialog) from
the executable's embedded PYZ archive and opens the executable by its path
for each read (``pyimod01_archive.ZlibArchiveReader.extract``). Once another
file sits at that path - the self-update renames the new version over the
running one (core.self_update.install), or a new build is copied there - the
running process reads the other file at its old offsets, and the first late
import fails with "zlib.error: Error -3 while decompressing data: incorrect
header check".

:func:`pin_frozen_archive` opens the executable once, at start, and lets the
archive read through that descriptor (``os.pread``: every read has its own
position, so late imports in two threads do not disturb each other). A file
renamed over the path then leaves the running process on the file it started
from; the new one is used by the next start. Windows needs nothing: a
running .exe cannot be replaced there (the update lands next to it).
"""

from __future__ import annotations

import builtins
import logging
import marshal
import os
import struct
import sys

log = logging.getLogger(__name__)

_MAGIC = b"PYZ\0"


class _PinnedFile:
    """The little of a binary file ``ZlibArchiveReader`` uses, read with
    ``os.pread`` from a descriptor held open for the process."""

    def __init__(self, fd: int) -> None:
        self._fd = fd
        self._pos = 0

    def __enter__(self) -> _PinnedFile:
        return self

    def __exit__(self, *_exc) -> bool:
        return False

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            self._pos = offset
        elif whence == os.SEEK_CUR:
            self._pos += offset
        else:
            self._pos = os.fstat(self._fd).st_size + offset
        return self._pos

    def tell(self) -> int:
        return self._pos

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = max(0, os.fstat(self._fd).st_size - self._pos)
        data = os.pread(self._fd, size, self._pos)
        self._pos += len(data)
        return data

    def readinto(self, buffer) -> int:
        data = self.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)

    def close(self) -> None:
        pass  # the descriptor stays open for the process


def _same_archive(fd: int, reader) -> bool:
    """Whether *fd* holds the archive *reader* was opened on: its magic at
    the start offset and the same table of contents."""
    pinned = _PinnedFile(fd)
    pinned.seek(reader._start_offset)
    header = pinned.read(len(_MAGIC) + 4 + 4)
    if len(header) < 12 or header[:4] != _MAGIC:
        return False
    (toc_offset,) = struct.unpack("!i", header[8:12])
    pinned.seek(reader._start_offset + toc_offset)
    try:
        toc = dict(marshal.loads(pinned.read()))
    except (EOFError, ValueError, TypeError):
        return False
    return toc == reader.toc


def pin_archive(archive_module, reader) -> bool:
    """Make *reader* (a ``ZlibArchiveReader`` of *archive_module*) read its
    file through a descriptor opened now. False when it cannot: no
    ``os.pread``, the file is gone, or it was already replaced."""
    path = getattr(reader, "_filename", None)
    if not path or not hasattr(os, "pread"):
        return False
    if getattr(archive_module, "_axross_pinned_path", None) == path:
        return True
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        log.warning("Bundle archive %s not pinned: %s", path, exc)
        return False
    if not _same_archive(fd, reader):
        os.close(fd)
        log.warning("Bundle archive %s was replaced before it could be pinned; "
                    "late imports read the file at that path", path)
        return False

    def pinned_open(file, mode="r", *args, **kwargs):
        if file == path and mode == "rb" and not args and not kwargs:
            return _PinnedFile(fd)
        return builtins.open(file, mode, *args, **kwargs)

    # The module looks "open" up in its own namespace first.
    archive_module.open = pinned_open
    archive_module._axross_pinned_path = path
    archive_module._axross_pinned_fd = fd
    return True


def pin_frozen_archive() -> bool:
    """:func:`pin_archive` for this process's own bundle; False when not frozen."""
    if not getattr(sys, "frozen", False):
        return False
    archive_module = sys.modules.get("pyimod01_archive")
    importers = sys.modules.get("pyimod02_importers")
    reader = getattr(importers, "pyz_archive", None)
    if archive_module is None or reader is None:
        return False
    return pin_archive(archive_module, reader)


#: The descriptor that holds the lock on the unpacked folder (lock_bundle_dir).
_BUNDLE_DIR_LOCK: dict[str, int] = {}


def lock_bundle_dir(path: str | None = None) -> bool:
    """Keep the temp cleaner away from this one-file bundle's unpacked folder.

    PyInstaller unpacks a one-file bundle into ``/tmp/_MEI*`` (``sys._MEIPASS``)
    and leaves it unlocked. systemd-tmpfiles cleans ``/tmp`` by age every day
    (``q /tmp ... 10d``): after ten days every file the process has not
    touched since its start - a Qt plugin, a translation, an extension
    module loaded later - is deleted under the running process, and the
    next late import fails (measured with the 0.14.102 binary and the age
    shortened: 2907 files gone, ``No module named 'PyQt6.QtSvg'``).
    tmpfiles skips a directory, and everything below it, on which it finds a
    BSD lock (tmpfiles.d(5), "Age"); a shared ``flock`` held for the life of
    the process is that lock. It does not stop the bootloader removing the
    folder when the process ends (flock is advisory).

    *path* defaults to ``sys._MEIPASS`` of a frozen process. False when
    there is nothing to lock (not frozen, no folder) or no ``flock``
    (Windows, whose temp cleaner works differently)."""
    if path is None:
        if not getattr(sys, "frozen", False):
            return False
        path = getattr(sys, "_MEIPASS", None)
    if not path:
        return False
    if path in _BUNDLE_DIR_LOCK:
        return True
    try:
        import fcntl
    except ImportError:
        return False
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                     | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        log.warning("Bundle folder %s not locked against the temp cleaner: %s", path, exc)
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except OSError as exc:
        os.close(fd)
        log.warning("Bundle folder %s not locked against the temp cleaner: %s", path, exc)
        return False
    _BUNDLE_DIR_LOCK[path] = fd
    return True


def _unlock_bundle_dir_for_tests(path: str) -> None:
    fd = _BUNDLE_DIR_LOCK.pop(path, None)
    if fd is not None:
        os.close(fd)


def _unpin_for_tests(archive_module) -> None:
    fd = archive_module.__dict__.pop("_axross_pinned_fd", None)
    archive_module.__dict__.pop("_axross_pinned_path", None)
    archive_module.__dict__.pop("open", None)
    if fd is not None:
        os.close(fd)
