"""A download as a spooled file instead of one bytes object in RAM.

Backends whose open_read must fetch a file before returning it (FTP,
S3, Azure, WebDAV) collected the whole body in an io.BytesIO: a 4 GiB
file needed 4 GiB of RAM. A SpooledTemporaryFile keeps small files in
memory and moves larger ones to a temp file, like SCP's read already
does; the result stays a seekable IO[bytes].

In a running transfer (core.transfer_hooks) the download checks Cancel
between chunks and reports its bytes: the whole fetch happens inside
``open_read``, before the engine's copy loop sees a byte.

Where a spool past :data:`READ_SPOOL_MAX` goes (:func:`spool_dir`): /tmp
is a tmpfs of half the RAM on many systems, and a large download there
ended in ENOSPC (or pushed the machine into swap) half-way. A spool goes
next to the transfer's local destination when the engine knows one, else
to ``$AXROSS_SPOOL_DIR`` or :func:`set_spool_dir`'s folder, else - unless
the user chose the temp folder (``TMPDIR``, the tmpfs setting) - to
``$XDG_CACHE_HOME/axross/spool``. A spool of known size checks the free
space there first and fails early (ENOSPC) instead of half-way.

A reader that goes front to back once - the transfer engine's copy loop
(:func:`sequential_reads`) - needs no spool at all: S3, Azure, WebDAV,
Dropbox, OneDrive and FTP then hand out the download as it arrives
(:class:`StreamedBody`, FTP's own reader), and a download into a local
folder needs the room for the file once, not twice (the spool beside the
copy). A spool stays where a reader may seek (FUSE, previews, a resume
that compares the partial with the source).
"""

from __future__ import annotations

import contextlib
import contextvars
import errno
import io
import logging
import os
import tempfile
from collections.abc import Callable, Iterable, Iterator
from typing import IO

from core import transfer_hooks

log = logging.getLogger(__name__)

#: Bytes a spool keeps in memory before it rolls over to a temp file.
READ_SPOOL_MAX = 8 * 1024 * 1024
#: Bytes asked for per read() from a file-like download body.
READ_CHUNK = 1024 * 1024
#: An absolute folder here is where spools go (see spool_dir()).
SPOOL_DIR_ENV = "AXROSS_SPOOL_DIR"
#: Free space a spool leaves on its file system, beside its own size.
SPOOL_RESERVE = 64 * 1024 * 1024

_configured_dir: str | None = None


def set_spool_dir(path: str | None) -> None:
    """Spools go to *path* from now on (None: the default again)."""
    global _configured_dir
    _configured_dir = os.path.abspath(path) if path else None


def _usable_dir(path: str | None) -> str | None:
    """*path*, made (0700) when missing; None when it cannot be used."""
    if not path:
        return None
    try:
        os.makedirs(path, mode=0o700, exist_ok=True)
    except OSError as exc:
        log.warning("Spool folder %s cannot be used (%s); using the temp folder", path, exc)
        return None
    return path if os.path.isdir(path) and os.access(path, os.W_OK | os.X_OK) else None


def spool_dir() -> str | None:
    """The folder for spools now; None means tempfile's default.

    The running transfer's own (its local destination's folder) first,
    then ``$AXROSS_SPOOL_DIR``, :func:`set_spool_dir`, the temp folder
    when the user chose it (``TMPDIR``, the tmpfs setting set
    ``tempfile.tempdir``), else ``$XDG_CACHE_HOME/axross/spool``."""
    hooks = transfer_hooks.current()
    near = getattr(hooks, "spool_dir", None) if hooks is not None else None
    if near and os.path.isdir(near) and os.access(near, os.W_OK | os.X_OK):
        return near
    env = (os.environ.get(SPOOL_DIR_ENV) or "").strip()
    for chosen in ((env if os.path.isabs(env) else None), _configured_dir):
        usable = _usable_dir(chosen)
        if usable is not None:
            return usable
    if tempfile.tempdir is not None or (os.environ.get("TMPDIR") or "").strip():
        return None
    from core.xdg_dirs import base_dir

    return _usable_dir(str(base_dir("XDG_CACHE_HOME") / "axross" / "spool"))


def _format_size(n: int) -> str:
    from core.system_info import human_bytes

    return human_bytes(n)


def ensure_spool_room(directory: str | None, size: int | None, *, factor: int = 1) -> None:
    """OSError ENOSPC when the file system of *directory* (None: the temp
    folder) has no room for *size* bytes (times *factor*) plus
    :data:`SPOOL_RESERVE`. Nothing to check for an unknown or small size
    (it stays in memory), or when the free space cannot be read."""
    if size is None or size <= READ_SPOOL_MAX:
        return
    folder = directory or tempfile.gettempdir()
    try:
        from core.posix_compat import disk_usage

        free = disk_usage(folder)[2]
    except (OSError, ValueError) as exc:
        log.debug("free space of %s unknown: %s", folder, exc)
        return
    needed = size * max(factor, 1) + SPOOL_RESERVE
    if free < needed:
        from core.i18n import tr

        raise OSError(
            errno.ENOSPC,
            tr("Not enough free space in {folder} to hold {size} while it is transferred "
               "({free} free). Set AXROSS_SPOOL_DIR to a folder with more room.").format(
                folder=folder, size=_format_size(size), free=_format_size(free)),
        )


def new_spool(size: int | None = None, *, max_size: int = READ_SPOOL_MAX) -> IO[bytes]:
    """An empty spool in :func:`spool_dir`, kept in memory up to
    *max_size* bytes; with *size* the free space is checked first."""
    directory = spool_dir()
    hooks = transfer_hooks.current()
    # Next to the local destination the copy needs the room a second time.
    near = hooks is not None and directory is not None and \
        directory == getattr(hooks, "spool_dir", None)
    ensure_spool_room(directory, size, factor=2 if near else 1)
    return tempfile.SpooledTemporaryFile(max_size=max_size, dir=directory)


def new_named_spool(size: int | None = None, *, prefix: str = "axross-",
                    suffix: str = "", delete: bool = True, mode: str = "w+b"):
    """A NamedTemporaryFile in :func:`spool_dir` (for a tool that wants a
    file path: adb pull / push, tftpy); with *size* the free space is
    checked first. With ``delete=False`` the caller removes it
    (:func:`remove_quietly`) on every path."""
    directory = spool_dir()
    ensure_spool_room(directory, size)
    return tempfile.NamedTemporaryFile(mode=mode, prefix=prefix, suffix=suffix,
                                       dir=directory, delete=delete)


def remove_quietly(path: str | None) -> None:
    """Remove the spool file *path*; one already gone is fine."""
    if not path:
        return
    try:
        os.unlink(path)
    except OSError:
        pass


_SEQUENTIAL: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "axross_read_sequential", default=False)


@contextlib.contextmanager
def sequential_reads(on: bool = True) -> Iterator[None]:
    """``open_read`` calls in the ``with`` body come from a reader that
    reads front to back once and never seeks (the transfer engine's copy
    loop, a checksum): a download may stream instead of spooling."""
    token = _SEQUENTIAL.set(bool(on))
    try:
        yield
    finally:
        _SEQUENTIAL.reset(token)


def streaming_wanted(size: int | None = None) -> bool:
    """True when the ``open_read`` being served may hand out the download
    as it arrives (:func:`sequential_reads`). With *size* the free space
    of the transfer's local destination folder is checked first - for the
    file once: no spool is kept beside it (OSError ENOSPC)."""
    if not _SEQUENTIAL.get():
        return False
    ensure_stream_room(size)
    return True


def ensure_stream_room(size: int | None) -> None:
    """OSError ENOSPC when the running transfer's local destination folder
    has no room for a streamed download of *size* bytes (once)."""
    hooks = transfer_hooks.current()
    near = getattr(hooks, "spool_dir", None) if hooks is not None else None
    if near:
        ensure_spool_room(near, size)


class StreamedBody(io.RawIOBase):
    """A download read from the wire as the caller reads, front to back.

    *chunks*: the body's chunks; *expected_size*: a download that ends
    shorter or longer is an OSError (as :func:`spool_chunks`); *close*:
    called once when the reader is closed (the response). An error of the
    HTTP library underneath (requests, botocore, the Azure SDK) while
    reading is an OSError naming *what*. Not seekable.
    """

    def __init__(self, chunks: Iterable[bytes], *, expected_size: int | None = None,
                 what: str = "read", close: Callable[[], object] | None = None) -> None:
        super().__init__()
        self._chunks = iter(chunks)
        self._expected = expected_size
        self._what = what
        self._close = close
        self._pending = b""
        self._received = 0
        self._pos = 0
        self._ended = False

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def tell(self) -> int:
        return self._pos

    def _next_chunk(self) -> bytes:
        while True:
            try:
                chunk = next(self._chunks)
            except StopIteration:
                self._ended = True
                if self._expected is not None and self._received != self._expected:
                    raise OSError(
                        errno.EIO,
                        f"{self._what}: received {self._received} bytes, "
                        f"the server announced {self._expected}",
                    ) from None
                return b""
            except OSError:
                raise
            except Exception as exc:  # noqa: BLE001 - the library's own error types
                raise OSError(errno.EIO, f"{self._what}: {exc}") from exc
            if chunk:
                self._received += len(chunk)
                return bytes(chunk)

    def readinto(self, buffer) -> int:
        if self.closed:
            raise ValueError("I/O operation on closed file")
        view = memoryview(buffer).cast("B")
        if not view.nbytes:
            return 0
        if not self._pending:
            if self._ended:
                return 0
            self._pending = self._next_chunk()
            if not self._pending:
                return 0
        n = min(len(self._pending), view.nbytes)
        view[:n] = self._pending[:n]
        self._pending = self._pending[n:]
        self._pos += n
        return n

    def close(self) -> None:
        if self.closed:
            return
        try:
            done, self._close = self._close, None
            closer = getattr(self._chunks, "close", None)  # a generator
            if closer is not None:
                try:
                    closer()
                except Exception:  # noqa: BLE001 - closing only
                    pass
            if done is not None:
                done()
        finally:
            super().close()


def new_read_spool(size: int | None = None) -> IO[bytes]:
    """An empty spool for a download that pushes its chunks (FTP);
    *size*, when known, is checked against the free space first."""
    return new_spool(size)


def read_chunks(body, size: int = READ_CHUNK) -> Iterator[bytes]:
    """``body.read(size)`` until it is exhausted.

    Reading with an explicit size until b"" is what lets botocore's
    StreamingBody compare the bytes received with its Content-Length.
    """
    while True:
        chunk = body.read(size)
        if not chunk:
            return
        yield chunk


def spool_chunks(
    chunks: Iterable[bytes],
    *,
    expected_size: int | None = None,
    what: str = "read",
    progress_total: int | None = None,
    close: Callable[[], object] | None = None,
) -> IO[bytes]:
    """Write *chunks* to a new spool and return it at position 0.

    With *expected_size* a download that is shorter or longer than the
    server announced is an OSError (*progress_total*: the size only for
    the progress report). The spool is closed on any error. In a running
    transfer (core.transfer_hooks) Cancel is checked between chunks
    (InterruptedError) and the bytes received are reported. *close* (the
    body's) is called once the chunks are read, or on error.

    For a reader that goes front to back (:func:`sequential_reads`) the
    chunks are handed out as they arrive instead (:class:`StreamedBody`,
    which calls *close* when it is closed).
    """
    size = expected_size if expected_size is not None else progress_total
    try:
        if streaming_wanted(size):
            return StreamedBody(chunks, expected_size=expected_size, what=what, close=close)
    except BaseException:
        if close is not None:
            close()
        raise
    try:
        return _spool_chunks(chunks, expected_size, what, progress_total, size)
    finally:
        if close is not None:
            close()


def _spool_chunks(chunks, expected_size, what, progress_total, size) -> IO[bytes]:
    spool = new_read_spool(size)
    total = 0
    hooks = transfer_hooks.current()
    try:
        if hooks is not None:
            hooks.check()
        for chunk in chunks:
            if chunk:
                spool.write(chunk)
                total += len(chunk)
                if hooks is not None:
                    hooks.received(total, expected_size if expected_size is not None
                                   else progress_total)
        if expected_size is not None and total != expected_size:
            raise OSError(f"{what}: received {total} bytes, the server announced {expected_size}")
        spool.seek(0)
    except BaseException:
        spool.close()
        raise
    return spool


def spool_response(response, *, what: str = "read") -> IO[bytes]:
    """A streamed ``requests`` response body as a spool (or, for a
    sequential reader, as it arrives); the response is closed either way.
    urllib3 still checks the body against its Content-Length."""
    expected = None
    try:
        expected = int(response.headers.get("Content-Length"))
    except (AttributeError, TypeError, ValueError):
        pass
    return spool_chunks(
        response.iter_content(READ_CHUNK),
        what=what,
        expected_size=None,
        progress_total=expected,
        close=response.close,
    )
