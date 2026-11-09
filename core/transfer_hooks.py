"""Cancel and progress of one transfer, for the network I/O a backend does
outside the transfer engine's copy loop.

The copy loop (core.transfer_worker) checks Cancel and counts bytes per
chunk it moves from ``open_read()`` to ``open_write()``. Many backends do
their real network transfer elsewhere:

* a spooling writer (OneDrive, Google Drive, Dropbox, S3, Azure, WebDAV,
  FTP, SCP, Telnet, IMAP) only buffers in ``write()`` and uploads in
  ``close()``;
* a downloading reader (OneDrive, Google Drive, Dropbox, S3, Azure,
  WebDAV, SCP) fetches the whole file inside ``open_read()``.

Without help the bar reached 100 % at disk speed, then the real upload ran
to its end whatever Cancel said. While a job runs, the engine makes a
:class:`TransferHooks` current (:func:`active`); a writer takes it when it
is made (:func:`current`) and keeps it for its ``close()``, a reader uses
it while ``open_read()`` downloads. Between chunks they call
:meth:`TransferHooks.check` (raises :class:`InterruptedError` once Cancel
was pressed) and report the network bytes with :meth:`TransferHooks.sent`
/ :meth:`TransferHooks.received`.

Nothing changes for code that does not know this module: without a
current hooks object every helper here does nothing, so the FileBackend
API, scripts and backends that ignore it work as before.

A writer whose ``close()`` was cancelled before it committed anything
raises :class:`UploadCancelled`: the destination is as it was (an upload
session that was never finished, an aborted multipart upload, uncommitted
Azure blocks). A writer that may have left part of the file behind (FTP
STOR, SCP, WebDAV PUT, Azure Files ranges) raises a plain
InterruptedError, and the engine rolls the destination back as after any
failed direct write.
"""

from __future__ import annotations

import contextlib
import contextvars
import threading
import time
from collections.abc import Callable, Iterator

#: The text of the InterruptedError a cancelled transfer raises (the
#: engine's own copy loop uses the same).
CANCELLED = "Transfer cancelled"


class UploadCancelled(InterruptedError):
    """``close()`` of a writer was cancelled before anything was
    committed: the destination is untouched."""


class TransferHooks:
    """Cancel and progress of one running transfer.

    *cancel_event*: a ``threading.Event`` set by Cancel. *progress*:
    ``progress(kind, done, total)`` with kind "upload" or "download",
    *done* the bytes moved over the network in this phase so far and
    *total* the bytes the phase will move (None when unknown); it may
    raise InterruptedError itself.
    """

    def __init__(
        self,
        cancel_event: threading.Event | None = None,
        progress: Callable[[str, int, int | None], None] | None = None,
    ) -> None:
        self.cancel_event = cancel_event
        self._progress = progress
        #: Set by a writer that will upload in close() (expect_upload):
        #: the engine counts that upload as a phase of the job.
        self.upload_expected = False
        #: Set once a reader reported a download of its own.
        self.downloaded = False

    def cancelled(self) -> bool:
        event = self.cancel_event
        return event is not None and event.is_set()

    def check(self) -> None:
        """InterruptedError when Cancel was pressed."""
        if self.cancelled():
            raise InterruptedError(CANCELLED)

    def wait(self, seconds: float) -> None:
        """Sleep *seconds*, waking at once on Cancel (InterruptedError)."""
        event = self.cancel_event
        if event is None:
            time.sleep(max(seconds, 0.0))
            return
        if event.wait(max(seconds, 0.0)):
            raise InterruptedError(CANCELLED)

    def expect_upload(self) -> None:
        """Called by a writer that uploads in ``close()``."""
        self.upload_expected = True

    def sent(self, done: int, total: int | None = None, *, check: bool = True) -> None:
        """*done* bytes of the upload are on the server; checks Cancel
        first unless *check* is False (the report after the commit: a
        Cancel then comes too late to undo anything)."""
        if check:
            self.check()
        if self._progress is not None:
            self._progress("upload", done, total)

    def received(self, done: int, total: int | None = None) -> None:
        """*done* bytes of the download arrived; checks Cancel."""
        self.check()
        self.downloaded = True
        if self._progress is not None:
            self._progress("download", done, total)


_CURRENT: contextvars.ContextVar[TransferHooks | None] = contextvars.ContextVar(
    "axross_transfer_hooks", default=None
)


def current() -> TransferHooks | None:
    """The hooks of the transfer running in this thread, or None."""
    return _CURRENT.get()


@contextlib.contextmanager
def active(hooks: TransferHooks | None) -> Iterator[TransferHooks | None]:
    """Make *hooks* current for the ``with`` body (None: no hooks - a
    rollback after Cancel must not be cancelled itself)."""
    token = _CURRENT.set(hooks)
    try:
        yield hooks
    finally:
        _CURRENT.reset(token)


@contextlib.contextmanager
def bound(hooks: TransferHooks | None) -> Iterator[TransferHooks | None]:
    """*hooks* current for the body when given; else whatever is current
    stays (a writer's close() re-enters the hooks it was made under, so
    the retry pauses of its upload wake on Cancel too)."""
    if hooks is None:
        yield current()
        return
    with active(hooks) as h:
        yield h


def check(hooks: TransferHooks | None = None) -> None:
    """InterruptedError when the transfer of *hooks* (default: the current
    one) was cancelled; nothing without one."""
    hooks = hooks if hooks is not None else current()
    if hooks is not None:
        hooks.check()


def wait(seconds: float) -> None:
    """Sleep *seconds*; with a current transfer, wake on its Cancel
    (InterruptedError)."""
    hooks = current()
    if hooks is None:
        time.sleep(max(seconds, 0.0))
    else:
        hooks.wait(seconds)


class ReadProgress:
    """A binary file read by an upload (requests, ftplib, an SSH channel):
    every ``read()`` checks Cancel first and reports the bytes handed out
    as sent. ``seek``/``tell`` pass through, so a library that sizes the
    body (requests' ``super_len``) or rewinds it for a retry still can.
    """

    def __init__(self, raw, hooks: TransferHooks | None, total: int | None = None) -> None:
        self._raw = raw
        self._hooks = hooks
        self._total = total
        self._sent = 0

    def read(self, n: int = -1) -> bytes:
        if self._hooks is not None:
            self._hooks.check()
        data = self._raw.read(n)
        if self._hooks is not None and data:
            position = self._raw.tell()
            self._sent = max(self._sent, position)
            self._hooks.sent(self._sent, self._total)
        return data

    def seek(self, pos: int, whence: int = 0) -> int:
        return self._raw.seek(pos, whence)

    def tell(self) -> int:
        return self._raw.tell()

    def __len__(self) -> int:
        """The bytes left to read (what requests sends as Content-Length)."""
        here = self._raw.tell()
        end = self._raw.seek(0, 2)
        self._raw.seek(here)
        return end - here

    def __iter__(self):
        """Pieces of 64 KiB (requests streams an iterable body chunked)."""
        return iter(lambda: self.read(64 * 1024), b"")


class WriteProgress:
    """A spool a download writes into: every ``write()`` checks Cancel and
    reports the bytes received so far."""

    def __init__(self, raw, hooks: TransferHooks | None, total: int | None = None) -> None:
        self._raw = raw
        self._hooks = hooks
        self._total = total
        self._received = 0

    def write(self, data: bytes) -> int:
        if self._hooks is not None:
            self._hooks.check()
        written = self._raw.write(data)
        self._received += len(data)
        if self._hooks is not None:
            self._hooks.received(self._received, self._total)
        return written
