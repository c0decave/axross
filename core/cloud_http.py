"""What the cloud backends (Google Drive, OneDrive, Dropbox, Azure Blob and
Files) share about failed requests: typed errors and bounded retries.

Typed errors. Every public method of a cloud backend raises an
:class:`OSError` subclass with an errno, never the SDK's own exception
(googleapiclient ``HttpError``, dropbox ``ApiError``, azure
``HttpResponseError``) and never an errno-less ``OSError``: callers catch
``OSError`` (the editor's "Cannot save file" dialog, atomic_write, trash,
MCP and scripting verbs), :func:`core.server_ops._is_destination_exists_error`
reads ``FileExistsError``, and a FUSE mount hands the errno to the kernel -
a throttled stat() answered as ENOENT made the kernel create the file anew
over the existing one. :func:`errno_for_status` maps an HTTP status,
:func:`oserror` builds the subclass Python picks for the errno
(``FileNotFoundError`` for ENOENT, ``PermissionError`` for EACCES ...).

Retries. A 429 or 5xx answer is what the services document as "try again
later", often with a ``Retry-After`` header. :func:`pause` waits before
the next attempt: exponential backoff with jitter, or the server's
Retry-After, capped so that a hostile or broken header cannot park a
transfer (and its Cancel) for minutes. :data:`ATTEMPTS` bounds the tries.
"""

from __future__ import annotations

import errno
import email.utils
import random
import time
from datetime import datetime, timezone

#: Tries of one request, the first included.
ATTEMPTS = 5
#: The first backoff pause; doubled per retry, at most MAX_DELAY.
BASE_DELAY = 0.5
MAX_DELAY = 8.0
#: A server's Retry-After is honoured up to this many seconds.
RETRY_AFTER_CAP = 30.0

#: Statuses that say "not processed, try again" (or a gateway lost the
#: answer). 501 / 505 are final.
RETRYABLE_STATUSES = frozenset({408, 429, 500, 502, 503, 504})

#: Replaced by the tests: the pause between two attempts.
_sleep = time.sleep


def errno_for_status(status: int | None) -> int:
    """The errno an HTTP error status stands for; EIO when unknown."""
    if status is None:
        return errno.EIO
    if status in (404, 410):
        return errno.ENOENT
    if status in (401, 403):
        return errno.EACCES
    if status == 409:
        return errno.EEXIST
    if status == 412:
        return errno.ESTALE
    if status == 413:
        return errno.EFBIG
    if status == 423:
        return errno.EBUSY
    if status in (429, 503):
        return errno.EAGAIN
    if status in (408, 504):
        return errno.ETIMEDOUT
    if status == 507:
        return errno.ENOSPC
    if status in (400, 405, 411, 414, 416, 422):
        return errno.EINVAL
    return errno.EIO


def oserror(err: int, message: str, filename: str | None = None) -> OSError:
    """``OSError(err, message[, filename])``: Python makes it the subclass
    of the errno (ENOENT -> FileNotFoundError, EEXIST -> FileExistsError,
    EACCES -> PermissionError, EISDIR -> IsADirectoryError ...)."""
    if filename is None:
        return OSError(err, message)
    return OSError(err, message, filename)


def status_oserror(status: int | None, message: str, filename: str | None = None) -> OSError:
    """The typed OSError of an HTTP error *status*."""
    return oserror(errno_for_status(status), message, filename)


def retry_after_seconds(value) -> float | None:
    """A ``Retry-After`` header value in seconds (delta-seconds or an
    HTTP date), capped at RETRY_AFTER_CAP; None when absent or garbage."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        seconds = float(text)
    except ValueError:
        try:
            when = email.utils.parsedate_to_datetime(text)
        except (TypeError, ValueError, IndexError):
            return None
        if when is None:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        seconds = (when - datetime.now(timezone.utc)).total_seconds()
    if seconds != seconds:  # NaN
        return None
    return min(max(seconds, 0.0), RETRY_AFTER_CAP)


def delay(attempt: int, retry_after: float | None = None) -> float:
    """Seconds to wait before retry number *attempt* (1 = the first
    retry): the server's Retry-After when it gave one, else exponential
    backoff with jitter."""
    if retry_after is not None:
        return min(max(retry_after, 0.0), RETRY_AFTER_CAP)
    base = min(BASE_DELAY * (2 ** max(attempt - 1, 0)), MAX_DELAY)
    return base / 2 + random.random() * base / 2


def pause(attempt: int, retry_after: float | None = None) -> None:
    """Wait before retry number *attempt* (see :func:`delay`)."""
    _sleep(delay(attempt, retry_after))


def rewrap(exc: BaseException, message: str, filename: str | None = None) -> OSError:
    """*message* as an OSError of *exc*'s errno (a typed error keeps its
    type under the new message); EIO when *exc* carries none."""
    err = getattr(exc, "errno", None) if isinstance(exc, OSError) else None
    if not isinstance(err, int) or not err:
        err = errno.EIO
    if filename is None and isinstance(exc, OSError):
        filename = exc.filename
    return oserror(err, message, filename)


def reason(exc: BaseException) -> str:
    """The text of *exc* without the "[Errno N]" an OSError puts first."""
    if isinstance(exc, OSError) and exc.strerror:
        return str(exc.strerror)
    return str(exc)


def no_file_as_folder(path: str, item):
    """*item* (the stat of *path*); NotADirectoryError when *path* ends in
    "/" and names a FILE - stat(2) of "file/" is ENOTDIR, and a backend
    whose path handling drops the slash answered with the file."""
    if path.endswith("/") and path.strip("/") and not item.is_dir:
        raise NotADirectoryError(errno.ENOTDIR, "Not a directory", path)
    return item
