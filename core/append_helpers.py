"""Shared helpers for read-modify-write append implementations."""

from __future__ import annotations

import errno
import logging
import re
from typing import IO, Callable

_APPEND_READ_CHUNK = 1024 * 1024


# "404" as a status of its own: not inside a request id ("7c1e4049") or
# a token such as "id-404a". A hyphen counts as part of the token.
_STATUS_404 = re.compile(r"(?<![\w-])404(?![\w-])")
# "no such" only for the thing an append reads - never "No such host".
_NO_SUCH_ENTRY = re.compile(r"\bno such (file|key|object|path|blob|directory)\b")
# A message naming a transient condition is never "absent", whatever
# else it contains: starting from an empty buffer would upload only the
# new bytes over the object.
_TRANSIENT_STATUS = re.compile(r"(?<![\w-])(408|429|500|502|503|504)(?![\w-])")
_TRANSIENT_WORDS = (
    "busy",
    "throttl",
    "slow down",
    "slowdown",
    "rate limit",
    "too many requests",
    "timed out",
    "timeout",
    "temporar",
    "try again",
    "retry",
    "unavailable",
    "connection reset",
    "connection refused",
    "connection aborted",
    "no such host",
    "host not found",
    "unknown host",
    "name resolution",
    "name or service not known",
    "nodename nor servname",
    "getaddrinfo",
)


def _looks_not_found(exc: BaseException, path: str = "") -> bool:
    if isinstance(exc, FileNotFoundError) or getattr(exc, "errno", None) == errno.ENOENT:
        return True
    text = str(exc)
    # The messages carry the path: "Cannot read /site/404.html: Access
    # Denied" must not read as "404" because of the object's name.
    for form in sorted({path, path.lstrip("/")}, key=len, reverse=True):
        if form:
            text = text.replace(form, "")
    text = text.lower()
    if _TRANSIENT_STATUS.search(text) or any(word in text for word in _TRANSIENT_WORDS):
        return False
    return (
        "not found" in text
        or "not_found" in text
        or "nosuchkey" in text
        or _NO_SUCH_ENTRY.search(text) is not None
        or _STATUS_404.search(text) is not None
    )


def read_existing_for_append(
    *,
    open_read: Callable[[str], IO[bytes]],
    stat: Callable[[str], object],
    path: str,
    cap: int,
    label: str,
    logger: logging.Logger,
) -> bytes:
    """Return existing bytes for append, or ``b""`` when the file is absent.

    Object/cloud backends emulate append by downloading the old object,
    concatenating bytes locally, then uploading the whole object again.
    If the download fails for an object that exists, continuing with an
    empty buffer would silently truncate user data.
    """
    if cap < 0:
        raise ValueError("cap must be >= 0")
    try:
        handle = open_read(path)
        try:
            chunks: list[bytes] = []
            remaining = cap + 1
            while remaining > 0:
                chunk = handle.read(min(_APPEND_READ_CHUNK, remaining))
                if not chunk:
                    break
                if len(chunk) > remaining:
                    chunk = chunk[:remaining]
                chunks.append(chunk)
                remaining -= len(chunk)
            return b"".join(chunks)
        finally:
            handle.close()
    except OSError as read_exc:
        try:
            stat(path)
        except OSError as stat_exc:
            if _looks_not_found(read_exc, path) or _looks_not_found(stat_exc, path):
                return b""
            raise OSError(
                f"{label} append: cannot verify existing object state for {path}: {stat_exc}"
            ) from read_exc

        logger.warning(
            "%s append: refusing to overwrite %s; could not read existing content (%s)",
            label,
            path,
            read_exc,
        )
        raise OSError(
            f"{label} append: refusing to overwrite {path}; could not "
            f"read existing content ({read_exc})"
        ) from read_exc
