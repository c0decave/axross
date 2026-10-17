"""A download as a spooled file instead of one bytes object in RAM.

Backends whose open_read must fetch a file before returning it (FTP,
S3, Azure, WebDAV) collected the whole body in an io.BytesIO: a 4 GiB
file needed 4 GiB of RAM. A SpooledTemporaryFile keeps small files in
memory and moves larger ones to a temp file, like SCP's read already
does; the result stays a seekable IO[bytes].
"""

from __future__ import annotations

import tempfile
from collections.abc import Iterable, Iterator
from typing import IO

#: Bytes a spool keeps in memory before it rolls over to a temp file.
READ_SPOOL_MAX = 8 * 1024 * 1024
#: Bytes asked for per read() from a file-like download body.
READ_CHUNK = 1024 * 1024


def new_read_spool() -> IO[bytes]:
    """An empty spool for a download that pushes its chunks (FTP)."""
    return tempfile.SpooledTemporaryFile(max_size=READ_SPOOL_MAX)


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
) -> IO[bytes]:
    """Write *chunks* to a new spool and return it at position 0.

    With *expected_size* a download that is shorter or longer than the
    server announced is an OSError. The spool is closed on any error.
    """
    spool = new_read_spool()
    total = 0
    try:
        for chunk in chunks:
            if chunk:
                spool.write(chunk)
                total += len(chunk)
        if expected_size is not None and total != expected_size:
            raise OSError(f"{what}: received {total} bytes, the server announced {expected_size}")
        spool.seek(0)
    except BaseException:
        spool.close()
        raise
    return spool


def spool_response(response, *, what: str = "read") -> IO[bytes]:
    """A streamed ``requests`` response body as a spool; the response is
    closed either way. urllib3 still checks the body against its
    Content-Length."""
    try:
        return spool_chunks(response.iter_content(READ_CHUNK), what=what)
    finally:
        response.close()
