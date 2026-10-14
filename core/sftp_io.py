"""Pipelined SFTP reads (bounded, adaptive read-ahead) and writes (every
acknowledgement checked).

paramiko sends one READ of at most 32 KiB and waits for its answer before
the next, so a plain download moves 32 KiB per round trip (~1.6 MB/s at
20 ms, however fast the link). paramiko's own ``prefetch()`` fixes the
latency but buffers every received chunk until it is read — the whole file
when the consumer is slower than the network — and looks chunks up with a
linear scan.

:class:`ReadAheadRaw` keeps both bounded: once reads are sequential it asks
for a window of requests at once (``readv``), the window doubling from
:attr:`MIN_WINDOW` to :attr:`MAX_WINDOW`; a seek drops back to plain,
request-sized reads, so random access (archive previews, hex views) does
not pull megabytes it never uses. Wrapped in :class:`io.BufferedReader`
it offers the full binary-file interface.
"""

from __future__ import annotations

import io
import os


class ReadAheadRaw(io.RawIOBase):
    REQUEST = 32 * 1024  # paramiko's MAX_REQUEST_SIZE
    MIN_WINDOW = 256 * 1024
    MAX_WINDOW = 8 * 1024 * 1024

    def __init__(self, opener) -> None:
        """*opener* returns a fresh paramiko ``SFTPFile`` for the path; it is
        called once now and again if a handle has to be replaced."""
        super().__init__()
        self._f = None
        self._opener = opener
        self._f = opener()
        self._pos = 0
        self._buf = b""
        self._buf_start = 0
        self._seq_end = 0  # where a sequential read would continue
        self._window = 0
        self._size: int | None = None

    # -- io.RawIOBase ---------------------------------------------------
    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            pos = offset
        elif whence == os.SEEK_CUR:
            pos = self._pos + offset
        elif whence == os.SEEK_END:
            pos = self._remote_size(refresh=True) + offset
        else:
            raise ValueError(f"invalid whence {whence!r}")
        if pos < 0:
            raise OSError("negative seek position")
        self._pos = pos
        return pos

    def readinto(self, b) -> int:
        n = len(b)
        if n == 0:
            return 0
        data = self._read(n)
        b[: len(data)] = data
        return len(data)

    def close(self) -> None:
        if not self.closed:
            self._buf = b""
            try:
                if self._f is not None:
                    self._f.close()
            finally:
                super().close()

    # -- internals ------------------------------------------------------
    def _remote_size(self, refresh: bool = False) -> int:
        if self._size is None or refresh:
            self._size = int(self._f.stat().st_size or 0)
        return self._size

    def _from_buffer(self, n: int) -> bytes | None:
        off = self._pos - self._buf_start
        if 0 <= off < len(self._buf):
            data = self._buf[off : off + n]
            self._pos += len(data)
            return data
        return None

    def _read(self, n: int) -> bytes:
        hit = self._from_buffer(n)
        if hit is not None:
            return hit
        if self._pos == self._seq_end:
            self._window = min(max(self._window * 2, self.MIN_WINDOW), self.MAX_WINDOW)
        else:
            self._window = 0
        self._buf = b""
        if self._window > n:
            end = min(self._pos + self._window, self._remote_size())
            if end > self._pos:
                self._fill(end)
                hit = self._from_buffer(n)
                if hit is not None:
                    return hit
        # Random access, the tail past the size we know (the file grew),
        # or a window that came back empty: one plain read.
        self._f.seek(self._pos)
        data = self._f.read(n)
        self._pos += len(data)
        self._seq_end = self._pos
        return data

    def _fill(self, end: int) -> None:
        chunks = [(o, min(self.REQUEST, end - o)) for o in range(self._pos, end, self.REQUEST)]
        try:
            data = b"".join(self._f.readv(chunks))
        except EOFError:
            data = b""
        if len(data) < end - self._pos:
            # The file shrank since its size was read. paramiko answers the
            # requests past the new end with a quiet short read but never
            # clears them from its prefetch bookkeeping (sftp_file.py,
            # _async_response), so the next read on this handle would wait
            # forever. Keep what arrived, replace the handle; plain reads
            # then find the new end.
            self._replace_handle()
        self._buf, self._buf_start = data, self._pos
        self._seq_end = self._pos + len(data)

    def _replace_handle(self) -> None:
        old, self._f = self._f, self._opener()
        self._size = None
        try:
            old.close()
        except Exception:  # noqa: BLE001 - the old handle is being discarded
            pass


def open_read_ahead(opener) -> io.BufferedReader:
    """Binary read handle with pipelined read-ahead; *opener* returns a new
    paramiko ``SFTPFile`` for the path."""
    return io.BufferedReader(ReadAheadRaw(opener), buffer_size=64 * 1024)


class _WriteAcks:
    """Receives the status answers to our WRITE requests.

    paramiko's own pipelined writes register ``type(None)`` as receiver, so
    an answer read by any other request on the connection is dropped, and
    ``close()`` never waits for the rest: a failed WRITE goes unnoticed. A
    receiver object (paramiko's prefetch does the same) gets every answer,
    whoever reads it from the socket."""

    def __init__(self) -> None:
        self.error: Exception | None = None

    def _async_response(self, t, msg, num) -> None:
        from paramiko.sftp import CMD_STATUS, SFTPError

        try:
            if t != CMD_STATUS:
                raise SFTPError("expected a status answer to WRITE")
            self._sftp._convert_status(msg)
        except Exception as exc:  # noqa: BLE001 - kept, raised by the writer
            if self.error is None:
                self.error = exc


class PipelinedWriter(io.RawIOBase):
    """Sends WRITEs without waiting for each answer (one round trip per
    32 KiB otherwise), at most :attr:`MAX_IN_FLIGHT` at a time, and checks
    every answer: a failure is raised by the next ``write``, ``flush`` or
    ``close`` — never lost."""

    REQUEST = 32 * 1024
    MAX_IN_FLIGHT = 64  # 2 MiB on the wire

    def __init__(self, sftp_file, *, append: bool = False) -> None:
        super().__init__()
        self._f = sftp_file
        self._sftp = sftp_file.sftp
        self._acks = _WriteAcks()
        self._acks._sftp = self._sftp
        self._pos = int(sftp_file.stat().st_size or 0) if append else 0

    def writable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def write(self, data) -> int:
        from paramiko.sftp import CMD_WRITE, int64

        self._raise_failure()
        view = memoryview(data)
        for start in range(0, len(view), self.REQUEST):
            chunk = bytes(view[start : start + self.REQUEST])
            self._sftp._async_request(
                self._acks, CMD_WRITE, self._f.handle, int64(self._pos), chunk
            )
            self._pos += len(chunk)
            while self._in_flight() > self.MAX_IN_FLIGHT:
                self._sftp._read_response()
                self._raise_failure()
        return len(view)

    def flush(self) -> None:
        """Wait until every WRITE is answered; raise the first failure."""
        if self.closed:
            return
        while self._in_flight():
            self._sftp._read_response()
        self._raise_failure()

    def close(self) -> None:
        if self.closed:
            return
        try:
            self.flush()
        finally:
            try:
                self._f.close()
            finally:
                super().close()

    def _in_flight(self) -> int:
        acks = self._acks
        return sum(1 for owner in list(self._sftp._expecting.values()) if owner is acks)

    def _raise_failure(self) -> None:
        if self._acks.error is not None:
            raise OSError(f"SFTP write failed: {self._acks.error}") from self._acks.error
