"""Phase 6a — expose any :class:`FileBackend` as a FUSE mount.

Wires fusepy on top of the backend protocol so third-party tools
(text editors, ``grep``, ``rsync`` from a different machine) can read
and optionally write files over the same connection axross holds,
without each tool having to know SFTP / S3 / WebDAV.

Read-only by default; writeable opt-in
--------------------------------------
:func:`mount` takes ``writeable=False`` by default — safer to point
a mount at a production bucket without an "oops" risk. Passing
``writeable=True`` enables create / write / truncate / unlink /
mkdir / rmdir / rename. The writeable path buffers file writes in a
per-handle tempfile and commits it to the backend on ``flush`` (= every
kernel-side ``close``, whose result the writer sees) and ``fsync``.
That matches how most remote backends think about mutation:
whole-file overwrite, not random-access edits. S3
has no in-place writes; IMAP has no rename; FTP can't truncate. The
temp-file-at-close strategy keeps us out of per-protocol contracts
we'd have to bend.

Rename fallback
---------------
``backend.rename`` is supported on most Linux-ish backends (local,
SFTP, SMB). S3 / IMAP / a few others raise OSError. The writeable
adapter falls back to ``backend.copy + backend.remove`` in that
case — slower but lets the kernel see the rename succeed.

Per-backend TTL cache
---------------------
Every operation on a remote backend is a network round-trip. ``ls``
on a FUSE-mounted SFTP would issue a ``list_dir`` for every entry
the kernel re-stats — a few hundred per ``ls -l``. We cache:

* directory listings (``readdir`` results)  — TTL_LISTING seconds
* per-entry stat metadata (size / mode / mtime) — TTL_STAT seconds
* file content is NOT cached; the kernel page cache already does
  that, and a FUSE-level cache would just double the RAM cost.

TTLs default to 30 seconds. Fresh enough for interactive work,
cheap enough to make ``find /mnt | xargs grep`` actually finish.

Optional dependency
-------------------
``fusepy`` (Linux/macOS) is optional. :func:`is_available` returns
False when the package isn't installed; the UI hides the
"Mount as FUSE" action accordingly. The library never raises at
import time so the rest of axross stays usable on systems without
FUSE.
"""

from __future__ import annotations

import contextlib
import errno
import logging
import os
import posixpath
import signal
import stat as stat_mod
import threading
import time
from dataclasses import dataclass, field

from core.subprocess_env import clean_child_env

log = logging.getLogger(__name__)


try:  # pragma: no cover — optional dep
    from fuse import FUSE, FuseOSError, Operations  # type: ignore

    FUSE_AVAILABLE = True
except ImportError:  # pragma: no cover — optional dep
    FUSE = None  # type: ignore[assignment]

    class FuseOSError(OSError):  # type: ignore[no-redef]
        """Stand-in for fusepy's FuseOSError on systems without the
        library. The real class forwards ``errno`` + ``strerror`` to
        OSError's two-arg form; a plain ``FuseOSError = OSError``
        alias would turn ``FuseOSError(errno.EIO)`` into
        ``OSError(5)`` — the ``5`` becomes the message and ``.errno``
        stays None, which silently breaks any test that asserts on
        the error code.
        """

        def __init__(self, code: int) -> None:
            super().__init__(code, os.strerror(code))

    Operations = object  # type: ignore[assignment,misc]
    FUSE_AVAILABLE = False


# --------------------------------------------------------------------------
# Cache helpers
# --------------------------------------------------------------------------

TTL_LISTING_DEFAULT = 30.0
TTL_STAT_DEFAULT = 30.0

# Hard cap on the read-and-discard fallback used when a backend's
# IO handle has no seek(). Without it, a kernel client requesting
# offset 900 MiB into a 1 GiB SFTP file would burn 900 MiB of network
# transfer per call. Cap at 128 MiB; beyond that we EIO so the kernel
# stops asking.
MAX_FALLBACK_DISCARD = 128 * 1024 * 1024


@dataclass
class _CacheSlot:
    value: object
    expires_at: float


class _TTLCache:
    """Tiny per-backend cache. Thread-safe (FUSE callbacks are
    issued from libfuse worker threads)."""

    def __init__(self, ttl: float) -> None:
        self._ttl = max(0.0, float(ttl))
        self._slots: dict[str, _CacheSlot] = {}
        self._lock = threading.Lock()

    def get(self, key: str):
        if self._ttl <= 0:
            return None
        with self._lock:
            slot = self._slots.get(key)
            if slot is None:
                return None
            if slot.expires_at < time.time():
                self._slots.pop(key, None)
                return None
            return slot.value

    def put(self, key: str, value) -> None:
        if self._ttl <= 0:
            return
        with self._lock:
            self._slots[key] = _CacheSlot(
                value=value,
                expires_at=time.time() + self._ttl,
            )

    def invalidate_all(self) -> None:
        with self._lock:
            self._slots.clear()


# --------------------------------------------------------------------------
# Path conversion
# --------------------------------------------------------------------------


def _to_backend_path(rel: str, root: str) -> str:
    """Translate a kernel-supplied path (always starts with ``/``)
    into a backend path under *root*."""
    rel = (rel or "/").lstrip("/")
    if not rel:
        return root
    if root.endswith("/"):
        return root + rel
    return f"{root}/{rel}"


# --------------------------------------------------------------------------
# Operations adapter
# --------------------------------------------------------------------------


@dataclass
class _WriteSession:
    """Per-open-file state for writeable mounts.

    Two modes:

    * ``mode == "buffer"`` — default. Writes land in ``tmp`` (a
      NamedTemporaryFile) as the kernel chunks them in; on
      ``flush`` / ``fsync`` the whole tempfile is streamed to
      ``backend.open_write`` at once. Works for any write pattern
      (random-access edits, partial overwrites, editors) at the
      cost of needing local disk space equal to the file size.

    * ``mode == "stream"`` — opt-in via mount(write_mode="stream").
      Writes flow directly into an always-open ``stream_handle`` on
      the backend as sequential chunks, skipping the tempfile
      entirely. ``expected_offset`` tracks where the next append
      must land; any out-of-order write raises EIO. Only safe for
      fresh files (O_CREAT / O_TRUNC) — opens of existing files
      silently fall back to buffer mode for that one session.

    ``dirty=False`` means the backend already holds the buffer:
    nothing was written since the open (pre-fetched content) or since
    the last successful commit — flush can skip the backend.

    ``errored=True`` is a sticky flag for stream sessions: once we've
    reported a write failure (out-of-order offset, backend refused a
    chunk or the commit) every later write and flush returns EIO, so
    an earlier EIO isn't silently lost.
    """

    path: str
    tmp: object
    dirty: bool = False
    mode: str = "buffer"
    stream_handle: object | None = None
    expected_offset: int = 0
    errored: bool = False
    #: A flush() / fsync() already returned this session's commit failure
    #: to the writer: release() then cleans up without repeating it.
    failure_reported: bool = False


@dataclass
class _SessionItem:
    """The stat fields of a file open for writing, in the shape
    :func:`_stat_dict` reads; ``modified=None`` means "now"."""

    size: int
    is_dir: bool = False
    modified: object = None


@dataclass
class _ReadSession:
    """Per-open-file state for read-only opens: one backend handle,
    opened on the first read and kept until release. ``pos`` is where
    the next read() on ``handle`` continues; sequential kernel reads
    use it as is, others seek (or reopen when the handle cannot)."""

    path: str
    full: str
    handle: object | None = None
    pos: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)


class BackendFuseFS(Operations):  # type: ignore[misc]
    """fusepy adapter that proxies into a FileBackend.

    Writeable when ``writeable=True``. The mutation methods then
    buffer per-handle to a tempfile and commit on flush; dir ops
    (mkdir / rmdir / unlink / rename) go through to the backend
    directly.

    When fusepy isn't installed, ``Operations`` aliases to ``object``
    and ``FuseOSError`` to ``OSError`` — the class definition still
    works, so tests can exercise the adapter logic without the
    kernel module. Real mounts go through :func:`mount`, which
    guards on :attr:`FUSE_AVAILABLE` first."""

    def __init__(
        self,
        backend,
        root: str,
        *,
        ttl_listing: float = TTL_LISTING_DEFAULT,
        ttl_stat: float = TTL_STAT_DEFAULT,
        writeable: bool = False,
        write_mode: str = "buffer",
    ) -> None:
        self.backend = backend
        self.root = root
        self._listing = _TTLCache(ttl_listing)
        self._stat = _TTLCache(ttl_stat)
        self.writeable = bool(writeable)
        if write_mode not in ("buffer", "stream"):
            raise ValueError(
                f"write_mode must be 'buffer' or 'stream'; got {write_mode!r}",
            )
        # Streaming writes flow directly into backend.open_write per
        # session. Fast and cheap on tempfile space for big sequential
        # copies (cp, rsync, tar -x), but any non-sequential write
        # raises EIO. The per-session fallback keeps editor opens
        # working by reverting to buffer mode for those specific
        # opens even on a stream-mode mount.
        self.write_mode = write_mode
        # fh → _WriteSession for per-open write buffering. Only
        # populated on writeable mounts.
        self._writes: dict[int, _WriteSession] = {}
        # fh → _ReadSession for read-only opens.
        self._reads: dict[int, _ReadSession] = {}
        self._fh_counter = 1_000_000
        self._fh_lock = threading.Lock()

    # ---- lookup / stat -------------------------------------------------
    def access(self, path, mode):
        if mode & os.W_OK and not self.writeable:
            raise FuseOSError(errno.EROFS)
        return 0

    def getattr(self, path, fh=None):
        # While a file is open for writing, the session -- not the
        # backend -- holds its content until the next commit: a created
        # file is not on the backend yet, an appended one is longer
        # there. Answering from the backend made create() fail with
        # ENOENT and let the kernel shrink i_size under an O_APPEND
        # writer, whose next write then overwrote the earlier ones.
        session = self._write_session_for(path, fh)
        if session is not None:
            return self._session_stat(session)
        return _stat_for(self, path, writeable=self.writeable)

    def _write_session_for(self, path, fh) -> _WriteSession | None:
        """The write session that speaks for *path*: the one behind *fh*
        when it is one, else the most recently opened one on *path*."""
        if fh is not None:
            session = self._writes.get(fh)
            if session is not None and session.path == path:
                return session
        newest = None
        for key, session in list(self._writes.items()):
            if session.path == path and (newest is None or key > newest[0]):
                newest = (key, session)
        return newest[1] if newest is not None else None

    def _session_stat(self, session: _WriteSession) -> dict:
        if session.mode == "stream":
            size = session.expected_offset
        else:
            session.tmp.flush()
            size = os.fstat(session.tmp.fileno()).st_size
        item = _SessionItem(size=size)
        return _stat_dict(item, writeable=self.writeable)

    # ---- directory ----------------------------------------------------
    def readdir(self, path, fh):
        yield "."
        yield ".."
        cached = self._listing.get(path)
        if cached is not None:
            names = cached
        else:
            full = _to_backend_path(path, self.root)
            try:
                items = self.backend.list_dir(full)
            except OSError as exc:
                log.debug("readdir(%s) failed: %s", full, exc)
                raise FuseOSError(errno.EIO)
            names = [
                getattr(it, "name", "")
                for it in items
                if getattr(it, "name", "") and getattr(it, "name", "") not in (".", "..")
            ]
            self._listing.put(path, names)
            # Pre-warm the per-entry stat cache from the same listing
            # so a subsequent getattr() doesn't re-fetch each row.
            for it in items:
                name = getattr(it, "name", "")
                if not name or name in (".", ".."):
                    continue
                if getattr(it, "is_link", False) is True:
                    continue  # getattr follows it to the target
                self._stat.put(
                    _join(path, name),
                    _stat_dict(it, writeable=self.writeable),
                )
        for n in names:
            yield n

    # ---- read ---------------------------------------------------------
    def read(self, path, size, offset, fh):
        # If the file is open for write, the authoritative bytes
        # live in the per-handle tempfile — read them from there
        # instead of round-tripping to the backend.
        session = self._writes.get(fh)
        if session is not None:
            if session.mode == "stream":
                # Streaming sessions have no readable buffer: the
                # bytes already went to the backend and aren't
                # recoverable mid-flight. Reads on a stream-write
                # fh are unusual (and mostly come from kernel
                # probing) — EIO is honest. User can open the same
                # file in a separate read-only fh to inspect the
                # committed content after release.
                log.debug(
                    "FUSE stream read(%s) on write fh — EIO",
                    session.path,
                )
                raise FuseOSError(errno.EIO)
            session.tmp.seek(offset)
            return session.tmp.read(size)
        full = _to_backend_path(path, self.root)
        reader = self._reads.get(fh)
        if reader is not None:
            with reader.lock:
                try:
                    return self._session_read(reader, size, offset)
                except FuseOSError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    # Drop the handle and answer this one read the way
                    # every read was answered before: a fresh open.
                    log.debug("FUSE read(%s) on held handle failed: %s", full, exc)
                    self._drop_read_handle(reader)
            return self._read_once(full, size, offset)
        return self._read_once(full, size, offset)

    def _open_for_read(self, full: str):
        try:
            return self.backend.open_read(full)
        except OSError as exc:
            log.debug("open_read(%s) failed: %s", full, exc)
            raise FuseOSError(errno.EIO)

    @staticmethod
    def _close_quietly(handle) -> None:
        try:
            handle.close()
        except Exception:
            pass

    def _refresh_readers(self, path: str) -> None:
        """After a commit to *path*, open read fhs on it reopen on their
        next read, so they see the new content as a per-read open did."""
        for reader in list(self._reads.values()):
            if reader.path == path:
                with reader.lock:
                    self._drop_read_handle(reader)

    def _drop_read_handle(self, reader: _ReadSession) -> None:
        handle, reader.handle, reader.pos = reader.handle, None, 0
        if handle is not None:
            self._close_quietly(handle)

    def _position(self, handle, full: str, offset: int) -> bool:
        """Move a handle at position 0 to *offset*. Returns False when
        the handle has no working seek() and the read+discard fallback
        ran instead (capped at MAX_FALLBACK_DISCARD: beyond that the
        network cost is ridiculous, so EIO makes the kernel stop)."""
        if hasattr(handle, "seek"):
            try:
                handle.seek(offset)
                return True
            except Exception:
                pass
        if offset:
            if offset > MAX_FALLBACK_DISCARD:
                log.warning(
                    "FUSE read: offset %d exceeds fallback cap %d for %s — returning EIO",
                    offset,
                    MAX_FALLBACK_DISCARD,
                    full,
                )
                raise FuseOSError(errno.EIO)
            discarded = 0
            while discarded < offset:
                chunk = handle.read(min(64 * 1024, offset - discarded))
                if not chunk:
                    break
                discarded += len(chunk)
        return False

    def _session_read(self, reader: _ReadSession, size: int, offset: int) -> bytes:
        handle = reader.handle
        if handle is not None and offset != reader.pos:
            moved = False
            if hasattr(handle, "seek"):
                try:
                    handle.seek(offset)
                    moved = True
                except Exception:
                    pass
            if moved:
                reader.pos = offset
            elif offset > reader.pos and offset - reader.pos <= MAX_FALLBACK_DISCARD:
                # Forward on a handle without seek: skip from here, not
                # from the start of the file.
                gap = offset - reader.pos
                while gap:
                    chunk = handle.read(min(64 * 1024, gap))
                    if not chunk:
                        break
                    gap -= len(chunk)
                reader.pos = offset - gap
                if gap:  # EOF before offset — same answer as a fresh open
                    return b""
            else:
                self._drop_read_handle(reader)
                handle = None
        if handle is None:
            handle = self._open_for_read(reader.full)
            try:
                self._position(handle, reader.full, offset)
            except BaseException:
                self._close_quietly(handle)
                raise
            reader.handle, reader.pos = handle, offset
        data = handle.read(size)
        reader.pos += len(data)
        return data

    def _read_once(self, full: str, size: int, offset: int) -> bytes:
        """One read on a handle opened for just this call."""
        handle = self._open_for_read(full)
        try:
            if self._position(handle, full, offset):
                try:
                    return handle.read(size)
                except Exception as exc:  # noqa: BLE001
                    # Seek worked, so the handle is no longer at 0: a
                    # discard fallback here would return the bytes at
                    # 2 * offset. Report the failure instead.
                    log.debug("FUSE read(%s) after seek failed: %s", full, exc)
                    raise FuseOSError(errno.EIO)
            return handle.read(size)
        finally:
            self._close_quietly(handle)

    # ---- mutation ------------------------------------------------------
    def _alloc_write_fh(self, session: _WriteSession) -> int:
        with self._fh_lock:
            fh = self._fh_counter
            self._fh_counter += 1
            self._writes[fh] = session
        return fh

    def _new_tempfile(self):
        import tempfile

        # delete=False so we control cleanup timing; FUSE release
        # happens on a libfuse worker thread and we want to own
        # the unlink rather than rely on the GC.
        return tempfile.NamedTemporaryFile(
            prefix=".axross-fuse-",
            delete=False,
        )

    def _may_exist(self, full: str) -> bool:
        """False only when the backend says *full* is not there."""
        try:
            return self.backend.exists(full) is not False
        except Exception:  # noqa: BLE001 - cannot rule it out
            return True

    @staticmethod
    def _discard_tempfile(tmp) -> None:
        try:
            tmp.close()
        except Exception:
            pass
        try:
            os.unlink(tmp.name)
        except Exception:
            pass

    def _open_stream_session(self, path: str) -> _WriteSession:
        """Open a backend write handle and wrap it in a streaming
        session. Raises FuseOSError(EIO) on backend failure so the
        caller — create()/open() — can propagate cleanly.

        Streaming sessions never allocate a tempfile; they hold the
        open ``backend.open_write`` handle until a flush commits it
        (close of the handle).
        """
        full = _to_backend_path(path, self.root)
        try:
            handle = self.backend.open_write(full)
        except OSError as exc:
            log.warning(
                "FUSE stream open_write(%s) failed: %s — caller will see EIO",
                full,
                exc,
            )
            raise FuseOSError(errno.EIO)
        return _WriteSession(
            path=path,
            tmp=None,
            dirty=True,
            mode="stream",
            stream_handle=handle,
            expected_offset=0,
        )

    def create(self, path, mode, fi=None):
        if not self.writeable:
            raise FuseOSError(errno.EROFS)
        if self.write_mode == "stream":
            session = self._open_stream_session(path)
        else:
            tmp = self._new_tempfile()
            session = _WriteSession(path=path, tmp=tmp, dirty=True)
        self._stat.invalidate_all()
        self._listing.invalidate_all()
        return self._alloc_write_fh(session)

    def open(self, path, flags):
        # Read-only mount or read-only open: no buffering needed.
        wanted_write = flags & (os.O_WRONLY | os.O_RDWR)
        if not self.writeable or not wanted_write:
            reader = _ReadSession(path=path, full=_to_backend_path(path, self.root))
            with self._fh_lock:
                fh = self._fh_counter
                self._fh_counter += 1
                self._reads[fh] = reader
            return fh
        # Streaming mode: cleanly accept only full-truncate opens.
        # O_TRUNC means "blow away existing content and start fresh"
        # — the same contract as create(). Non-truncate opens want
        # to edit an existing file, which needs buffer mode because
        # we can't stream edits sequentially without pre-fetching
        # and re-streaming. Fall back per-file so mixed workloads
        # don't require the user to switch mounts.
        if self.write_mode == "stream" and (flags & os.O_TRUNC):
            session = self._open_stream_session(path)
            return self._alloc_write_fh(session)
        tmp = self._new_tempfile()
        full = _to_backend_path(path, self.root)
        pre_fetched = False
        if not (flags & os.O_TRUNC):
            # Pre-fetch existing content so partial writes preserve
            # the rest of the file. If the backend doesn't have
            # the file (create-by-open races), fall through with
            # an empty buffer — FUSE treats it as a fresh file.
            try:
                with self.backend.open_read(full) as src:
                    while True:
                        chunk = src.read(64 * 1024)
                        if not chunk:
                            break
                        tmp.write(chunk)
                pre_fetched = True
            except OSError as exc:
                if self._may_exist(full):
                    # The buffer is empty or cut short, and flush
                    # would commit it over the file the read failed on.
                    log.warning("open(%s) pre-fetch failed: %s — EIO", full, exc)
                    self._discard_tempfile(tmp)
                    raise FuseOSError(errno.EIO)
                tmp.seek(0)
                tmp.truncate()
        tmp.seek(0)
        # dirty only when truncate was requested (content really
        # differs) or we couldn't pre-fetch (new-file case). A
        # read-then-immediately-close with no writes shouldn't
        # cause a backend overwrite.
        session = _WriteSession(
            path=path,
            tmp=tmp,
            dirty=bool(flags & os.O_TRUNC) or not pre_fetched,
        )
        return self._alloc_write_fh(session)

    def write(self, path, data, offset, fh):
        session = self._writes.get(fh)
        if session is None:
            raise FuseOSError(errno.EROFS)
        if session.errored:
            # Sticky — once a write failed in this session, every
            # subsequent write reports EIO so the kernel doesn't
            # assemble a partial-ok result.
            raise FuseOSError(errno.EIO)
        if session.mode == "stream":
            # Streaming only accepts strictly sequential writes.
            # Any seek / random-access / partial overwrite is a
            # clear "this isn't the workload streaming mode can
            # serve" signal; raise EIO and flip the errored flag.
            if offset != session.expected_offset:
                session.errored = True
                log.warning(
                    "FUSE stream write(%s): non-sequential offset "
                    "%d (expected %d) — EIO. Re-mount without "
                    "write_mode='stream' to buffer edits.",
                    session.path,
                    offset,
                    session.expected_offset,
                )
                raise FuseOSError(errno.EIO)
            if session.stream_handle is None:
                self._reopen_stream(session)
            try:
                session.stream_handle.write(data)
            except OSError as exc:
                session.errored = True
                log.warning(
                    "FUSE stream write(%s) backend refused: %s",
                    session.path,
                    exc,
                )
                raise FuseOSError(errno.EIO)
            session.expected_offset += len(data)
            session.dirty = True
            return len(data)
        # Buffer mode.
        session.tmp.seek(offset)
        written = session.tmp.write(data)
        session.dirty = True
        return written

    def truncate(self, path, length, fh=None):
        if not self.writeable:
            raise FuseOSError(errno.EROFS)
        if fh is not None:
            session = self._writes.get(fh)
            if session is not None:
                if session.mode == "stream":
                    # In stream mode, truncate is only a no-op when
                    # ``length == expected_offset`` (i.e. "truncate
                    # here" matches where we are already). Any other
                    # length would need to either rewind the backend
                    # handle (not supported) or forward-extend (would
                    # require writing the gap bytes, which the kernel
                    # didn't give us). Flip errored.
                    if length == session.expected_offset:
                        return
                    session.errored = True
                    log.warning(
                        "FUSE stream truncate(%s, %d): only "
                        "length==%d is permitted. Re-mount without "
                        "write_mode='stream' to edit.",
                        session.path,
                        length,
                        session.expected_offset,
                    )
                    raise FuseOSError(errno.EIO)
                session.tmp.truncate(length)
                session.dirty = True
                return
        # Path-level truncate with no handle: fetch, truncate,
        # flush. Covers the ``open(path, O_WRONLY|O_TRUNC)`` path
        # on fuse versions that route through truncate() rather
        # than calling create().
        full = _to_backend_path(path, self.root)
        import tempfile

        buf = tempfile.NamedTemporaryFile(prefix=".axross-fuse-")
        try:
            try:
                if length > 0:
                    with self.backend.open_read(full) as src:
                        remaining = length
                        while remaining > 0:
                            chunk = src.read(min(64 * 1024, remaining))
                            if not chunk:
                                break
                            buf.write(chunk)
                            remaining -= len(chunk)
            except OSError as prefetch_exc:
                # Missing file is the common case (truncate as part
                # of open(O_CREAT|O_TRUNC)). For a file that is there,
                # flushing what we could read would replace its first
                # *length* bytes with zeros.
                if self._may_exist(full):
                    log.warning(
                        "truncate(%s) pre-fetch failed (%s) — EIO",
                        full,
                        prefetch_exc,
                    )
                    raise FuseOSError(errno.EIO)
                buf.seek(0)
                buf.truncate()
            buf.truncate(length)
            buf.seek(0)
            try:
                from core.atomic_io import atomic_write_stream

                atomic_write_stream(
                    self.backend,
                    full,
                    buf,
                    chunk_size=64 * 1024,
                )
            except OSError as exc:
                log.warning("truncate(%s) flush failed: %s", full, exc)
                raise FuseOSError(errno.EIO)
        finally:
            buf.close()
        self._stat.invalidate_all()
        self._listing.invalidate_all()
        self._refresh_readers(path)

    def flush(self, path, fh):
        # The kernel calls flush() from every close(2) of a descriptor
        # on this handle and hands its result to that close(). This is
        # therefore where the commit happens: release() comes after the
        # last close, asynchronously, and the kernel discards its return
        # value -- a commit failure there never reaches the writer.
        session = self._writes.get(fh)
        if session is not None:
            self._commit_reported(session, "flush")
        return 0

    def fsync(self, path, datasync, fh):
        session = self._writes.get(fh)
        if session is not None:
            self._commit_reported(session, "fsync")
        return 0

    def _commit_reported(self, session: _WriteSession, caller: str) -> None:
        try:
            self._commit(session, caller)
        except FuseOSError:
            session.failure_reported = True
            raise

    def _commit(self, session: _WriteSession, caller: str) -> None:
        """Bring the backend up to the session's content.

        Raises FuseOSError(EIO) when the backend refuses, so flush() /
        fsync() report the failure to the writing program. A buffer
        session stays dirty after a failure: the next flush retries.
        """
        if session.mode == "stream":
            self._commit_stream(session, caller)
            return
        if not session.dirty:
            return
        tmp = session.tmp
        tmp.flush()
        tmp.seek(0)
        full = _to_backend_path(session.path, self.root)
        try:
            from core.atomic_io import atomic_write_stream

            atomic_write_stream(
                self.backend,
                full,
                tmp,
                chunk_size=64 * 1024,
            )
        except OSError as exc:
            log.warning("FUSE %s(%s) commit failed: %s", caller, full, exc)
            raise FuseOSError(errno.EIO)
        session.dirty = False
        self._stat.invalidate_all()
        self._listing.invalidate_all()
        self._refresh_readers(session.path)

    def _commit_stream(self, session: _WriteSession, caller: str) -> None:
        """Close (= commit) the backend handle of a stream session.

        The handle is gone afterwards; a later sequential write on the
        same fh reopens the file (see :meth:`_reopen_stream`). If the
        session already errored (non-sequential write earlier), prefer
        ``discard()`` when available so the backend doesn't quietly
        materialise a partial file as the committed state.
        """
        if session.errored:
            handle, session.stream_handle = session.stream_handle, None
            if handle is not None:
                discard = getattr(handle, "discard", None)
                try:
                    if callable(discard):
                        discard()
                    else:
                        # No discard -- close anyway and leave commit or
                        # rollback to the backend; EIO keeps the caller
                        # from thinking success.
                        handle.close()
                except Exception as exc:  # noqa: BLE001
                    log.debug(
                        "FUSE stream close-after-error(%s): %s",
                        session.path,
                        exc,
                    )
            raise FuseOSError(errno.EIO)
        handle, session.stream_handle = session.stream_handle, None
        if handle is None:
            return
        try:
            handle.close()
        except OSError as exc:
            session.errored = True
            log.warning(
                "FUSE stream %s(%s) commit failed: %s",
                caller,
                session.path,
                exc,
            )
            raise FuseOSError(errno.EIO)
        self._stat.invalidate_all()
        self._listing.invalidate_all()
        self._refresh_readers(session.path)

    def _reopen_stream(self, session: _WriteSession) -> None:
        """A write after a flush committed the stream: open the backend
        file again and continue where it ended. From offset 0 that is a
        plain open_write; past it the backend must support append."""
        full = _to_backend_path(session.path, self.root)
        try:
            if session.expected_offset:
                session.stream_handle = self.backend.open_write(full, append=True)
            else:
                session.stream_handle = self.backend.open_write(full)
        except (OSError, TypeError, NotImplementedError) as exc:
            session.errored = True
            log.warning(
                "FUSE stream write(%s) after a commit cannot continue the file: %s",
                session.path,
                exc,
            )
            raise FuseOSError(errno.EIO)

    def release(self, path, fh):
        reader = self._reads.pop(fh, None)
        if reader is not None:
            with reader.lock:
                self._drop_read_handle(reader)
            return 0
        session = self._writes.pop(fh, None)
        if session is None:
            return 0
        # flush() already committed on close(). What is left is content
        # that reached us after the last close (mmap write-back) or a
        # stream nobody flushed. The kernel discards release's answer:
        # a failure flush() already returned is not raised again, any
        # other one is (fusepy logs it; callers outside the kernel see it).
        try:
            self._commit(session, "release")
        except FuseOSError:
            if not session.failure_reported:
                raise
            log.debug("FUSE release(%s): final commit failed again", session.path)
        finally:
            if session.tmp is not None:
                self._discard_tempfile(session.tmp)
        return 0

    def unlink(self, path):
        if not self.writeable:
            raise FuseOSError(errno.EROFS)
        full = _to_backend_path(path, self.root)
        try:
            self.backend.remove(full, recursive=False)
        except OSError as exc:
            log.debug("unlink(%s) failed: %s", full, exc)
            raise FuseOSError(_mutation_errno(exc))
        self._stat.invalidate_all()
        self._listing.invalidate_all()
        self._refresh_readers(path)

    def mkdir(self, path, mode):
        if not self.writeable:
            raise FuseOSError(errno.EROFS)
        full = _to_backend_path(path, self.root)
        try:
            self.backend.mkdir(full)
        except OSError as exc:
            log.debug("mkdir(%s) failed: %s", full, exc)
            raise FuseOSError(_mutation_errno(exc))
        self._listing.invalidate_all()

    def rmdir(self, path):
        if not self.writeable:
            raise FuseOSError(errno.EROFS)
        full = _to_backend_path(path, self.root)
        try:
            self.backend.remove(full, recursive=False)
        except OSError as exc:
            log.debug("rmdir(%s) failed: %s", full, exc)
            raise FuseOSError(_mutation_errno(exc))
        self._listing.invalidate_all()

    def rename(self, old, new):
        if not self.writeable:
            raise FuseOSError(errno.EROFS)
        old_full = _to_backend_path(old, self.root)
        new_full = _to_backend_path(new, self.root)
        try:
            self.backend.rename(old_full, new_full)
        except OSError as rename_exc:
            from core.server_ops import _rename_fallback_allowed, server_side_move

            if not _rename_fallback_allowed(self.backend, rename_exc):
                log.debug(
                    "rename(%s → %s) failed without fallback: %s",
                    old_full,
                    new_full,
                    rename_exc,
                )
                raise FuseOSError(_mutation_errno(rename_exc))
            try:
                server_side_move(self.backend, old_full, new_full)
            except OSError as move_exc:
                log.debug(
                    "rename(%s → %s) failed: primary=%s, fallback=%s",
                    old_full,
                    new_full,
                    rename_exc,
                    move_exc,
                )
                raise FuseOSError(_mutation_errno(move_exc))
        self._stat.invalidate_all()
        self._listing.invalidate_all()
        self._refresh_readers(old)
        self._refresh_readers(new)


# --------------------------------------------------------------------------
# Stat helpers (live outside the class so tests can drive them
# without spinning up FUSE)
# --------------------------------------------------------------------------


def _join(parent: str, child: str) -> str:
    if parent.endswith("/"):
        return parent + child
    return f"{parent}/{child}"


def _stat_dict(item, *, writeable: bool = False) -> dict:
    """Translate a backend FileItem into the dict that fusepy's
    ``getattr`` callback wants. Mode bits reflect the mount flavour:
    0o444/0o555 for read-only, 0o664/0o775 for writeable."""
    is_dir = bool(getattr(item, "is_dir", False))
    size = int(getattr(item, "size", 0) or 0)
    modified = getattr(item, "modified", None)
    if modified is not None and hasattr(modified, "timestamp"):
        try:
            mtime = float(modified.timestamp())
        except Exception:
            mtime = time.time()
    else:
        mtime = time.time()
    if is_dir:
        mode = stat_mod.S_IFDIR | (0o775 if writeable else 0o555)
    else:
        mode = stat_mod.S_IFREG | (0o664 if writeable else 0o444)
    return {
        "st_mode": mode,
        "st_size": size,
        "st_nlink": 2 if is_dir else 1,
        "st_mtime": mtime,
        "st_atime": mtime,
        "st_ctime": mtime,
        "st_uid": os.getuid() if hasattr(os, "getuid") else 0,
        "st_gid": os.getgid() if hasattr(os, "getgid") else 0,
    }


def _stat_for(adapter, path: str, *, writeable: bool = False) -> dict:
    """Top-level stat used by ``BackendFuseFS.getattr``. Lives
    outside the class so the unit tests can call it without standing
    up a FUSE process — they instantiate a real adapter and pass it
    in. ``writeable`` flips the mode bits so the kernel doesn't
    reject an ``open(..., O_RDWR)`` on a writeable mount."""
    cached = adapter._stat.get(path)
    if cached is not None:
        return cached
    full = _to_backend_path(path, adapter.root)
    try:
        item = adapter.backend.stat(full)
        if getattr(item, "is_link", False) is True:
            item = _link_target_item(adapter.backend, full, item)
    except OSError as exc:
        log.debug("stat(%s) failed: %s", full, exc)
        raise FuseOSError(_stat_errno(exc))
    result = _stat_dict(item, writeable=writeable)
    adapter._stat.put(path, result)
    return result


#: Symlinks followed before a chain counts as a loop (the kernel's limit).
MAX_LINK_HOPS = 40


def _link_target_item(backend, full: str, link_item):
    """The stat of what the link at *full* finally points to.

    Backends answer stat() with an lstat: a link's own size is the length
    of its target text, but reads follow the link, so the kernel cut every
    read at that size. The mount shows the target, like sshfs does. A
    backend that cannot read links keeps *link_item*.
    """
    current = full
    for _hop in range(MAX_LINK_HOPS):
        try:
            target = backend.readlink(current)
        except (AttributeError, NotImplementedError):
            return link_item
        if not target:
            raise OSError(errno.ENOENT, "empty symlink", current)
        if not target.startswith("/"):
            target = posixpath.join(posixpath.dirname(current), target)
        current = posixpath.normpath(target)
        item = backend.stat(current)
        if getattr(item, "is_link", False) is not True:
            return item
    raise OSError(errno.ELOOP, os.strerror(errno.ELOOP), full)


#: The errno of an OSError subclass a backend raised without one.
_ERRNO_OF_CLASS = (
    (PermissionError, errno.EACCES),
    (FileNotFoundError, errno.ENOENT),
    (FileExistsError, errno.EEXIST),
    (NotADirectoryError, errno.ENOTDIR),
    (IsADirectoryError, errno.EISDIR),
)


def _mutation_errno(exc: OSError) -> int:
    """The errno unlink / mkdir / rmdir / rename report for a backend
    failure: the backend's own, so ``rmdir`` of a non-empty folder is
    ENOTEMPTY and ``mkdir -p`` sees the EEXIST it skips. An error without
    one is EIO, unless its class says what it is."""
    code = getattr(exc, "errno", None)
    if isinstance(code, int) and code in errno.errorcode:
        return code
    for cls, mapped in _ERRNO_OF_CLASS:
        if isinstance(exc, cls):
            return mapped
    return errno.EIO


def _stat_errno(exc: OSError) -> int:
    """The errno getattr reports for a failed backend stat.

    Only "not found" may be ENOENT: the kernel then lets O_CREAT create
    the name, and create() starts an empty buffer whose commit replaces
    the file that was there all along. A timeout or a dropped connection
    is EIO. A bare OSError without errno stays ENOENT: several backends
    say "not found" that way.
    """
    if isinstance(exc, PermissionError):
        return errno.EACCES
    if isinstance(exc, (TimeoutError, ConnectionError)):
        return errno.EIO
    code = getattr(exc, "errno", None)
    if code is None or code in (errno.ENOENT, errno.ENOTDIR):
        return errno.ENOENT
    if code == errno.ELOOP:
        return errno.ELOOP
    return errno.EIO


# --------------------------------------------------------------------------
# Mount manager
# --------------------------------------------------------------------------


#: Signals whose handling libfuse touches: it installs handlers for those
#: still at their default and, when the loop ends, sets them back to the
#: default - SIGPIPE too, which Python ignores and libfuse never installed.
_FUSE_SIGNALS = ("SIGHUP", "SIGINT", "SIGTERM", "SIGPIPE")


@contextlib.contextmanager
def preserved_signal_dispositions():
    """Save the process's handling of :data:`_FUSE_SIGNALS` and restore it
    on exit, from any thread (raw sigaction through libc: Python's
    signal.signal works in the main thread only). Without it, an unmount
    left SIGPIPE at its default and the next write to a dead pipe or
    socket killed axross silently (status 141)."""
    saved = []
    libc = None
    try:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        for name in _FUSE_SIGNALS:
            number = getattr(signal, name, None)
            if number is None:
                continue
            # An opaque buffer larger than any struct sigaction: read back
            # and written as it is, never interpreted.
            buffer = ctypes.create_string_buffer(512)
            if libc.sigaction(int(number), None, buffer) == 0:
                saved.append((int(number), buffer))
    except (OSError, AttributeError) as exc:  # no libc sigaction (not POSIX)
        log.debug("signal dispositions not saved: %s", exc)
    try:
        yield
    finally:
        for number, buffer in saved:
            if libc.sigaction(number, buffer, None) != 0:
                log.warning("could not restore the handling of signal %d", number)


@dataclass
class MountHandle:
    """Returned by :func:`mount`. Call ``.unmount()`` to release."""

    mount_point: str
    backend_id: str
    _thread: threading.Thread = field(repr=False)
    _stop: threading.Event = field(default_factory=threading.Event, repr=False)

    def is_alive(self) -> bool:
        return self._thread.is_alive()

    def unmount(self, timeout: float = 5.0) -> None:
        """Best-effort unmount via fusermount. The mount loop exits
        when the kernel detaches the FS; we then join the thread."""
        log.info("FUSE unmounting: %s (backend=%s)", self.mount_point, self.backend_id)
        # Always attempt the system unmount — easier to recover from
        # a stuck mount this way than to try to signal libfuse.
        for cmd in (("fusermount", "-u", self.mount_point), ("umount", self.mount_point)):
            try:
                import subprocess

                subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=timeout,
                    check=False,
                                    env=clean_child_env(),
                )
            except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
                log.debug("unmount(%s): %s failed: %s", self.mount_point, cmd[0], exc)
        self._stop.set()
        self._thread.join(timeout=timeout)


def is_available() -> bool:
    """True iff fusepy is importable. Does not check kernel/fusermount —
    those failures surface from the actual mount call."""
    return FUSE_AVAILABLE


def mount(
    backend,
    mount_point: str,
    *,
    root: str = "/",
    ttl_listing: float = TTL_LISTING_DEFAULT,
    ttl_stat: float = TTL_STAT_DEFAULT,
    writeable: bool = False,
    write_mode: str = "buffer",
) -> MountHandle:
    """Mount *backend* (rooted at *root*) at *mount_point*.

    Default is read-only — the writeable flag must be set explicitly.

    ``write_mode`` selects how writes land on the backend when
    ``writeable=True``:

    * ``"buffer"`` (default) — per-open tempfile on local disk,
      committed on flush (close) and fsync. Works for any write pattern including
      random-access edits, at the cost of local disk space equal
      to the file size. Good for interactive editing.
    * ``"stream"`` — per-open ``backend.open_write`` handle that
      accepts bytes directly as the kernel chunks them in. No
      tempfile is allocated; memory stays flat regardless of file
      size. Works for strictly sequential writes (cp, rsync,
      tar -x), and fails with EIO on any seek / out-of-order
      offset / partial overwrite. Non-truncate opens of existing
      files silently fall back to buffer mode for that one
      session so editors still work on a mixed-workload mount.

    Returns a :class:`MountHandle` whose ``unmount()`` releases the
    mount. Spawns a daemon thread for the FUSE loop so the calling
    GUI keeps running.

    Raises :class:`RuntimeError` if fusepy isn't available.
    """
    if not FUSE_AVAILABLE:
        raise RuntimeError("core.fuse_mount: fusepy is not installed (pip install fusepy)")
    if not os.path.isdir(mount_point):
        raise NotADirectoryError(f"mount point {mount_point!r} doesn't exist or isn't a dir")
    adapter = BackendFuseFS(
        backend,
        root,
        ttl_listing=ttl_listing,
        ttl_stat=ttl_stat,
        writeable=writeable,
        write_mode=write_mode,
    )
    stop = threading.Event()

    def _loop() -> None:
        try:
            # libfuse resets signal handling when its loop ends.
            with preserved_signal_dispositions():
                FUSE(  # type: ignore[misc]
                    adapter,
                    mount_point,
                    foreground=True,
                    ro=not writeable,
                    nothreads=True,
                    allow_other=False,
                )
        except Exception as exc:  # noqa: BLE001 — log + die quietly
            log.warning("FUSE loop exited with %s", exc)
        finally:
            stop.set()

    t = threading.Thread(
        target=_loop,
        daemon=True,
        name=f"fuse-mount:{mount_point}",
    )
    t.start()
    backend_id = type(backend).__name__
    log.info(
        "FUSE mounted: backend=%s root=%s -> %s mode=%s write_mode=%s",
        backend_id,
        root,
        mount_point,
        "rw" if writeable else "ro",
        write_mode,
    )
    return MountHandle(
        mount_point=mount_point,
        backend_id=backend_id,
        _thread=t,
        _stop=stop,
    )


__all__ = [
    "BackendFuseFS",
    "FUSE_AVAILABLE",
    "MountHandle",
    "TTL_LISTING_DEFAULT",
    "TTL_STAT_DEFAULT",
    "_WriteSession",
    "is_available",
    "mount",
]
