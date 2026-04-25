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
per-handle tempfile and flushes to the backend on ``release`` (= the
kernel-side ``close``). That matches how most remote backends think
about mutation: whole-file overwrite, not random-access edits. S3
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

import errno
import logging
import os
import stat as stat_mod
import threading
import time
from dataclasses import dataclass, field

log = logging.getLogger("core.fuse_mount")


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
      ``release`` the whole tempfile is streamed to
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

    ``dirty=False`` means we opened the file read-only (no pre-
    fetch) or the kernel never issued a write — the release path
    can skip the flush.

    ``errored=True`` is a sticky flag: once we've reported a write
    failure (out-of-order offset, backend refused a chunk) the
    release path skips the commit and returns EIO to the kernel,
    so an earlier EIO on write isn't silently lost.
    """
    path: str
    tmp: object
    dirty: bool = False
    mode: str = "buffer"
    stream_handle: object | None = None
    expected_offset: int = 0
    errored: bool = False


class BackendFuseFS(Operations):  # type: ignore[misc]
    """fusepy adapter that proxies into a FileBackend.

    Writeable when ``writeable=True``. The mutation methods then
    buffer per-handle to a tempfile and flush on release; dir ops
    (mkdir / rmdir / unlink / rename) go through to the backend
    directly.

    When fusepy isn't installed, ``Operations`` aliases to ``object``
    and ``FuseOSError`` to ``OSError`` — the class definition still
    works, so tests can exercise the adapter logic without the
    kernel module. Real mounts go through :func:`mount`, which
    guards on :attr:`FUSE_AVAILABLE` first."""

    def __init__(self, backend, root: str, *,
                 ttl_listing: float = TTL_LISTING_DEFAULT,
                 ttl_stat: float = TTL_STAT_DEFAULT,
                 writeable: bool = False,
                 write_mode: str = "buffer") -> None:
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
        self._fh_counter = 1_000_000
        self._fh_lock = threading.Lock()

    # ---- lookup / stat -------------------------------------------------
    def access(self, path, mode):
        if mode & os.W_OK and not self.writeable:
            raise FuseOSError(errno.EROFS)
        return 0

    def getattr(self, path, fh=None):
        return _stat_for(self, path, writeable=self.writeable)

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
            names = [getattr(it, "name", "") for it in items
                     if getattr(it, "name", "")
                     and getattr(it, "name", "") not in (".", "..")]
            self._listing.put(path, names)
            # Pre-warm the per-entry stat cache from the same listing
            # so a subsequent getattr() doesn't re-fetch each row.
            for it in items:
                name = getattr(it, "name", "")
                if not name or name in (".", ".."):
                    continue
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
                    "FUSE stream read(%s) on write fh — EIO", session.path,
                )
                raise FuseOSError(errno.EIO)
            session.tmp.seek(offset)
            return session.tmp.read(size)
        full = _to_backend_path(path, self.root)
        try:
            handle = self.backend.open_read(full)
        except OSError as exc:
            log.debug("open_read(%s) failed: %s", full, exc)
            raise FuseOSError(errno.EIO)
        try:
            # Some backends support seek() via the returned IO
            # handle; others don't. Prefer seek when available.
            if hasattr(handle, "seek"):
                try:
                    handle.seek(offset)
                    return handle.read(size)
                except Exception:
                    pass
            # Fallback: read+discard up to offset, then return
            # the requested slice. Capped — beyond MAX_FALLBACK_
            # DISCARD bytes the network cost is ridiculous, and
            # an LLM / FUSE client iterating a large file by
            # random offset would cause hundreds of MiB of waste
            # per call.
            if offset:
                if offset > MAX_FALLBACK_DISCARD:
                    log.warning(
                        "FUSE read: offset %d exceeds fallback cap "
                        "%d for %s — returning EIO", offset,
                        MAX_FALLBACK_DISCARD, full,
                    )
                    raise FuseOSError(errno.EIO)
                discarded = 0
                while discarded < offset:
                    chunk = handle.read(min(64 * 1024, offset - discarded))
                    if not chunk:
                        break
                    discarded += len(chunk)
            return handle.read(size)
        finally:
            try:
                handle.close()
            except Exception:
                pass

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
            prefix=".axross-fuse-", delete=False,
        )

    def _open_stream_session(self, path: str) -> _WriteSession:
        """Open a backend write handle and wrap it in a streaming
        session. Raises FuseOSError(EIO) on backend failure so the
        caller — create()/open() — can propagate cleanly.

        Streaming sessions never allocate a tempfile; they hold the
        open ``backend.open_write`` handle for the whole lifetime
        of the kernel fh and commit on release.
        """
        full = _to_backend_path(path, self.root)
        try:
            handle = self.backend.open_write(full)
        except OSError as exc:
            log.warning(
                "FUSE stream open_write(%s) failed: %s — caller will "
                "see EIO", full, exc,
            )
            raise FuseOSError(errno.EIO)
        return _WriteSession(
            path=path, tmp=None, dirty=True, mode="stream",
            stream_handle=handle, expected_offset=0,
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
            return 0
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
            except OSError:
                pass
        tmp.seek(0)
        # dirty only when truncate was requested (content really
        # differs) or we couldn't pre-fetch (new-file case). A
        # read-then-immediately-close with no writes shouldn't
        # cause a backend overwrite.
        session = _WriteSession(
            path=path, tmp=tmp,
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
                    session.path, offset, session.expected_offset,
                )
                raise FuseOSError(errno.EIO)
            try:
                session.stream_handle.write(data)
            except OSError as exc:
                session.errored = True
                log.warning(
                    "FUSE stream write(%s) backend refused: %s",
                    session.path, exc,
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
                        session.path, length, session.expected_offset,
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
                # of open(O_CREAT|O_TRUNC)); a perm/network error is
                # unusual enough to log so a user debugging "why is
                # my file suddenly zero bytes?" has a breadcrumb.
                log.info(
                    "truncate(%s) pre-fetch failed (%s) — flushing "
                    "a %d-byte buffer from what we could read",
                    full, prefetch_exc, length,
                )
            buf.truncate(length)
            buf.seek(0)
            try:
                with self.backend.open_write(full) as dst:
                    while True:
                        chunk = buf.read(64 * 1024)
                        if not chunk:
                            break
                        dst.write(chunk)
            except OSError as exc:
                log.warning("truncate(%s) flush failed: %s", full, exc)
                raise FuseOSError(errno.EIO)
        finally:
            buf.close()
        self._stat.invalidate_all()
        self._listing.invalidate_all()

    def flush(self, path, fh):
        # Kernel may call flush() as part of close. The real flush
        # to the backend happens in release(); here we just return
        # success so the kernel doesn't think a write is stuck.
        return 0

    def release(self, path, fh):
        session = self._writes.pop(fh, None)
        if session is None:
            return 0
        if session.mode == "stream":
            # Streaming: the backend handle has been accepting
            # bytes all along. Close it to commit. If the session
            # already errored (non-sequential write earlier), prefer
            # ``discard()`` when available so the backend doesn't
            # quietly materialise a partial file as the committed
            # state.
            handle = session.stream_handle
            if handle is None:
                return 0
            try:
                if session.errored:
                    discard = getattr(handle, "discard", None)
                    if callable(discard):
                        try:
                            discard()
                        except Exception as exc:  # noqa: BLE001
                            log.debug(
                                "FUSE stream discard(%s) raised: %s",
                                session.path, exc,
                            )
                    else:
                        # No discard — close anyway but leave the
                        # backend's own commit/rollback logic to
                        # decide. EIO back to the kernel keeps the
                        # caller from thinking success.
                        try:
                            handle.close()
                        except Exception as exc:  # noqa: BLE001
                            log.debug(
                                "FUSE stream close-after-error(%s): %s",
                                session.path, exc,
                            )
                    raise FuseOSError(errno.EIO)
                try:
                    handle.close()
                except OSError as exc:
                    log.warning(
                        "FUSE stream release(%s) close failed: %s",
                        session.path, exc,
                    )
                    raise FuseOSError(errno.EIO)
                self._stat.invalidate_all()
                self._listing.invalidate_all()
            finally:
                session.stream_handle = None
            return 0
        # Buffer mode.
        tmp = session.tmp
        try:
            if session.dirty:
                tmp.flush()
                tmp.seek(0)
                full = _to_backend_path(path, self.root)
                try:
                    with self.backend.open_write(full) as dst:
                        while True:
                            chunk = tmp.read(64 * 1024)
                            if not chunk:
                                break
                            dst.write(chunk)
                except OSError as exc:
                    log.warning("release(%s) flush failed: %s", full, exc)
                    raise FuseOSError(errno.EIO)
                self._stat.invalidate_all()
                self._listing.invalidate_all()
        finally:
            # Always clean up the temp file, even on EIO.
            try:
                tmp.close()
            except Exception:
                pass
            try:
                os.unlink(tmp.name)
            except Exception:
                pass
        return 0

    def unlink(self, path):
        if not self.writeable:
            raise FuseOSError(errno.EROFS)
        full = _to_backend_path(path, self.root)
        try:
            self.backend.remove(full, recursive=False)
        except OSError as exc:
            log.debug("unlink(%s) failed: %s", full, exc)
            raise FuseOSError(errno.EIO)
        self._stat.invalidate_all()
        self._listing.invalidate_all()

    def mkdir(self, path, mode):
        if not self.writeable:
            raise FuseOSError(errno.EROFS)
        full = _to_backend_path(path, self.root)
        try:
            self.backend.mkdir(full)
        except OSError as exc:
            log.debug("mkdir(%s) failed: %s", full, exc)
            raise FuseOSError(errno.EIO)
        self._listing.invalidate_all()

    def rmdir(self, path):
        if not self.writeable:
            raise FuseOSError(errno.EROFS)
        full = _to_backend_path(path, self.root)
        try:
            self.backend.remove(full, recursive=False)
        except OSError as exc:
            log.debug("rmdir(%s) failed: %s", full, exc)
            raise FuseOSError(errno.EIO)
        self._listing.invalidate_all()

    def rename(self, old, new):
        if not self.writeable:
            raise FuseOSError(errno.EROFS)
        old_full = _to_backend_path(old, self.root)
        new_full = _to_backend_path(new, self.root)
        try:
            self.backend.rename(old_full, new_full)
        except OSError as rename_exc:
            # Fallback for S3 / IMAP / Exchange folders etc. that
            # don't expose a first-class rename — try copy+delete
            # and only give up if that fails too. The "at least
            # try" rule here avoids a mv on a S3 mount failing
            # with EIO when the operation IS possible, just not
            # via the rename primitive.
            try:
                self.backend.copy(old_full, new_full)
            except OSError as copy_exc:
                log.debug(
                    "rename(%s → %s) failed: primary=%s, copy=%s",
                    old_full, new_full, rename_exc, copy_exc,
                )
                raise FuseOSError(errno.EIO)
            # Copy succeeded; now remove the source. If that fails
            # we've created a duplicate — undo the copy to get back
            # to the pre-rename state. If the undo also fails we
            # log loudly (the user now has duplicate data) and
            # surface EIO so the kernel-side mv reports failure.
            try:
                self.backend.remove(old_full, recursive=False)
            except OSError as remove_exc:
                log.warning(
                    "rename(%s → %s) fallback: copy succeeded but "
                    "remove(source) failed: %s — undoing copy",
                    old_full, new_full, remove_exc,
                )
                try:
                    self.backend.remove(new_full, recursive=False)
                except OSError as undo_exc:
                    log.error(
                        "rename(%s → %s) fallback: UNDO ALSO FAILED — "
                        "backend now holds duplicate data at both "
                        "paths: %s",
                        old_full, new_full, undo_exc,
                    )
                raise FuseOSError(errno.EIO)
        self._stat.invalidate_all()
        self._listing.invalidate_all()



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
    except OSError as exc:
        log.debug("stat(%s) failed: %s", full, exc)
        raise FuseOSError(errno.ENOENT)
    result = _stat_dict(item, writeable=writeable)
    adapter._stat.put(path, result)
    return result


# --------------------------------------------------------------------------
# Mount manager
# --------------------------------------------------------------------------

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
        # Always attempt the system unmount — easier to recover from
        # a stuck mount this way than to try to signal libfuse.
        for cmd in (("fusermount", "-u", self.mount_point),
                    ("umount", self.mount_point)):
            try:
                import subprocess
                subprocess.run(
                    cmd, capture_output=True, timeout=timeout, check=False,
                )
            except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
                log.debug("unmount(%s): %s failed: %s",
                          self.mount_point, cmd[0], exc)
        self._stop.set()
        self._thread.join(timeout=timeout)


def is_available() -> bool:
    """True iff fusepy is importable. Does not check kernel/fusermount —
    those failures surface from the actual mount call."""
    return FUSE_AVAILABLE


def mount(backend, mount_point: str, *, root: str = "/",
          ttl_listing: float = TTL_LISTING_DEFAULT,
          ttl_stat: float = TTL_STAT_DEFAULT,
          writeable: bool = False,
          write_mode: str = "buffer") -> MountHandle:
    """Mount *backend* (rooted at *root*) at *mount_point*.

    Default is read-only — the writeable flag must be set explicitly.

    ``write_mode`` selects how writes land on the backend when
    ``writeable=True``:

    * ``"buffer"`` (default) — per-open tempfile on local disk,
      flushed on release. Works for any write pattern including
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
        raise RuntimeError(
            "core.fuse_mount: fusepy is not installed (pip install fusepy)"
        )
    if not os.path.isdir(mount_point):
        raise NotADirectoryError(
            f"mount point {mount_point!r} doesn't exist or isn't a dir"
        )
    adapter = BackendFuseFS(
        backend, root,
        ttl_listing=ttl_listing, ttl_stat=ttl_stat, writeable=writeable,
        write_mode=write_mode,
    )
    stop = threading.Event()

    def _loop() -> None:
        try:
            FUSE(  # type: ignore[misc]
                adapter, mount_point,
                foreground=True, ro=not writeable, nothreads=True,
                allow_other=False,
            )
        except Exception as exc:  # noqa: BLE001 — log + die quietly
            log.warning("FUSE loop exited with %s", exc)
        finally:
            stop.set()

    t = threading.Thread(
        target=_loop, daemon=True, name=f"fuse-mount:{mount_point}",
    )
    t.start()
    backend_id = type(backend).__name__
    return MountHandle(
        mount_point=mount_point, backend_id=backend_id,
        _thread=t, _stop=stop,
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
