"""Pack files and folders into an archive, on any backend.

Formats
-------
* ``zip`` (deflate), ``tar.gz``, ``tar.bz2``, ``tar.xz``, ``tar.zst`` - any
  number of files and folders.
* ``7z`` (LZMA2) - optionally encrypted with AES-256 and a password; with
  ``encrypt_names`` the file list is encrypted too, so without the password
  not even the names can be read. Needs ``py7zr`` (the ``archive`` extra).
* ``gz``, ``bz2``, ``xz``, ``zst`` - one file compressed on its own
  (``name.txt`` -> ``name.txt.gz``).

zstd comes from the standard library (Python 3.14+, ``compression.zstd``),
or its backport ``backports.zstd`` (a dependency of py7zr, so the archive
extra and the binary have it); without either the zstd formats say so.
Plain ZIP has no password option: its old ZipCrypto is broken and AES-ZIP
needs a further dependency that Windows Explorer does not open either -
an encrypted archive is a 7z.

Safety
------
* Sources are read through the backend (local or remote), folders walked
  recursively; symbolic links are skipped and reported, never followed.
* The archive is first written to a temporary file and only then put in
  place - locally by a hard link that fails instead of replacing an
  existing file, remotely by an upload to a name that did not exist. An
  existing archive is never overwritten: ``bundle.zip`` becomes
  ``bundle (2).zip``.
* A file whose size differs from its listing while it is read fails the
  whole run; an error or a cancel removes the temporary file, so no
  half-written archive is left behind.
"""

from __future__ import annotations

import atexit
import bz2
import errno
import gzip
import io
import logging
import lzma
import os
import posixpath
import shutil
import stat as stat_mod
import tarfile
import tempfile
import threading
import time
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field

from core.posix_compat import fchmod_private

log = logging.getLogger(__name__)

#: Files (not folders) one run packs at most.
MAX_PACK_FILES = 200_000
CHUNK = 1024 * 1024
LEVELS = {"fast": 0, "normal": 1, "best": 2}


class PackError(Exception):
    """The archive could not be made; nothing was left behind."""


class PackCancelled(PackError):
    """Stopped on request; nothing was left behind."""


# ---------------------------------------------------------------------------
# zstd: the standard library (3.14+), else its backport
# ---------------------------------------------------------------------------


def _zstd_module():
    try:
        from compression import zstd  # Python 3.14+

        return ("stdlib", zstd)
    except ImportError:
        pass
    try:
        # The same API before 3.14; py7zr (the archive extra) depends on it.
        from backports import zstd as backported  # type: ignore[import-not-found]

        return ("stdlib", backported)
    except ImportError:
        return None


def zstd_writer(raw, level: int):
    """A write-only file object compressing into *raw*."""
    mod = _zstd_module()
    if mod is None:
        raise PackError("zstd needs Python 3.14 or backports.zstd")
    return mod[1].ZstdFile(raw, "wb", level=level)


def zstd_reader(raw, *, close_raw: bool = False):
    """A read-only file object decompressing *raw* (a binary file)."""
    mod = _zstd_module()
    if mod is None:
        raise PackError("zstd needs Python 3.14 or backports.zstd")
    reader = mod[1].ZstdFile(raw, "rb")
    if close_raw:
        original = reader.close

        def close():
            try:
                original()
            finally:
                raw.close()

        reader.close = close
    return reader


def zstd_decompress(data: bytes) -> bytes:
    mod = _zstd_module()
    if mod is None:
        raise PackError("zstd needs Python 3.14 or backports.zstd")
    return mod[1].decompress(data)


def _have_py7zr() -> bool:
    try:
        import py7zr  # noqa: F401
    except ImportError:
        return False
    return True


# ---------------------------------------------------------------------------
# Formats and options
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Format:
    fmt_id: str
    label: str
    suffix: str
    single: bool = False  # exactly one file in, compressed on its own
    encrypts: bool = False  # takes a password

    def available(self) -> tuple[bool, str]:
        if "zst" in self.fmt_id and _zstd_module() is None:
            return False, (
                "zstd needs Python 3.14 or backports.zstd (pip install 'axross[archive]')"
            )
        if self.fmt_id == "7z" and not _have_py7zr():
            return False, "7z needs the py7zr package (pip install 'axross[archive]')"
        return True, ""


#: In menu order: the two everyday formats first.
FORMATS: dict[str, Format] = {
    f.fmt_id: f
    for f in (
        Format("zip", "ZIP", ".zip"),
        Format("tar.gz", "tar.gz (gzip)", ".tar.gz"),
        Format("tar.zst", "tar.zst (zstd)", ".tar.zst"),
        Format("tar.xz", "tar.xz (xz)", ".tar.xz"),
        Format("tar.bz2", "tar.bz2 (bzip2)", ".tar.bz2"),
        Format("7z", "7z (AES-256 optional)", ".7z", encrypts=True),
        Format("gz", "gzip, one file", ".gz", single=True),
        Format("zst", "zstd, one file", ".zst", single=True),
        Format("xz", "xz, one file", ".xz", single=True),
        Format("bz2", "bzip2, one file", ".bz2", single=True),
    )
}

# fast / normal / best per codec
_LEVEL_TABLE = {
    "deflate": (1, 6, 9),
    "bz2": (1, 9, 9),
    "xz": (1, 6, 9),
    "zst": (1, 3, 19),
    "7z": (1, 5, 9),
}


@dataclass
class PackOptions:
    fmt: str
    level: str = "normal"
    password: str = ""
    encrypt_names: bool = True

    def __post_init__(self) -> None:
        if self.fmt not in FORMATS:
            raise PackError(f"unknown format {self.fmt!r}")
        if self.level not in LEVELS:
            raise PackError(f"unknown level {self.level!r}; one of {', '.join(LEVELS)}")

    def level_for(self, codec: str) -> int:
        return _LEVEL_TABLE[codec][LEVELS[self.level]]


@dataclass
class PackResult:
    path: str
    files: int = 0
    folders: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    #: Left out, by archive name: symlinks, and what *refuse* turned down.
    skipped: list[str] = field(default_factory=list)
    #: Left out, by archive name: sockets, pipes and devices (no content to
    #: pack; reading a pipe could wait for ever). They failed the pack.
    special: list[str] = field(default_factory=list)
    #: Left out: names below a packed folder that cannot be an archive
    #: member (a server's "../x", "a/b", a control character), as written.
    unusable: list[str] = field(default_factory=list)


def default_name(names: list[str], folder: str = "") -> str:
    """A name for the archive: the one selected item, else the folder."""
    if len(names) == 1:
        return names[0]
    base = posixpath.basename(folder.rstrip("/\\").replace("\\", "/"))
    return base or "archive"


# ---------------------------------------------------------------------------
# Walking the sources
# ---------------------------------------------------------------------------


@dataclass
class _Entry:
    arcname: str
    path: str
    is_dir: bool
    size: int
    mtime: float
    #: The source's permission bits (masked to 0o777), stored in the archive.
    mode: int = 0o644
    #: ``(st_dev, st_ino)`` of a local source when it was walked: the file
    #: read must be that one (:func:`_open_local_source`).
    ident: tuple[int, int] | None = None


def _mode(backend, item, path: str, is_dir: bool) -> int:
    """The permission bits of *item* to store: ``stat`` for a local file,
    else the backend's ``permissions`` (0 is "not known": 0644, a folder
    0755). Only 0o777 - no setuid, setgid or sticky bit in an archive."""
    default = 0o755 if is_dir else 0o644
    if _is_local(backend):
        try:
            return os.lstat(path).st_mode & 0o777
        except OSError:
            return default
    perms = getattr(item, "permissions", 0)
    return perms & 0o777 if isinstance(perms, int) and perms > 0 else default


def _local_ident(backend, path: str) -> tuple[int, int] | None:
    if not _is_local(backend):
        return None
    try:
        st = os.lstat(path)
    except OSError:
        return None
    return (st.st_dev, st.st_ino)


def _is_local(backend) -> bool:
    """A local backend whose paths are used as they are: the archive is
    written in the folder and the sources read by name. A confined one
    (core.confined_fs, the MCP server's) is not: there a folder of the path
    swapped for a symlink must not be followed, so the archive is built in
    the private staging folder and created beneath the root's descriptor
    (:func:`_place_confined`), the sources read through the backend."""
    from core.local_fs import LocalFS

    return isinstance(backend, LocalFS) and not hasattr(backend, "create_new")


#: Staging folders of this process, removed at exit when a pack was cut off
#: (the process ended mid-task) - none is left behind.
_STAGING: dict[str, str | None] = {}
_STAGING_LOCK = threading.Lock()


def _remove_staging_at_exit() -> None:
    from core import partials

    with _STAGING_LOCK:
        left = list(_STAGING.items())
        _STAGING.clear()
    for path, record in left:
        shutil.rmtree(path, ignore_errors=True)
        partials.done(record)


atexit.register(_remove_staging_at_exit)


def _staging_folder(backend, folder: str) -> str:
    """A private folder for the archive being built: in the root of a
    confined backend that holds *folder* (the same file system as the
    archive - not the system temp folder, often a RAM disk, which a big
    pack filled), else in the system temp folder (a remote destination)."""
    base = None
    for root in getattr(backend, "roots", ()) or ():
        real = os.path.realpath(root)
        target = os.path.realpath(folder) if isinstance(folder, str) else ""
        if target == real or target.startswith(real.rstrip(os.sep) + os.sep):
            base = real
            break
    from core import partials

    path = tempfile.mkdtemp(prefix=f".axross-pack-{os.getpid()}-", dir=base) if base else \
        tempfile.mkdtemp(prefix="axross-pack-")
    # Recorded: a process killed mid-pack leaves it, the next start sweeps it.
    with _STAGING_LOCK:
        _STAGING[path] = partials.track(path)
    return path


def _mtime(item) -> float:
    modified = getattr(item, "modified", None)
    try:
        # Any date from 1970 on: tar and 7z keep it; ZIP's earliest (1980)
        # is applied where a ZIP entry is made (_zip_date_time).
        return max(0.0, modified.timestamp())
    except (AttributeError, OSError, OverflowError, ValueError):
        return time.time()


def _local_special(backend, path: str) -> bool:
    """A socket, pipe or device on this machine's disk (no content to pack)."""
    if not _is_local(backend):
        return False
    try:
        mode = os.lstat(path).st_mode
    except OSError:
        return False  # the read reports it
    return not (stat_mod.S_ISREG(mode) or stat_mod.S_ISDIR(mode) or stat_mod.S_ISLNK(mode))


def _collect(
    backend, folder: str, names: list[str], cancel, refuse=None, special=None, unusable=None
) -> tuple[list[_Entry], list[str]]:
    """The entries to pack and the archive names left out. *refuse(path)*:
    true for a path that must not be read (core.mcp_groups: a secret such
    as an SSH key) - checked for every name and everything below it.
    Sockets, pipes and devices on a local disk go to *special* (a list)."""
    try:
        listing = {i.name: i for i in backend.list_dir(folder)}
    except OSError as exc:
        raise PackError(f"cannot list {folder}: {exc}") from exc
    entries: list[_Entry] = []
    skipped: list[str] = []
    files = 0
    from core.path_policy import BackendPathPolicy

    policy = BackendPathPolicy.for_backend(backend)

    def add(item, path: str, arcname: str) -> None:
        # Iterative, depth first in name order (the order the recursion had):
        # a tree 1500 folders deep hit Python's recursion limit.
        nonlocal files
        stack = [(item, path, arcname)]

        def count() -> None:
            # Folders count too: a tree of a million empty folders was
            # walked and held in memory without a limit.
            nonlocal files
            files += 1
            if files > MAX_PACK_FILES:
                raise PackError(f"more than {MAX_PACK_FILES} files and folders - "
                                "pack fewer at a time")

        while stack:
            item, path, arcname = stack.pop()
            if cancel is not None and cancel.is_set():
                raise PackCancelled("cancelled")
            if getattr(item, "is_link", False) or (refuse is not None and refuse(path)):
                skipped.append(arcname)
                continue
            if item.is_dir:
                count()
                entries.append(_Entry(arcname, path, True, 0, _mtime(item),
                                      _mode(backend, item, path, True)))
                try:
                    children = backend.list_dir(path)
                except OSError as exc:
                    raise PackError(f"cannot list {arcname}: {exc}") from exc
                below = []
                for child in sorted(children, key=lambda c: c.name):
                    if child.name in ("..", "."):
                        continue
                    if not _usable_child_name(policy, child.name):
                        # A server's "../../x", "a/b" or a control character:
                        # never an archive name (it would land elsewhere for
                        # whoever extracts it); left out and named.
                        if unusable is not None:
                            unusable.append(f"{arcname}/{child.name!r}")
                        continue
                    below.append((child, backend.join(path, child.name),
                                  f"{arcname}/{child.name}"))
                stack.extend(reversed(below))
                continue
            if special is not None and _local_special(backend, path):
                special.append(arcname)
                continue
            count()
            entries.append(_Entry(arcname, path, False, max(0, int(item.size or 0)),
                                  _mtime(item), _mode(backend, item, path, False),
                                  _local_ident(backend, path)))

    for name in names:
        if name in ("", ".", "..") or "/" in name or "\\" in name:
            raise PackError(f"not a name in this folder: {name!r}")
        item = listing.get(name)
        if item is None:
            raise PackError(f"cannot read {name}: not found in {folder}")
        add(item, backend.join(folder, name), name)
    return entries, skipped


def _usable_child_name(policy, name: str) -> bool:
    """One safe name by the backend's own rules (core.remote_name): no
    separator, NUL, control or direction character, not "." or ".."."""
    try:
        policy.validate_leaf(name)
    except ValueError:
        return False
    return True


class _Exact(io.RawIOBase):
    """Reads a source and fails when it is not exactly *size* bytes."""

    def __init__(self, fh, size: int, arcname: str, cancel) -> None:
        self._fh = fh
        self._left = size
        self._arcname = arcname
        self._cancel = cancel

    def readable(self) -> bool:
        return True

    def read(self, n: int = -1) -> bytes:
        if self._cancel is not None and self._cancel.is_set():
            raise PackCancelled("cancelled")
        if self._left <= 0:
            return b""
        want = self._left if n is None or n < 0 else min(n, self._left)
        data = self._fh.read(min(want, CHUNK))
        if not data:
            raise PackError(f"{self._arcname} changed while packing (shorter than listed)")
        self._left -= len(data)
        return data

    def readinto(self, buf) -> int:
        data = self.read(len(buf))
        buf[: len(data)] = data
        return len(data)

    def finish(self) -> None:
        if self._left > 0:
            raise PackError(f"{self._arcname} changed while packing (shorter than listed)")
        if self._fh.read(1):
            raise PackError(f"{self._arcname} changed while packing (longer than listed)")


def _open_local_source(entry: _Entry):
    """A local source opened for reading as the walk saw it: never through
    a symlink put in its place (``O_NOFOLLOW``), the same file (device and
    inode) - not one moved there meanwhile -, a regular file (``O_NONBLOCK``:
    a FIFO put there does not block). It was opened by name, following a
    link: another local process that can write in the folder had the
    link's target (an SSH key) packed under the listed name."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) \
        | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(entry.path, flags)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise PackError(f"{entry.arcname} became a symbolic link while packing - "
                            "not read") from exc
        raise PackError(f"cannot read {entry.arcname}: {exc}") from exc
    try:
        st = os.fstat(fd)
        if not stat_mod.S_ISREG(st.st_mode):
            raise PackError(f"{entry.arcname} is no longer a regular file - not read")
        if entry.ident is not None and (st.st_dev, st.st_ino) != entry.ident:
            raise PackError(f"{entry.arcname} was replaced while packing - not read")
        os.set_blocking(fd, True)
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def _reads_direct(backend) -> bool:
    """A local source is opened by :func:`_open_local_source` - not where
    the platform has no O_NOFOLLOW, nor for a LocalFS whose reads are its
    own (a subclass overriding open_read)."""
    from core.local_fs import LocalFS

    return (_is_local(backend) and bool(getattr(os, "O_NOFOLLOW", 0))
            and type(backend).open_read is LocalFS.open_read)


def _open_source(backend, entry: _Entry, cancel) -> tuple[object, _Exact]:
    if _reads_direct(backend):
        fh = _open_local_source(entry)
    else:
        try:
            fh = backend.open_read(entry.path)
        except OSError as exc:
            raise PackError(f"cannot read {entry.arcname}: {exc}") from exc
    return fh, _Exact(fh, entry.size, entry.arcname, cancel)


def _copy(src: _Exact, dst) -> int:
    total = 0
    while True:
        chunk = src.read(CHUNK)
        if not chunk:
            break
        dst.write(chunk)
        total += len(chunk)
    src.finish()
    return total


# ---------------------------------------------------------------------------
# Writers (into a local temporary file)
# ---------------------------------------------------------------------------


#: The local date and time a ZIP entry can hold (its DOS date field).
_ZIP_EARLIEST = (1980, 1, 1, 0, 0, 0)
_ZIP_LATEST = (2107, 12, 31, 23, 59, 58)


def _zip_date_time(mtime: float) -> tuple:
    """*mtime* as a ZIP entry's local date and time, held to what a ZIP can
    store: the clamp is on the local time - 1980-01-01 00:00 UTC is a
    1979 date west of UTC."""
    try:
        stamp = tuple(time.localtime(mtime)[:6])
    except (OverflowError, OSError, ValueError):
        return _ZIP_LATEST if mtime > 0 else _ZIP_EARLIEST
    return max(_ZIP_EARLIEST, min(_ZIP_LATEST, stamp))


class _RawNameZipInfo(zipfile.ZipInfo):
    """A member whose name is not UTF-8 (a Latin-1 file name on Linux,
    decoded with surrogateescape) keeps its raw bytes, without the UTF-8
    flag - as zip tools store such names - instead of failing the pack
    ("surrogates not allowed")."""

    def _encodeFilenameFlags(self):  # noqa: N802 - zipfile's name
        try:
            return super()._encodeFilenameFlags()
        except UnicodeEncodeError:
            return self.filename.encode("utf-8", "surrogateescape"), self.flag_bits


def _write_zip(backend, entries, out, opts, step, cancel) -> None:
    level = opts.level_for("deflate")
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=level) as zf:
        for e in entries:
            stamp = _zip_date_time(e.mtime)
            if e.is_dir:
                info = _RawNameZipInfo(e.arcname + "/", date_time=stamp)
                info.external_attr = (stat_mod.S_IFDIR | e.mode) << 16 | 0x10
                zf.writestr(info, b"")
                continue
            info = _RawNameZipInfo(e.arcname, date_time=stamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat_mod.S_IFREG | e.mode) << 16
            fh, src = _open_source(backend, e, cancel)
            with fh, zf.open(info, "w", force_zip64=e.size > 0x7FFFFFFF) as dst:
                _copy(src, dst)
            step(e)


def _compressor(fmt: str, raw, opts: PackOptions, name: str = ""):
    """The compressing writer around *raw*. *name* is what a gzip header
    names as the original file ("" for none): GzipFile took the temporary
    file's name otherwise, and ``gunzip -N`` restored ``.axross-pack-….tmp``."""
    codec = fmt.split(".")[-1]
    if codec == "gz":
        return gzip.GzipFile(
            filename=name, fileobj=raw, mode="wb",
            compresslevel=opts.level_for("deflate"), mtime=0
        )
    if codec == "bz2":
        return bz2.BZ2File(raw, "wb", compresslevel=opts.level_for("bz2"))
    if codec == "xz":
        return lzma.LZMAFile(raw, "wb", preset=opts.level_for("xz"))
    if codec == "zst":
        return zstd_writer(raw, opts.level_for("zst"))
    raise PackError(f"no compressor for {fmt}")


def _write_tar(backend, entries, raw, opts, step, cancel) -> None:
    comp = _compressor(opts.fmt, raw, opts)
    try:
        # surrogateescape: a name that is not UTF-8 keeps its bytes.
        with tarfile.open(fileobj=comp, mode="w|", format=tarfile.PAX_FORMAT,
                          encoding="utf-8", errors="surrogateescape") as tf:
            for e in entries:
                info = tarfile.TarInfo(e.arcname)
                info.mtime = int(e.mtime)
                if e.is_dir:
                    info.type = tarfile.DIRTYPE
                    info.mode = e.mode
                    tf.addfile(info)
                    continue
                info.size = e.size
                info.mode = e.mode
                fh, src = _open_source(backend, e, cancel)
                with fh:
                    try:
                        tf.addfile(info, io.BufferedReader(src, CHUNK))
                    except OSError as exc:  # tarfile's "unexpected end of data"
                        raise PackError(f"{e.arcname} changed while packing ({exc})") from exc
                    src.finish()
                step(e)
    finally:
        comp.close()


def _stamp_staged(path: str, e: _Entry) -> None:
    """Give a staging file or folder *e*'s time and mode (py7zr stores what
    it finds on the file it is handed). The owner keeps what the pack
    needs: a folder (used again) all rights, a file (read next) reading."""
    try:
        os.chmod(path, (e.mode & 0o777) | (0o700 if e.is_dir else 0o400))
        os.utime(path, (e.mtime, e.mtime))
    except OSError:
        pass  # the default time and mode stay: the content is what matters


def _stamp_7z_record(zf, e: _Entry) -> None:
    """The time and mode of *e* on the record py7zr's writef() just made
    (it gives a file object's member the time of now and a default mode)."""
    from py7zr.helpers import ArchiveTimestamp

    record = zf.header.files_info.files[-1]
    record["lastwritetime"] = ArchiveTimestamp.from_datetime(e.mtime)
    # FILE_ATTRIBUTE_ARCHIVE, the Unix extension flag, the Unix mode above.
    record["attributes"] = 0x20 | 0x8000 | ((stat_mod.S_IFREG | (e.mode & 0o777)) << 16)


def _write_7z(backend, entries, out, opts, step, cancel, staging: str) -> None:
    import py7zr

    for e in entries:
        # 7z keeps names as UTF-16: a name that is not UTF-8 (its bytes kept
        # as surrogates) cannot go in. py7zr failed with a codec error that
        # named no file.
        try:
            e.arcname.encode("utf-16-le")
        except UnicodeEncodeError:
            shown = e.arcname.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
            raise PackError(f"7z cannot store the name {shown!r} (it is not UTF-8); "
                            "tar keeps it") from None

    filters = [{"id": py7zr.FILTER_LZMA2, "preset": opts.level_for("7z")}]
    if opts.password:
        filters.append({"id": py7zr.FILTER_CRYPTO_AES256_SHA256})
    local = _reads_direct(backend)
    empty_dir = os.path.join(staging, "dir")
    os.makedirs(empty_dir, exist_ok=True)
    with py7zr.SevenZipFile(
        out,
        "w",
        filters=filters,
        password=opts.password or None,
        header_encryption=bool(opts.password and opts.encrypt_names),
    ) as zf:
        for e in entries:
            if cancel is not None and cancel.is_set():
                raise PackCancelled("cancelled")
            if e.is_dir:
                # py7zr takes the time and mode of the file it is given:
                # the folder's own, not the staging folder's.
                _stamp_staged(empty_dir, e)
                zf.write(empty_dir, e.arcname)
                continue
            if local:
                # The file opened as the walk saw it (never through a link,
                # _open_source) is handed to py7zr: it read the path itself
                # (following a link put there) and stored the whole mode,
                # setuid bits too. The time and the mode (0o777 only) are
                # set on its record as zf.write() would have.
                fh, src = _open_source(backend, e, cancel)
                with fh:
                    if os.fstat(fh.fileno()).st_size != e.size:
                        raise PackError(f"{e.arcname} changed while packing")
                    zf.writef(fh, e.arcname)
                    if fh.tell() != e.size or os.fstat(fh.fileno()).st_size != e.size:
                        raise PackError(f"{e.arcname} changed while packing")
                _stamp_7z_record(zf, e)
            else:  # py7zr needs a seekable file: fetch one at a time
                tmp = os.path.join(staging, "file")
                fh, src = _open_source(backend, e, cancel)
                with fh, open(tmp, "wb") as dst:
                    _copy(src, dst)
                _stamp_staged(tmp, e)  # the file's time and mode, not the copy's
                zf.write(tmp, e.arcname)
                os.unlink(tmp)
            step(e)


def _local_temp(folder: str):
    """A new private file in *folder* for the archive while it is written,
    named as axross's other atomic writes (``.tmp-<12 hex>.tmp``): a pack
    killed half way (kill -9, a power cut) left ``.axross-pack-xxxx.tmp`` -
    a half archive - for good; this name the pane's sweep
    (core.atomic_recovery) removes once it is an hour old.

    ``(path, file)``: the writers write into the file opened here, never
    reopening the name - in a folder others can write to, the name swapped
    for a symlink between the two opens made the archive overwrite the
    link's target."""
    import secrets

    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) \
        | getattr(os, "O_CLOEXEC", 0)
    for _ in range(100):
        path = os.path.join(folder, f".tmp-{secrets.token_hex(6)}.tmp")
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            continue
        # named by its path (a bare fdopen() is named by the descriptor)
        return path, open(path, "w+b", opener=lambda _path, _flags: fd)
    raise PackError(f"no free temporary name in {folder}")


def archive_mode(entries) -> int:
    """The mode the archive gets: a new file's (0666 less the umask) - as
    private as the most private thing it holds. A file or folder that the
    group, or others, cannot read keeps the archive from them as well: the
    archive must not hand out what its sources did not. Owner read and
    write always."""
    from core.process_umask import process_umask

    allowed = 0o666
    for e in entries:
        group, other = (0o050, 0o005) if e.is_dir else (0o040, 0o004)
        if e.mode & group != group:
            allowed &= ~0o060
        if e.mode & other != other:
            allowed &= ~0o006
    return (allowed & ~process_umask()) | 0o600


def _write_single(backend, entries, raw, opts, step, cancel) -> None:
    files = [e for e in entries if not e.is_dir]
    if len(entries) != 1 or len(files) != 1:
        raise PackError(f"{FORMATS[opts.fmt].label} compresses exactly one file")
    comp = _compressor(opts.fmt, raw, opts, name=files[0].arcname.rsplit("/", 1)[-1])
    try:
        fh, src = _open_source(backend, files[0], cancel)
        with fh:
            _copy(src, comp)
    finally:
        comp.close()
    step(files[0])


# ---------------------------------------------------------------------------
# Putting it in place
# ---------------------------------------------------------------------------


def _unique(backend, folder: str, stem: str, suffix: str) -> str:
    candidate = backend.join(folder, stem + suffix)
    n = 2
    while backend.exists(candidate):
        candidate = backend.join(folder, f"{stem} ({n}){suffix}")
        n += 1
        if n > 10_000:
            raise PackError("no free archive name")
    return candidate


def _place_local(tmp: str, backend, folder: str, stem: str, suffix: str, check=None) -> str:
    for _attempt in range(100):
        target = _unique(backend, folder, stem, suffix)
        if check is not None:
            check(target)
        try:
            # fails instead of replacing an existing file; a link is not followed
            os.link(tmp, target, follow_symlinks=False)
        except FileExistsError:
            continue  # taken meanwhile: next name
        except OSError:
            if os.path.lexists(target):
                continue
            os.rename(tmp, target)  # a file system without hard links
            return target
        os.unlink(tmp)
        return target
    raise PackError("no free archive name")


def _place_confined(tmp: str, backend, folder: str, stem: str, suffix: str, cancel,
                    check=None, mode: int = 0o600) -> str:
    """Copy the archive to the first free name, created with O_EXCL beneath
    the confined backend's root (``create_new``): never over a file, never
    through a symlink. A failed copy removes what it wrote."""
    for _attempt in range(100):
        target = _unique(backend, folder, stem, suffix)
        if check is not None:
            check(target)
        try:
            dst = backend.create_new(target, mode)
        except FileExistsError:
            continue  # taken meanwhile: next name
        try:
            with dst, open(tmp, "rb") as src:
                while True:
                    if cancel is not None and cancel.is_set():
                        raise PackCancelled("cancelled")
                    chunk = src.read(CHUNK)
                    if not chunk:
                        break
                    dst.write(chunk)
        except BaseException:
            try:
                backend.remove(target)
            except OSError:
                pass
            raise
        return target
    raise PackError("no free archive name")


def _place_remote(tmp: str, backend, folder: str, stem: str, suffix: str, cancel,
                  check=None, mode: int | None = None) -> str:
    """Upload the archive under a hidden temporary name next to its place,
    then rename it there: a dropped connection leaves no truncated
    ``bundle.zip`` under the final name - at most the hidden part."""
    import secrets

    from core.path_policy import hidden_sibling_name
    from core.server_ops import server_side_move

    target = _unique(backend, folder, stem, suffix)
    if check is not None:
        check(target)
    name = target.rsplit(backend.separator(), 1)[-1]
    part = backend.join(folder, hidden_sibling_name(name, f".{secrets.token_hex(6)}.part"))
    try:
        with open(tmp, "rb") as src, backend.open_write(part) as dst:
            if mode is not None and mode & 0o066 != 0o066:
                # Private sources: the server's default mode (often 0644)
                # is narrowed before any of the archive is sent.
                try:
                    backend.chmod(part, mode)
                except (OSError, AttributeError, NotImplementedError) as exc:
                    log.info("pack: the mode of %s not set: %s", part, exc)
            while True:
                if cancel is not None and cancel.is_set():
                    raise PackCancelled("cancelled")
                chunk = src.read(CHUNK)
                if not chunk:
                    break
                dst.write(chunk)
        server_side_move(backend, part, target, overwrite=False)
    except BaseException:
        try:
            if backend.exists(part):
                backend.remove(part)
        except OSError:
            pass
        raise
    return target


def pack(
    backend,
    folder: str,
    names: list[str],
    archive_name: str,
    options: PackOptions,
    *,
    progress: Callable[[int, int, str], None] | None = None,
    cancel: threading.Event | None = None,
    refuse: Callable[[str], bool] | None = None,
    check_target: Callable[[str], None] | None = None,
) -> PackResult:
    """Pack *names* (entries of *folder*) into ``folder/archive_name +
    suffix``. *progress(done_files, total_files, name)* runs on the calling
    thread; *cancel* stops at the next file or chunk. *refuse(path)*: true
    for a source (a name, or anything below one) that is left out and
    listed in ``skipped`` instead. *check_target(path)*: run on each name
    the archive may get before it is made there (raises to refuse it)."""
    fmt = FORMATS[options.fmt]
    ok, reason = fmt.available()
    if not ok:
        raise PackError(reason)
    if options.password and not fmt.encrypts:
        raise PackError("a password needs the 7z format (ZIP and tar cannot encrypt safely)")
    stem = archive_name.strip()
    if stem in ("", ".", "..") or "/" in stem or "\\" in stem or "\x00" in stem:
        raise PackError(f"not a valid archive name: {archive_name!r}")
    if stem.lower().endswith(fmt.suffix):
        stem = stem[: -len(fmt.suffix)]

    special: list[str] = []
    unusable: list[str] = []
    entries, skipped = _collect(backend, folder, names, cancel, refuse, special, unusable)
    if fmt.single and (len(entries) != 1 or entries[0].is_dir):
        raise PackError(f"{fmt.label} compresses exactly one file")
    total = sum(1 for e in entries if not e.is_dir)
    result = PackResult(path="", skipped=skipped, special=special, unusable=unusable)
    result.folders = sum(1 for e in entries if e.is_dir)

    def step(entry: _Entry) -> None:
        result.files += 1
        result.bytes_in += entry.size
        if progress is not None:
            progress(result.files, total, entry.arcname)
        if cancel is not None and cancel.is_set():
            raise PackCancelled("cancelled")

    local = _is_local(backend)
    try:
        staging = _staging_folder(backend, folder)
    except OSError as exc:
        raise PackError(f"packing failed: no temporary folder: {exc}") from exc
    tmp = ""
    out = None
    mode = archive_mode(entries)
    try:
        # Inside the try: a folder that cannot be written is a PackError,
        # and the staging folder goes with the rest.
        if local:
            tmp, out = _local_temp(folder)
        else:
            tmp = os.path.join(staging, "archive")  # in the private staging folder
            out = open(tmp, "x+b")
        if fmt.fmt_id == "zip":
            _write_zip(backend, entries, out, options, step, cancel)
        elif fmt.fmt_id == "7z":
            _write_7z(backend, entries, out, options, step, cancel, staging)
        elif fmt.single:
            _write_single(backend, entries, out, options, step, cancel)
        else:
            _write_tar(backend, entries, out, options, step, cancel)
        if cancel is not None and cancel.is_set():
            raise PackCancelled("cancelled")
        out.flush()
        result.bytes_out = os.fstat(out.fileno()).st_size
        if local:
            # The usual mode of a new file once it is whole (private while
            # written): 0600 had every archive kept from the group and others.
            fchmod_private(out.fileno(), mode)
            written, named = os.fstat(out.fileno()), os.lstat(tmp)
            if (written.st_dev, written.st_ino) != (named.st_dev, named.st_ino):
                raise PackError(f"the temporary file {tmp} was replaced while packing")
        out.close()
        if local:
            result.path = _place_local(tmp, backend, folder, stem, fmt.suffix, check_target)
        elif hasattr(backend, "create_new"):
            result.path = _place_confined(tmp, backend, folder, stem, fmt.suffix, cancel,
                                          check_target, mode)
        else:
            result.path = _place_remote(tmp, backend, folder, stem, fmt.suffix, cancel,
                                        check_target, mode)
        return result
    except PackError:
        raise
    except (OSError, ValueError, EOFError, RuntimeError) as exc:
        raise PackError(f"packing failed: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 - py7zr raises its own types
        raise PackError(f"packing failed: {type(exc).__name__}: {exc}") from exc
    finally:
        if out is not None:
            try:
                out.close()
            except OSError:
                pass
        if tmp and os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
        shutil.rmtree(staging, ignore_errors=True)
        from core import partials

        with _STAGING_LOCK:
            partials.done(_STAGING.pop(staging, None))


__all__ = [
    "FORMATS",
    "LEVELS",
    "archive_mode",
    "MAX_PACK_FILES",
    "Format",
    "PackCancelled",
    "PackError",
    "PackOptions",
    "PackResult",
    "default_name",
    "pack",
    "zstd_decompress",
]
