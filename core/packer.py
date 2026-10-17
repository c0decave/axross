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

import bz2
import gzip
import io
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

#: Files (not folders) one run packs at most.
MAX_PACK_FILES = 200_000
CHUNK = 1024 * 1024
LEVELS = {"fast": 0, "normal": 1, "best": 2}
_TEMP_PREFIX = ".axross-pack-"


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
    skipped: list[str] = field(default_factory=list)  # symlinks, by archive name


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


def _is_local(backend) -> bool:
    from core.local_fs import LocalFS

    return isinstance(backend, LocalFS)


def _mtime(item) -> float:
    modified = getattr(item, "modified", None)
    try:
        return max(315532800.0, modified.timestamp())  # 1980: ZIP's earliest
    except (AttributeError, OSError, OverflowError, ValueError):
        return time.time()


def _collect(backend, folder: str, names: list[str], cancel) -> tuple[list[_Entry], list[str]]:
    try:
        listing = {i.name: i for i in backend.list_dir(folder)}
    except OSError as exc:
        raise PackError(f"cannot list {folder}: {exc}") from exc
    entries: list[_Entry] = []
    skipped: list[str] = []
    files = 0

    def add(item, path: str, arcname: str) -> None:
        nonlocal files
        if cancel is not None and cancel.is_set():
            raise PackCancelled("cancelled")
        if getattr(item, "is_link", False):
            skipped.append(arcname)
            return
        if item.is_dir:
            entries.append(_Entry(arcname, path, True, 0, _mtime(item)))
            try:
                children = backend.list_dir(path)
            except OSError as exc:
                raise PackError(f"cannot list {arcname}: {exc}") from exc
            for child in sorted(children, key=lambda c: c.name):
                if child.name in ("..", "."):
                    continue
                add(child, backend.join(path, child.name), f"{arcname}/{child.name}")
            return
        files += 1
        if files > MAX_PACK_FILES:
            raise PackError(f"more than {MAX_PACK_FILES} files - pack fewer at a time")
        entries.append(_Entry(arcname, path, False, max(0, int(item.size or 0)), _mtime(item)))

    for name in names:
        if name in ("", ".", "..") or "/" in name or "\\" in name:
            raise PackError(f"not a name in this folder: {name!r}")
        item = listing.get(name)
        if item is None:
            raise PackError(f"cannot read {name}: not found in {folder}")
        add(item, backend.join(folder, name), name)
    return entries, skipped


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


def _open_source(backend, entry: _Entry, cancel) -> tuple[object, _Exact]:
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


def _write_zip(backend, entries, out_path, opts, step, cancel) -> None:
    level = opts.level_for("deflate")
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED, compresslevel=level) as zf:
        for e in entries:
            stamp = time.localtime(e.mtime)[:6]
            if e.is_dir:
                info = zipfile.ZipInfo(e.arcname + "/", date_time=stamp)
                info.external_attr = (stat_mod.S_IFDIR | 0o755) << 16 | 0x10
                zf.writestr(info, b"")
                continue
            info = zipfile.ZipInfo(e.arcname, date_time=stamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat_mod.S_IFREG | 0o644) << 16
            fh, src = _open_source(backend, e, cancel)
            with fh, zf.open(info, "w", force_zip64=e.size > 0x7FFFFFFF) as dst:
                _copy(src, dst)
            step(e)


def _compressor(fmt: str, raw, opts: PackOptions):
    codec = fmt.split(".")[-1]
    if codec == "gz":
        return gzip.GzipFile(
            fileobj=raw, mode="wb", compresslevel=opts.level_for("deflate"), mtime=0
        )
    if codec == "bz2":
        return bz2.BZ2File(raw, "wb", compresslevel=opts.level_for("bz2"))
    if codec == "xz":
        return lzma.LZMAFile(raw, "wb", preset=opts.level_for("xz"))
    if codec == "zst":
        return zstd_writer(raw, opts.level_for("zst"))
    raise PackError(f"no compressor for {fmt}")


def _write_tar(backend, entries, out_path, opts, step, cancel) -> None:
    with open(out_path, "wb") as raw:
        comp = _compressor(opts.fmt, raw, opts)
        try:
            with tarfile.open(fileobj=comp, mode="w|", format=tarfile.PAX_FORMAT) as tf:
                for e in entries:
                    info = tarfile.TarInfo(e.arcname)
                    info.mtime = int(e.mtime)
                    if e.is_dir:
                        info.type = tarfile.DIRTYPE
                        info.mode = 0o755
                        tf.addfile(info)
                        continue
                    info.size = e.size
                    info.mode = 0o644
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


def _write_7z(backend, entries, out_path, opts, step, cancel, staging: str) -> None:
    import py7zr

    filters = [{"id": py7zr.FILTER_LZMA2, "preset": opts.level_for("7z")}]
    if opts.password:
        filters.append({"id": py7zr.FILTER_CRYPTO_AES256_SHA256})
    local = _is_local(backend)
    empty_dir = os.path.join(staging, "dir")
    os.makedirs(empty_dir, exist_ok=True)
    with py7zr.SevenZipFile(
        out_path,
        "w",
        filters=filters,
        password=opts.password or None,
        header_encryption=bool(opts.password and opts.encrypt_names),
    ) as zf:
        for e in entries:
            if cancel is not None and cancel.is_set():
                raise PackCancelled("cancelled")
            if e.is_dir:
                zf.write(empty_dir, e.arcname)
                continue
            if local:
                fh, src = _open_source(backend, e, cancel)  # checks the size, too
                with fh:
                    while src.read(CHUNK):
                        pass
                    src.finish()
                zf.write(e.path, e.arcname)
            else:  # py7zr needs a seekable file: fetch one at a time
                tmp = os.path.join(staging, "file")
                fh, src = _open_source(backend, e, cancel)
                with fh, open(tmp, "wb") as dst:
                    _copy(src, dst)
                zf.write(tmp, e.arcname)
                os.unlink(tmp)
            step(e)


def _write_single(backend, entries, out_path, opts, step, cancel) -> None:
    files = [e for e in entries if not e.is_dir]
    if len(entries) != 1 or len(files) != 1:
        raise PackError(f"{FORMATS[opts.fmt].label} compresses exactly one file")
    with open(out_path, "wb") as raw:
        comp = _compressor(opts.fmt, raw, opts)
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


def _place_local(tmp: str, backend, folder: str, stem: str, suffix: str) -> str:
    for _attempt in range(100):
        target = _unique(backend, folder, stem, suffix)
        try:
            os.link(tmp, target)  # fails instead of replacing an existing file
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


def _place_remote(tmp: str, backend, folder: str, stem: str, suffix: str, cancel) -> str:
    target = _unique(backend, folder, stem, suffix)
    try:
        with open(tmp, "rb") as src, backend.open_write(target) as dst:
            while True:
                if cancel is not None and cancel.is_set():
                    raise PackCancelled("cancelled")
                chunk = src.read(CHUNK)
                if not chunk:
                    break
                dst.write(chunk)
    except BaseException:
        try:
            if backend.exists(target):
                backend.remove(target)
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
) -> PackResult:
    """Pack *names* (entries of *folder*) into ``folder/archive_name +
    suffix``. *progress(done_files, total_files, name)* runs on the calling
    thread; *cancel* stops at the next file or chunk."""
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

    entries, skipped = _collect(backend, folder, names, cancel)
    if fmt.single and (len(entries) != 1 or entries[0].is_dir):
        raise PackError(f"{fmt.label} compresses exactly one file")
    total = sum(1 for e in entries if not e.is_dir)
    result = PackResult(path="", skipped=skipped)
    result.folders = sum(1 for e in entries if e.is_dir)

    def step(entry: _Entry) -> None:
        result.files += 1
        result.bytes_in += entry.size
        if progress is not None:
            progress(result.files, total, entry.arcname)
        if cancel is not None and cancel.is_set():
            raise PackCancelled("cancelled")

    local = _is_local(backend)
    staging = tempfile.mkdtemp(prefix="axross-pack-")
    if local:
        fd, tmp = tempfile.mkstemp(prefix=_TEMP_PREFIX, suffix=".tmp", dir=folder)
        os.close(fd)
    else:
        tmp = os.path.join(staging, "archive")
    try:
        if fmt.fmt_id == "zip":
            _write_zip(backend, entries, tmp, options, step, cancel)
        elif fmt.fmt_id == "7z":
            if os.path.exists(tmp):
                os.unlink(tmp)  # py7zr creates the file itself
            _write_7z(backend, entries, tmp, options, step, cancel, staging)
        elif fmt.single:
            _write_single(backend, entries, tmp, options, step, cancel)
        else:
            _write_tar(backend, entries, tmp, options, step, cancel)
        if cancel is not None and cancel.is_set():
            raise PackCancelled("cancelled")
        result.bytes_out = os.path.getsize(tmp)
        if local:
            result.path = _place_local(tmp, backend, folder, stem, fmt.suffix)
        else:
            result.path = _place_remote(tmp, backend, folder, stem, fmt.suffix, cancel)
        return result
    except PackError:
        raise
    except (OSError, ValueError, EOFError, RuntimeError) as exc:
        raise PackError(f"packing failed: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 - py7zr raises its own types
        raise PackError(f"packing failed: {type(exc).__name__}: {exc}") from exc
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
        shutil.rmtree(staging, ignore_errors=True)


__all__ = [
    "FORMATS",
    "LEVELS",
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
