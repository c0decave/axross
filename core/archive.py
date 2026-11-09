"""Safe archive extraction to a local directory.

Supported formats
-----------------
* **ZIP family** via ``zipfile``: ``.zip``, ``.xpi``, ``.jar``,
  ``.war``, ``.apk``, ``.epub``, ``.docx``, ``.xlsx``, ``.odt``.
  All share the ZIP container format; only the filename extension
  differs.
* **TAR family** via ``tarfile``: ``.tar``, ``.tar.gz`` / ``.tgz``,
  ``.tar.bz2`` / ``.tbz2``, ``.tar.xz`` / ``.txz``.
* **7z** via ``py7zr`` (optional — returns ``SEVEN_Z_AVAILABLE=False``
  when the package isn't installed).

Safety contract
---------------
Every extraction enforces:

1. **Zip-slip guard** — each entry's resolved absolute path must
   stay under ``target_dir`` after ``realpath`` + ``normpath``. An
   entry like ``../../../etc/passwd`` is refused and no files are
   written (the target dir is removed before raising so there's no
   partial state).
2. **No absolute-path entries** — refused upfront.
3. **No symlink / hardlink entries** — a tar symlink or hardlink
   member, and a ZIP member whose Unix mode says symlink (Info-ZIP
   ``zip -y``), is left out: nothing is written for it, and its name
   is in :attr:`ExtractResult.skipped_links`. Any other non-file,
   non-directory tar member (device, FIFO) refuses the archive.
4. **Size / count / ratio caps** — an archive that claims to
   expand to more than ``MAX_EXTRACT_TOTAL_BYTES`` OR contains
   more than ``MAX_EXTRACT_FILES`` entries OR shows a per-entry
   compression ratio above ``MAX_COMPRESSION_RATIO`` is refused
   as a likely zip-bomb.

Cancellation
------------
The ``progress`` callback is invoked between entries with
``(files_done, files_total, current_name)``. Callbacks may raise
:class:`ExtractCancelled` to abort in flight; the partially-
populated target dir is removed before the exception propagates.

Collision handling
------------------
:func:`auto_suffix_dir` picks a non-existing directory name —
``foo``, ``foo-1``, ``foo-2``, … — so callers can repeatedly
extract the same archive without clobbering earlier extractions.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import logging
import os
import posixpath
import shutil
import stat
import tarfile
import tempfile
import time
import zipfile
from dataclasses import dataclass
from typing import Callable

log = logging.getLogger(__name__)


def _installed(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):  # pragma: no cover - a broken install
        return False


# py7zr is imported at its first use, not with this module: it pulls in
# Cryptodome, cffi and pycparser - about 70 % of this module's import time,
# paid on the GUI thread at the first double-click on any file and the
# first Find Files (core.file_search imports this module).
SEVEN_Z_AVAILABLE = _installed("py7zr")
py7zr = None  # the module once _seven_zip() has imported it


def _seven_zip(what: str):
    """The py7zr module, imported now if not yet; UnsafeArchive naming
    *what* (\"7z listing\") when it cannot be imported."""
    global py7zr, SEVEN_Z_AVAILABLE
    if py7zr is None:
        try:
            import py7zr as module  # type: ignore[import-not-found]
        except ImportError as exc:
            SEVEN_Z_AVAILABLE = False
            raise UnsafeArchive(
                f"{what} requires py7zr — install with: pip install py7zr",
            ) from exc
        py7zr = module
    return py7zr


try:  # pragma: no cover — optional dep
    import rarfile  # type: ignore[import-not-found]

    RAR_AVAILABLE = True
except ImportError:  # pragma: no cover
    rarfile = None  # type: ignore[assignment]
    RAR_AVAILABLE = False
# NOTE: ``RAR_AVAILABLE`` reflects ONLY whether the ``rarfile`` *package*
# imports — there is no backend probe here. A missing ``unrar``/``unar``
# *tool* is detected at call time (rarfile shells out to it on first
# read) and surfaced as :class:`RarUnavailable` via the
# ``RarCannotExec``/``RarExecError`` catch in ``_extract_rar`` / ``_list_rar``.


# --------------------------------------------------------------------------
# Config caps
# --------------------------------------------------------------------------

# Max number of entries we'll extract from one archive. A zip bomb
# can claim millions of small files to exhaust inodes; 10k is above
# any realistic real-world archive.
MAX_EXTRACT_FILES = 10_000

# Max entries of one archive that are listed (the archive preview, an
# archive nested in another, MCP list_archive) or read to extract a
# selection of it. Every entry costs memory while it is listed (~700
# bytes measured), and tar headers compress to almost nothing: a 918 KiB
# tar.gz held 200 000 of them. Linux kernel sources hold about 90 000.
MAX_LIST_ENTRIES = 250_000

# Max total uncompressed bytes. 1 GiB is generous for realistic
# archives (a 600 MiB app-bundle expands to a few hundred MiB),
# tight enough that a 42-kB bomb expanding to 4 GiB is refused.
MAX_EXTRACT_TOTAL_BYTES = 1 * 1024 * 1024 * 1024

# Max bytes the members of a compressed tar declare before a listing (the
# archive preview, MCP archive_list, a selection's extraction) stops. A
# compressed tar has no index: every member's data is decompressed to
# reach the next header, so a 2.4 KB .tar.bz2 declaring one 10 TB member
# kept a core busy for hours. A plain .tar is skipped through by seeking
# and has no such limit.
MAX_LIST_TAR_BYTES = 8 * MAX_EXTRACT_TOTAL_BYTES
# The most of a compressed tar's stream that one read may take: a header's
# own data (a GNU long name, a pax header) is read whole, in one call,
# before anyone can count it. Member data is read in 64 KiB chunks.
MAX_TAR_READ = 16 * 1024 * 1024

# Max per-entry compression ratio (uncompressed / max(1,compressed)).
# The canonical "zip of zeros" bomb hits ratios of 1000:1. 100:1
# accommodates legitimate text archives (which can legitimately
# compress 20:1 or so) without admitting the pathological case.
MAX_COMPRESSION_RATIO = 100

# An archive inside an archive is opened in the preview by extracting it
# (with every guard above) to a temp folder first. Each level is one more
# such copy, so both the depth and the size of one nested archive are
# bounded: four levels of 256 MiB are at most 1 GiB of temp files.
MAX_NESTED_DEPTH = 4
MAX_NESTED_ARCHIVE_BYTES = 256 * 1024 * 1024


# --------------------------------------------------------------------------
# Extension table — single source of truth for "is this extractable?"
# --------------------------------------------------------------------------

_ZIP_EXTENSIONS = (
    ".zip",
    ".xpi",
    ".jar",
    ".war",
    ".apk",
    ".epub",
    ".docx",
    ".xlsx",
    ".odt",
)
_TAR_EXTENSIONS = (
    # Compound extensions MUST be listed before their plain .tar
    # counterpart so the extension-stripping logic grabs the longer
    # match first.
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
    ".tar.zst",
    ".tzst",
    ".tar",
)
_SEVEN_Z_EXTENSIONS = (".7z",)
_RAR_EXTENSIONS = (".rar",)
# One compressed file, no container. Checked after the TAR table so
# ".tar.gz" stays a tarball.
_SINGLE_EXTENSIONS = (".gz", ".bz2", ".xz", ".zst")
_ZSTD_EXTENSIONS = (".tar.zst", ".tzst", ".zst")


def _zstd_available() -> bool:
    from core import packer

    return packer.FORMATS["zst"].available()[0]


def _tarfile_knows_zstd() -> bool:
    return "zst" in getattr(tarfile.TarFile, "OPEN_METH", {})


def _ext_usable(ext: str) -> bool:
    return ext not in _ZSTD_EXTENSIONS or _zstd_available()


def _single_ext(lower: str) -> str | None:
    """The single-file extension of *lower*, unless it is a tarball."""
    if any(lower.endswith(ext) for ext in _TAR_EXTENSIONS):
        return None
    return next((ext for ext in _SINGLE_EXTENSIONS if lower.endswith(ext)), None)


class ExtractCancelled(Exception):
    """Raised by callers' ``progress`` callback to abort an extraction.
    :func:`extract` catches it, removes the partially-populated target
    directory, and re-raises."""


class UnsafeArchive(ValueError):
    """Raised when an archive trips one of the safety guards: zip-
    slip path, absolute-path entry, symlink entry, per-entry size or
    count cap, bomb-ratio cap. The caller should surface this to the
    user as "this archive was refused"; NEVER treat it as a transient
    error — an attacker crafted the archive specifically to trigger
    it, retrying gives them another shot."""


class RarUnavailable(RuntimeError):
    """Raised when a ``.rar`` archive is listed/extracted but the
    optional ``rarfile`` package and/or its backend tool isn't usable.
    Carries a fixed remediation hint so callers can surface it
    verbatim. Distinct from :class:`UnsafeArchive` — this is a missing-
    capability condition, NOT a refused/hostile archive."""


_RAR_UNAVAILABLE_MSG = (
    "RAR support requires the 'rarfile' package and an 'unrar'/'unar' "
    "tool — pip install rarfile"
)


# --------------------------------------------------------------------------
# Listing model
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ArchiveEntry:
    """One member of an archive as reported by :func:`list_archive`.

    Read-only metadata only — listing never extracts content. ``size``
    is the uncompressed byte count; ``compressed`` the stored byte
    count (for TAR family, which has no per-member compressed size,
    ``compressed`` mirrors ``size``). ``mtime`` is an epoch float when
    the format records one and we can decode it, else ``None``.
    """

    name: str
    size: int
    compressed: int
    mtime: float | None
    is_dir: bool
    #: The stored permission bits (``0o644``), None when the format or the
    #: maker of the archive stores none.
    mode: int | None = None
    #: ``file``, ``dir``, ``symlink``, ``hardlink`` or ``other`` (a device
    #: or FIFO entry of a tar). Extraction refuses all but files and dirs.
    kind: str = "file"

    @property
    def ratio(self) -> float:
        """Space-saving fraction in ``[0.0, 1.0]``: ``1 - compressed/size``.
        ``0.0`` when ``size <= 0`` (empty/dir entry, no division) and
        clamped at ``0.0`` when an entry stored larger than its
        original (``compressed > size``)."""
        if self.size <= 0:
            return 0.0
        return max(0.0, 1.0 - self.compressed / self.size)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def is_supported_archive(name_or_path: str) -> bool:
    """True iff the filename matches a supported archive extension.
    Case-insensitive. ``.7z`` is included only when ``py7zr`` is
    importable and ``.rar`` only when ``rarfile`` is importable;
    extracting either without the library would fail late, and hiding
    the menu item up-front is the honest UX."""
    lower = name_or_path.lower()
    for ext in _ZIP_EXTENSIONS + _TAR_EXTENSIONS:
        if lower.endswith(ext):
            return _ext_usable(ext)
    single = _single_ext(lower)
    if single is not None:
        return _ext_usable(single)
    if SEVEN_Z_AVAILABLE:
        for ext in _SEVEN_Z_EXTENSIONS:
            if lower.endswith(ext):
                return True
    if RAR_AVAILABLE:
        for ext in _RAR_EXTENSIONS:
            if lower.endswith(ext):
                return True
    return False


def archive_family(name_or_path: str) -> str | None:
    """How :func:`list_archive` would read *name_or_path*: ``"zip"``,
    ``"tar"``, ``"single"`` (one compressed file), ``"7z"`` or ``"rar"``
    - or ``None`` when the name is no archive this installation can read
    (the same availability rules as :func:`is_supported_archive`)."""
    if not is_supported_archive(name_or_path):
        return None
    lower = name_or_path.lower()
    if lower.endswith(_RAR_EXTENSIONS):
        return "rar"
    if lower.endswith(_TAR_EXTENSIONS):
        return "tar"
    if lower.endswith(_ZIP_EXTENSIONS):
        return "zip"
    if lower.endswith(_SEVEN_Z_EXTENSIONS):
        return "7z"
    return "single"


def check_bomb_ratio(uncompressed: int, compressed: int, member_name: str) -> None:
    """Raise :class:`UnsafeArchive` when one member's compression ratio
    is above :data:`MAX_COMPRESSION_RATIO` - the guard extraction uses,
    for callers that read members themselves (Find Files)."""
    _check_bomb_ratio(uncompressed, compressed, member_name)


def strip_archive_extension(name_or_path: str) -> str:
    """Return the basename of *name_or_path* with its archive
    extension removed. Compound extensions (``.tar.gz`` etc.) are
    recognised and both parts are stripped. Returns the basename
    verbatim when no extension matches — caller must decide whether
    that's a bug or a pass-through."""
    base = os.path.basename(name_or_path)
    lower = base.lower()
    for ext in _TAR_EXTENSIONS + _ZIP_EXTENSIONS + _SEVEN_Z_EXTENSIONS + _RAR_EXTENSIONS:
        if lower.endswith(ext):
            return base[: -len(ext)]
    single = _single_ext(lower)
    if single is not None:
        return base[: -len(single)]
    return base


def auto_suffix_dir(parent: str, base: str) -> str:
    """Return an absolute path for a directory named *base* under
    *parent* that does NOT yet exist. Tries the plain base first,
    then ``base-1``, ``base-2``, … up to 999; raises OSError if the
    counter wraps (clearly a bug in the caller's flow — 999
    identical extractions in one folder is not a real workload).

    Pure path math — does not create the directory.
    """
    # lexists: a dangling symlink is a taken name too (exists() says no).
    candidate = os.path.join(parent, base)
    if not os.path.lexists(candidate):
        return candidate
    for i in range(1, 1000):
        candidate = os.path.join(parent, f"{base}-{i}")
        if not os.path.lexists(candidate):
            return candidate
    raise OSError(
        f"auto_suffix_dir: exhausted 999 suffix candidates under "
        f"{parent!r} for base {base!r} — clean up before retrying",
    )


# --------------------------------------------------------------------------
# Safety probes
# --------------------------------------------------------------------------


class ExtractResult(int):
    """What :func:`extract` and :func:`extract_members` did: the number of
    regular files written (an ``int``, as these returned before) and the
    link members left out (:attr:`skipped_links`, archive names).

    A symlink member used to refuse a whole tarball, and a ZIP symlink was
    written as a regular 0755 file holding the link's target path; links
    are skipped now, never followed or created."""

    skipped_links: list[str]

    def __new__(cls, written: int = 0, skipped_links=()):
        obj = super().__new__(cls, written)
        obj.skipped_links = list(skipped_links)
        return obj

    def __repr__(self) -> str:
        return f"ExtractResult({int(self)}, skipped_links={self.skipped_links!r})"


def _zip_is_link(info: zipfile.ZipInfo) -> bool:
    """A ZIP member whose Unix mode is a symlink (Info-ZIP ``zip -y``): its
    data is the link's target path, not file content."""
    return info.create_system == 3 and stat.S_ISLNK(info.external_attr >> 16)


def _as_result(written, skipped: list[str]) -> ExtractResult:
    if skipped:
        log.info("archive: %d link member(s) left out: %s", len(skipped), ", ".join(skipped[:20]))
    return ExtractResult(int(written), skipped)


def _write_member_file(dest: str, src, mode: int | None, mtime: float | None) -> None:
    """Write one member's bytes to *dest* with its stored mode and time.

    The file is created with the member's rwx bits (set-id and sticky
    bits dropped; the umask applies, as with tar for a normal user), so a
    0600 member never sits readable by others while it is written. A
    member without a stored mode gets the default 0666 less the umask.
    """
    perm = (mode & 0o777) if mode else 0o666
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(dest, flags, perm)
    with os.fdopen(fd, "wb") as dst:
        shutil.copyfileobj(src, dst, length=64 * 1024)
    if mtime is not None and mtime > 0:
        try:
            os.utime(dest, (mtime, mtime))
        except (OSError, OverflowError, ValueError) as exc:
            log.debug("archive: cannot set the time of %s: %s", dest, exc)


def _member_parts(member_name: str) -> list[str]:
    """The folders and name of a member below the target, as written there
    (``a/./b/../c`` -> ``["a", "c"]``); UnsafeArchive for one that leaves it."""
    norm = posixpath.normpath(member_name.replace("\\", "/"))
    if norm in ("", "."):
        return []
    if norm == ".." or norm.startswith(("../", "/")):
        raise UnsafeArchive(f"archive entry escapes target directory: {member_name!r}")
    return norm.split("/")


class _Sink:
    """Where one extraction writes: the target folder it created.

    POSIX: a descriptor of the target folder, opened right after it was
    created (``O_NOFOLLOW``, relative to its parent's descriptor). Every
    folder and file of a member is created relative to it, component by
    component, without following a symlink (core.confined_fs), and a file
    is created with ``O_EXCL`` - another process that writes in the same
    tree (it swaps a folder just created for a symlink to
    ``~/.config/autostart``, or plants a hard link) makes the extraction
    fail instead of writing outside. 7z and RAR, whose libraries write by
    path, extract into a private temporary folder first and are copied in.
    Without ``dir_fd`` (Windows) the paths are used, as before.
    """

    def __init__(self, target: str, parent_fd: int | None = None, name: str = "",
                 fd: int | None = None) -> None:
        self.target = target
        self.parent_fd = parent_fd
        self.name = name
        self.fd = fd

    @classmethod
    def create(cls, target: str, parent_dir=None) -> "_Sink":
        """Create the folder *target* (0o755; FileExistsError when it is
        there) and the sink writing into it. *parent_dir(target)*: a context
        manager giving ``(descriptor of the parent folder, name)`` - the MCP
        server's confined backend (core.confined_fs.ConfinedLocalFS.parent_dir);
        else the parent folder is opened by its path (made when missing)."""
        from core import confined_fs as CF

        if not CF.FD_CONFINED:
            os.makedirs(target, mode=0o755, exist_ok=False)
            if os.path.islink(target):
                try:
                    os.unlink(target)
                except OSError:
                    pass
                raise UnsafeArchive(
                    f"target directory {target!r} is a symlink — refusing "
                    "to extract into an indirection (likely symlink-swap "
                    "race from another local process)",
                )
            return cls(target)
        if parent_dir is not None:
            with parent_dir(target) as (pfd, name):
                return cls._made_in(target, pfd, name)
        folder, name = os.path.split(os.path.abspath(target))
        os.makedirs(folder, exist_ok=True)
        pfd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
        try:
            return cls._made_in(target, pfd, name)
        finally:
            os.close(pfd)

    @classmethod
    def _made_in(cls, target: str, pfd: int, name: str) -> "_Sink":
        os.mkdir(name, 0o755, dir_fd=pfd)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(name, flags, dir_fd=pfd)
        except OSError as exc:
            # The folder just made was swapped for a symlink (ELOOP, or
            # ENOTDIR for one to a file) by another local process.
            raise UnsafeArchive(
                f"target directory {target!r} is a symlink — refusing "
                "to extract into an indirection (likely symlink-swap "
                "race from another local process)",
            ) from exc
        return cls(target, os.dup(pfd), name, fd)

    def _confined(self, what):
        """Run *what()*; a symlink or a file that appeared in the way is
        UnsafeArchive (the extraction is refused and removed)."""
        from core import confined_fs as CF

        try:
            return what()
        except CF.SymlinkRefused as exc:
            raise UnsafeArchive(
                f"a symbolic link appeared in the extraction folder {self.target!r} - "
                "refused (another process changes it while it is extracted)"
            ) from exc
        except FileExistsError as exc:
            raise UnsafeArchive(
                f"a file appeared in the extraction folder {self.target!r} while it was "
                "extracted - refused"
            ) from exc

    def makedirs(self, member_name: str, dest: str) -> None:
        if self.fd is None:
            os.makedirs(dest, exist_ok=True)
            return
        from core import confined_fs as CF

        parts = _member_parts(member_name)
        os.close(self._confined(lambda: CF.makedirs_beneath(self.fd, parts, path=dest)))

    def open_new(self, member_name: str, dest: str, perm: int = 0o666):
        """A new file for the member, open for writing (``O_EXCL``)."""
        if self.fd is None:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            return open(dest, "xb")
        from core import confined_fs as CF

        parts = _member_parts(member_name)
        if not parts:
            raise UnsafeArchive(f"archive entry has empty/root path: {member_name!r}")

        def make():
            dfd = CF.makedirs_beneath(self.fd, parts[:-1], path=dest)
            try:
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
                return CF.open_beneath(dfd, parts[-1:], flags, perm, path=dest)
            finally:
                os.close(dfd)

        return os.fdopen(self._confined(make), "wb")

    def write(self, member_name: str, dest: str | None, src, mode: int | None,
              mtime: float | None) -> None:
        """A member's bytes, with its stored mode and time (see
        :func:`_write_member_file`)."""
        if self.fd is None:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            _write_member_file(dest, src, mode, mtime)
            return
        perm = (mode & 0o777) if mode else 0o666
        with self.open_new(member_name, dest or member_name, perm) as dst:
            shutil.copyfileobj(src, dst, length=64 * 1024)
            dst.flush()
            if mtime is not None and mtime > 0:
                try:
                    os.utime(dst.fileno(), (mtime, mtime))
                except (OSError, OverflowError, ValueError) as exc:
                    log.debug("archive: cannot set the time of %s: %s", member_name, exc)

    def staged(self, extract_into: Callable[[str], None]) -> None:
        """Run *extract_into(folder)* of a library that writes by path
        (py7zr, rarfile): without a descriptor into the target itself, else
        into a private temporary folder whose files are then copied in."""
        if self.fd is None:
            extract_into(self.target)
            return
        staging = tempfile.mkdtemp(prefix="axross-extract-")
        try:
            extract_into(staging)
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        self._adopt(staging)

    def _adopt(self, staging: str) -> None:
        """Copy what a library extracted into *staging* into the target
        (regular files and folders only), then remove *staging*."""
        try:
            for dirpath, dirnames, filenames in os.walk(staging, followlinks=False):
                rel = os.path.relpath(dirpath, staging)
                base = "" if rel == "." else rel.replace(os.sep, "/") + "/"
                for d in dirnames:
                    if not os.path.islink(os.path.join(dirpath, d)):
                        self.makedirs(base + d, "")
                for f in filenames:
                    path = os.path.join(dirpath, f)
                    st = os.lstat(path)
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    with open(path, "rb") as src:
                        self.write(base + f, None, src, stat.S_IMODE(st.st_mode), st.st_mtime)
        finally:
            shutil.rmtree(staging, ignore_errors=True)

    def measure(self) -> int:
        """The bytes of the regular files in the target (see
        :func:`_measure_tree_bytes`)."""
        if self.fd is None:
            return _measure_tree_bytes(self.target)
        total = 0
        for _dirpath, _dirs, filenames, dfd in os.fwalk(".", dir_fd=self.fd,
                                                         follow_symlinks=False):
            for name in filenames:
                try:
                    st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISREG(st.st_mode):
                    total += st.st_size
        return total

    def discard(self) -> None:
        """Remove the target and everything in it (a refused or failed
        extraction) - by descriptor: the folder this extraction made, even
        when another process renamed it or put a symlink in its place."""
        if self.fd is None:
            shutil.rmtree(self.target, ignore_errors=True)
            return
        try:
            there = os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False)
            same = os.path.samestat(there, os.fstat(self.fd))
        except OSError:
            same = False
        if same:
            shutil.rmtree(self.name, dir_fd=self.parent_fd, ignore_errors=True)
            return
        try:
            names = os.listdir(self.fd)
        except OSError:
            return
        for entry in names:
            try:
                st = os.stat(entry, dir_fd=self.fd, follow_symlinks=False)
                if stat.S_ISDIR(st.st_mode):
                    shutil.rmtree(entry, dir_fd=self.fd, ignore_errors=True)
                else:
                    os.unlink(entry, dir_fd=self.fd)
            except OSError:
                pass

    def close(self) -> None:
        for fd in (self.fd, self.parent_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        self.fd = self.parent_fd = None


def _zip_mode(info: zipfile.ZipInfo) -> int | None:
    """The Unix mode a ZIP made on Unix stores, None for any other maker."""
    if info.create_system != 3:
        return None
    return (info.external_attr >> 16) & 0o7777 or None


def _zip_mtime(info: zipfile.ZipInfo) -> float | None:
    try:
        return time.mktime(tuple(info.date_time) + (0, 0, -1))
    except (OverflowError, ValueError):
        return None


def _is_root_dir_entry(member_name: str) -> bool:
    """True for a directory entry that names the extraction root itself.

    ``tar -C dir -czf x.tgz .`` stores the folder as ``./``, which tarfile
    reports as ``.``: nothing to create, and no reason to refuse the whole
    archive. Only relative spellings made of ``.`` segments count; an
    absolute ``/`` and anything with ``..`` stay with the zip-slip check.
    """
    normalised = member_name.replace("\\", "/")
    if not normalised or normalised.startswith("/"):
        return False
    return all(part in ("", ".") for part in normalised.split("/"))


def _safe_member_path(target_root: str, member_name: str) -> str:
    """Resolve *member_name* under *target_root* and refuse any
    escape. Returns the absolute path to extract to. Raises
    :class:`UnsafeArchive` on:

    * absolute paths (``/etc/passwd``, ``C:\\foo``)
    * path traversal (``..``) that escapes *target_root*
    * NUL bytes (some archive formats tolerate them; the filesystem
      doesn't)
    """
    if "\x00" in member_name:
        raise UnsafeArchive(
            f"archive entry name contains NUL byte: {member_name!r}",
        )
    normalised = member_name.replace("\\", "/")
    if normalised in {"", "."}:
        raise UnsafeArchive(
            f"archive entry has empty/root path: {member_name!r}",
        )
    # Absolute paths are never allowed — Python's os.path.join would
    # silently drop target_root when the second arg is absolute.
    if os.path.isabs(member_name) or (
        len(member_name) >= 2 and member_name[1] == ":"  # Windows drive
    ):
        raise UnsafeArchive(
            f"archive entry has absolute path: {member_name!r}",
        )
    # Normalise forward slashes to the host separator for the join,
    # then resolve + check containment.
    joined = os.path.join(target_root, normalised)
    # realpath collapses ``..`` AND any symlink in the ancestor chain
    # of target_root — the comparison is against the *resolved* form.
    resolved_root = os.path.realpath(target_root)
    resolved_member = os.path.realpath(joined)
    # Must be equal to the root OR a descendant. Use os.sep in the
    # check so ``target_root_evil`` isn't accepted as a prefix of
    # ``target_root``.
    if resolved_member != resolved_root and not resolved_member.startswith(resolved_root + os.sep):
        raise UnsafeArchive(
            f"archive entry escapes target directory: {member_name!r} "
            f"would write to {resolved_member!r}",
        )
    return resolved_member


class _TarBudget:
    """A compressed tar's decompressed stream that refuses to go past
    *limit* bytes, and any single read above :data:`MAX_TAR_READ` - before
    the decompressor does the work (tarfile seeks over member data and
    reads a header's own data in one call). While :attr:`poll` is set, a
    long seek forward goes in steps of :data:`_SEEK_STEP` and polls between
    them, so Cancel stops even the skip over one big member."""

    def __init__(self, fileobj, limit: int) -> None:
        self._fileobj = fileobj
        self._limit = limit
        self.poll: Callable[[], None] | None = None

    def __getattr__(self, name):
        return getattr(self._fileobj, name)

    def _refuse(self, end: int) -> None:
        if end > self._limit:
            raise UnsafeArchive(
                f"archive data goes on past {self._limit} bytes; the cap is {self._limit}"
            )

    def seek(self, pos: int, whence: int = 0):
        if whence == os.SEEK_CUR:
            pos, whence = self._fileobj.tell() + pos, os.SEEK_SET
        if whence != os.SEEK_SET:
            return self._fileobj.seek(pos, whence)
        self._refuse(pos)
        if self.poll is not None:
            here = self._fileobj.tell()
            while pos - here > _SEEK_STEP:
                self.poll()
                here = self._fileobj.seek(here + _SEEK_STEP)
        return self._fileobj.seek(pos)

    def read(self, size: int = -1):
        if size is None or size < 0 or size > MAX_TAR_READ:
            raise UnsafeArchive(f"a tar header holds more than {MAX_TAR_READ} bytes of data")
        self._refuse(self._fileobj.tell() + size)
        return self._fileobj.read(size)


def _stream_budget(max_bytes: int, cap: int) -> int:
    """The decompressed bytes of a tar whose *cap* members declare at most
    *max_bytes*: their data, and a few KiB of headers and padding each."""
    return max_bytes + cap * 4096 + MAX_TAR_READ


#: Bytes decompressed between two polls while seeking over member data.
_SEEK_STEP = 64 * 1024 * 1024


def _tar_is_plain(tf: tarfile.TarFile) -> bool:
    """*tf* reads an uncompressed file (seeking past data costs nothing)."""
    return isinstance(tf.fileobj, (io.BufferedReader, io.BufferedRandom, io.FileIO))


def _tar_members_capped(
    tf: tarfile.TarFile,
    cap: int,
    *,
    max_bytes: int,
    poll: Callable[[str], None] | None = None,
) -> list[tarfile.TarInfo]:
    """The members of *tf*, read header by header, and
    :class:`UnsafeArchive` as soon as there are more than *cap*:
    ``getmembers()`` reads every header before anyone can count them.

    The bytes the members declare are added up as the headers come, and
    above *max_bytes* the walk stops before the next header is read: in a
    compressed tar, reaching it decompresses the member's data first.
    (A plain .tar is seeked through: *max_bytes* does not apply.) *poll*
    gets each member's name and may raise (:class:`ExtractCancelled`)."""
    plain = _tar_is_plain(tf)
    budget = None
    if not plain:
        if not isinstance(tf.fileobj, _TarBudget):
            tf.fileobj = _TarBudget(tf.fileobj, _stream_budget(max_bytes, cap))
        budget = tf.fileobj
        if poll is not None:
            budget.poll = lambda: poll("")
    members: list[tarfile.TarInfo] = []
    declared = 0
    try:
        for member in tf:
            if poll is not None:
                poll(member.name)
            if len(members) >= cap:
                raise UnsafeArchive(f"archive has more than {cap} entries; cap is {cap}")
            members.append(member)
            # What tarfile skips to reach the next header: regular (and
            # sparse) data, and that of types it does not know.
            if member.isreg() or member.type not in tarfile.SUPPORTED_TYPES:
                declared += max(0, int(member.size))
                if declared > max_bytes and not plain:
                    raise UnsafeArchive(
                        f"archive declares more than {max_bytes} uncompressed bytes; "
                        f"cap is {max_bytes}"
                    )
    finally:
        if budget is not None:
            budget.poll = None
    return members


def zip_declared_entries(fh) -> tuple[int, int] | None:
    """``(entries, directory bytes)`` from the end-of-central-directory
    record, read before ``zipfile`` builds every entry; None when there
    is no plain record (zip64 and odd files are left to zipfile)."""
    try:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        tail = min(size, 65536 + 22)
        fh.seek(size - tail)
        data = fh.read(tail)
        fh.seek(0)
    except (OSError, ValueError):
        return None
    pos = data.rfind(b"PK\x05\x06")
    if pos < 0 or len(data) - pos < 22:
        return None
    entries = int.from_bytes(data[pos + 10 : pos + 12], "little")
    dir_size = int.from_bytes(data[pos + 12 : pos + 16], "little")
    return entries, dir_size


def _check_zip_entry_count(archive_path: str, cap: int) -> None:
    """Refuse a ZIP whose directory declares more than *cap* entries
    before ``zipfile`` parses it (0xFFFF is the zip64 marker, not a count:
    those are counted once parsed)."""
    with open(archive_path, "rb") as fh:
        declared = zip_declared_entries(fh)
    if declared is not None and declared[0] != 0xFFFF and declared[0] > cap:
        raise UnsafeArchive(f"archive declares {declared[0]} entries; cap is {cap}")


def _collision_key(path: str) -> str:
    return os.path.normcase(os.path.normpath(path))


def _check_duplicate_member(seen: set[str], target_path: str, member_name: str) -> None:
    key = _collision_key(target_path)
    if key in seen:
        raise UnsafeArchive(
            f"archive contains duplicate output path: {member_name!r}",
        )
    seen.add(key)


def _check_bomb_ratio(uncompressed: int, compressed: int, member_name: str) -> None:
    """Refuse an entry whose compression ratio exceeds the cap.
    Called per-entry; a single bomb entry is enough to refuse the
    whole archive since processing further entries only compounds
    the damage."""
    if compressed <= 0:
        # Zero-byte compressed with non-zero uncompressed is the
        # canonical bomb shape — reject immediately.
        if uncompressed > 0:
            raise UnsafeArchive(
                f"archive entry has zero-byte compressed size but "
                f"{uncompressed} bytes uncompressed: {member_name!r} "
                "(bomb signature)",
            )
        return
    ratio = uncompressed / compressed
    if ratio > MAX_COMPRESSION_RATIO:
        raise UnsafeArchive(
            f"archive entry compression ratio {ratio:.1f}:1 exceeds "
            f"{MAX_COMPRESSION_RATIO}:1 cap: {member_name!r} "
            f"({compressed} compressed → {uncompressed} uncompressed)",
        )


# --------------------------------------------------------------------------
# Extractors — one per family, all share the (archive_path, target,
# progress) contract. Callers go through :func:`extract` which
# dispatches by extension.
# --------------------------------------------------------------------------


def _extract_zip(
    archive_path: str,
    target: str,
    progress: Callable[[int, int, str], None] | None,
    sink: _Sink | None = None,
) -> int:
    """Extract a ZIP-family archive. Returns the count of files
    actually written (directories don't count; they're created as
    a side effect of ensuring parents for file entries)."""
    sink = sink or _Sink(target)
    _check_zip_entry_count(archive_path, MAX_EXTRACT_FILES)
    with zipfile.ZipFile(archive_path) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_EXTRACT_FILES:
            raise UnsafeArchive(
                f"archive has {len(infos)} entries; cap is {MAX_EXTRACT_FILES}",
            )
        # Pre-sum uncompressed sizes so a declaration of 10 GiB total
        # is refused before we've written even one byte.
        total_uncompressed = sum(max(0, i.file_size) for i in infos if not i.is_dir())
        if total_uncompressed > MAX_EXTRACT_TOTAL_BYTES:
            raise UnsafeArchive(
                f"archive declares {total_uncompressed} uncompressed "
                f"bytes; cap is {MAX_EXTRACT_TOTAL_BYTES}",
            )
        files_total = sum(1 for i in infos if not i.is_dir() and not _zip_is_link(i))
        files_done = 0
        skipped: list[str] = []
        seen_paths: set[str] = set()
        for info in infos:
            name = info.filename
            if _zip_is_link(info):
                skipped.append(name)
                continue
            # zipfile flags directories by trailing slash OR
            # explicit attrs; use is_dir() to cover both.
            if info.is_dir():
                dest = _safe_member_path(target, name)
                _check_duplicate_member(seen_paths, dest, name)
                sink.makedirs(name, dest)
                continue
            _check_bomb_ratio(
                info.file_size,
                info.compress_size,
                name,
            )
            dest = _safe_member_path(target, name)
            _check_duplicate_member(seen_paths, dest, name)
            # Stream decompressed bytes — no whole-file buffer.
            with zf.open(info) as src:
                sink.write(name, dest, src, _zip_mode(info), _zip_mtime(info))
            files_done += 1
            if progress is not None:
                progress(files_done, files_total, name)
        return _as_result(files_done, skipped)


#: Leading bytes of the stream formats :func:`_open_tar` opens itself.
_TAR_CODECS = ((b"\x1f\x8b", "gz"), (b"BZh", "bz2"), (b"\xfd7zXZ\x00", "xz"))


@contextlib.contextmanager
def _budgeted_tar(archive_path: str, limit: int):
    """A TarFile over the gzip / bzip2 / xz stream of *archive_path* read
    through :class:`_TarBudget` from the very first header (tarfile reads
    that one, and a GNU long name or pax header before it, while it is
    constructed); None for anything else (a plain or zstd tar)."""
    import bz2
    import gzip
    import lzma
    import zlib

    with open(archive_path, "rb") as raw:
        magic = raw.read(6)
        codec = next((c for m, c in _TAR_CODECS if magic.startswith(m)), None)
        if codec is None:
            yield None
            return
        raw.seek(0)
        opener = {"gz": lambda f: gzip.GzipFile(fileobj=f, mode="rb"),
                  "bz2": lambda f: bz2.BZ2File(f), "xz": lambda f: lzma.LZMAFile(f)}[codec]
        with opener(raw) as stream:
            try:
                tf = tarfile.TarFile(fileobj=_TarBudget(stream, limit), mode="r")
            except (OSError, EOFError, zlib.error, lzma.LZMAError) as exc:
                # What tarfile.open says of a stream that is not a tar.
                raise tarfile.ReadError(f"{codec} stream is not a tar archive: {exc}") from exc
            with tf:
                yield tf


@contextlib.contextmanager
def _open_tar(archive_path: str, budget: int | None = None):
    """A TarFile for any of the TAR family. A zstd tarball on a Python
    whose tarfile has no zstd (before 3.14 - the binary build) is
    decompressed into a private temporary file first, at most a little
    over MAX_EXTRACT_TOTAL_BYTES: tarfile needs random access.

    *budget*: the decompressed bytes a gzip / bzip2 / xz tar may take
    (:class:`_TarBudget`, from the first header on)."""
    lower = archive_path.lower()
    if budget is not None:
        with _budgeted_tar(archive_path, budget) as tf:
            if tf is not None:
                yield tf
                return
    if not lower.endswith((".tar.zst", ".tzst")) or _tarfile_knows_zstd():
        with tarfile.open(archive_path, mode="r:*") as tf:
            yield tf
        return
    from core import packer

    limit = MAX_EXTRACT_TOTAL_BYTES + MAX_EXTRACT_FILES * 1024 + (1 << 20)
    with tempfile.TemporaryFile(prefix="axross-tar-") as tmp:
        try:
            with open(archive_path, "rb") as raw, packer.zstd_reader(raw) as src:
                _copy_capped(src, tmp, limit, archive_path)
        except UnsafeArchive:
            raise
        except Exception as exc:  # noqa: BLE001 - the codec's own error types
            raise UnsafeArchive(
                f"cannot decompress {os.path.basename(archive_path)}: {exc}"
            ) from exc
        tmp.seek(0)
        with tarfile.open(fileobj=tmp, mode="r:") as tf:
            yield tf


def _copy_capped(src, dst, limit: int, what: str) -> int:
    total = 0
    while True:
        chunk = src.read(1024 * 1024)
        if not chunk:
            return total
        total += len(chunk)
        if total > limit:
            raise UnsafeArchive(
                f"{os.path.basename(what)} expands beyond {limit} bytes; "
                f"cap is {MAX_EXTRACT_TOTAL_BYTES} — likely a bomb",
            )
        dst.write(chunk)


def _single_reader(archive_path: str, ext: str):
    import bz2
    import gzip
    import lzma

    if ext == ".gz":
        return gzip.open(archive_path, "rb")
    if ext == ".bz2":
        return bz2.open(archive_path, "rb")
    if ext == ".xz":
        return lzma.open(archive_path, "rb")
    from core import packer

    raw = open(archive_path, "rb")  # noqa: SIM115 - closed with the reader
    try:
        return packer.zstd_reader(raw, close_raw=True)
    except BaseException:
        raw.close()
        raise


def _single_member_name(archive_path: str) -> str:
    stem = strip_archive_extension(archive_path)
    return stem if stem not in ("", ".", "..") else "data"


def _extract_single(
    archive_path: str,
    target: str,
    progress: Callable[[int, int, str], None] | None,
    sink: _Sink | None = None,
) -> int:
    """One compressed file: decompressed into *target*/<name without the
    extension>, never more than MAX_EXTRACT_TOTAL_BYTES."""
    ext = _single_ext(archive_path.lower())
    if ext is None:
        raise UnsafeArchive(f"not a single compressed file: {archive_path!r}")
    sink = sink or _Sink(target)
    name = _single_member_name(archive_path)
    out_path = _safe_member_path(target, name)
    if progress is not None:
        progress(0, 1, name)
    try:
        with _single_reader(archive_path, ext) as src, sink.open_new(name, out_path) as dst:
            _copy_capped(src, dst, MAX_EXTRACT_TOTAL_BYTES, archive_path)
    except (UnsafeArchive, ExtractCancelled):
        raise
    except Exception as exc:  # noqa: BLE001 - zlib.error, LZMAError, ZstdError, EOFError, …
        raise UnsafeArchive(f"cannot decompress {os.path.basename(archive_path)}: {exc}") from exc
    if progress is not None:
        progress(1, 1, name)
    return 1


def _extract_tar(
    archive_path: str,
    target: str,
    progress: Callable[[int, int, str], None] | None,
    sink: _Sink | None = None,
) -> int:
    """Extract a TAR-family archive. Tarfile sniffs gz/bz2/xz from
    the magic bytes so a single ``mode='r:*'`` open handles all
    four compressed variants."""
    sink = sink or _Sink(target)
    with _open_tar(archive_path, _stream_budget(MAX_EXTRACT_TOTAL_BYTES, MAX_EXTRACT_FILES)) as tf:
        members = _tar_members_capped(
            tf,
            MAX_EXTRACT_FILES,
            max_bytes=MAX_EXTRACT_TOTAL_BYTES,
            # Cancel is honoured while the headers are read, too.
            poll=(lambda name: progress(0, 0, name)) if progress is not None else None,
        )
        total_uncompressed = sum(max(0, m.size) for m in members if m.isfile())
        if total_uncompressed > MAX_EXTRACT_TOTAL_BYTES:
            raise UnsafeArchive(
                f"archive declares {total_uncompressed} uncompressed "
                f"bytes; cap is {MAX_EXTRACT_TOTAL_BYTES}",
            )
        files_total = sum(1 for m in members if m.isfile())
        files_done = 0
        skipped: list[str] = []
        seen_paths: set[str] = set()
        for m in members:
            # Tar members can be symlinks, hardlinks, device nodes,
            # FIFOs — all of which can escape the target dir or
            # trigger host-side side-effects we never want to
            # execute automatically. Only REG + DIR are written; a
            # link is left out (and reported), anything else refuses.
            if m.issym() or m.islnk():
                skipped.append(m.name)
                continue
            if not (m.isfile() or m.isdir()):
                raise UnsafeArchive(
                    f"tar entry has unsupported type {getattr(m, 'type', b'?')!r}: {m.name!r}",
                )
            if m.isdir():
                if _is_root_dir_entry(m.name):
                    continue
                dest = _safe_member_path(target, m.name)
                _check_duplicate_member(seen_paths, dest, m.name)
                sink.makedirs(m.name, dest)
                continue
            # Tarfile doesn't expose per-entry compressed size the
            # same way zipfile does — the whole archive is a single
            # compressed stream. The total-bytes cap above catches
            # declared bloat; skip per-entry ratio checks.
            dest = _safe_member_path(target, m.name)
            _check_duplicate_member(seen_paths, dest, m.name)
            src = tf.extractfile(m)
            if src is None:
                # Some non-regular types leak through isfile() on
                # older Python versions — defensive skip.
                continue
            try:
                sink.write(m.name, dest, src, m.mode, m.mtime)
            finally:
                src.close()
            files_done += 1
            if progress is not None:
                progress(files_done, files_total, m.name)
        return _as_result(files_done, skipped)


def _extract_7z(
    archive_path: str,
    target: str,
    progress: Callable[[int, int, str], None] | None,
    sink: _Sink | None = None,
) -> int:
    """Extract a 7z archive via py7zr. Safety caps are applied
    before extraction starts; py7zr's own ``extractall`` is called
    only after every path has passed the zip-slip check."""
    sink = sink or _Sink(target)
    if not SEVEN_Z_AVAILABLE:
        raise UnsafeArchive(
            "7z extraction requires py7zr — install with: pip install py7zr",
        )
    seven_zip = _seven_zip("7z extraction")
    with seven_zip.SevenZipFile(archive_path, mode="r") as sz:
        # py7zr.list() returns FileInfo objects with uncompressed
        # sizes but no compressed size per entry; cap on count +
        # total bytes.
        entries = sz.list()
        if len(entries) > MAX_EXTRACT_FILES:
            raise UnsafeArchive(
                f"archive has {len(entries)} entries; cap is {MAX_EXTRACT_FILES}",
            )
        total_uncompressed = sum(max(0, getattr(e, "uncompressed", 0)) for e in entries)
        if total_uncompressed > MAX_EXTRACT_TOTAL_BYTES:
            raise UnsafeArchive(
                f"archive declares {total_uncompressed} uncompressed "
                f"bytes; cap is {MAX_EXTRACT_TOTAL_BYTES}",
            )
        # Zip-slip pre-flight — validate every name BEFORE py7zr
        # starts writing. If we detect an escape on entry 50 of
        # 100 after extraction began, entries 1..49 are already on
        # disk and we'd have to reverse them.
        safe_targets: list[str] = []
        seen_paths: set[str] = set()
        for e in entries:
            name = getattr(e, "filename", "")
            if not name:
                raise UnsafeArchive("7z entry has empty/root path")
            if getattr(e, "is_symlink", False):
                raise UnsafeArchive(
                    f"7z entry is a symlink: {name!r}",
                )
            if not (getattr(e, "is_file", False) or getattr(e, "is_directory", False)):
                raise UnsafeArchive(
                    f"7z entry has unsupported type: {name!r}",
                )
            dest = _safe_member_path(target, name)
            _check_duplicate_member(seen_paths, dest, name)
            safe_targets.append(name)
        # py7zr.extractall can't cooperate with a per-entry progress
        # callback in a portable way; emit a single "starting"
        # progress and a single "done" progress.
        if progress is not None:
            progress(0, len(entries), "")
    # py7zr needs its own fresh open for extraction — the sz.list()
    # above advanced internal state.
    # py7zr writes by path: into a private folder, then copied in by the sink.
    def into(out: str) -> None:
        with seven_zip.SevenZipFile(archive_path, mode="r") as sz:
            sz.extract(path=out, targets=safe_targets)

    sink.staged(into)
    files_written = sum(1 for e in entries if not getattr(e, "is_directory", False))
    if progress is not None:
        progress(files_written, files_written, "")
    return files_written


def _extract_rar(
    archive_path: str,
    target: str,
    progress: Callable[[int, int, str], None] | None,
    sink: _Sink | None = None,
) -> int:
    """Extract a RAR archive via ``rarfile`` (which shells out to an
    ``unrar``/``unar`` backend). Mirrors :func:`_extract_7z`: every
    member name passes the zip-slip / duplicate / cap checks BEFORE
    any byte is written, then rarfile extracts only the validated set.

    Raises :class:`RarUnavailable` when the package is missing OR the
    backend tool can't be executed; reuses the shared guard helpers
    for every other refusal.
    """
    if not RAR_AVAILABLE:
        raise RarUnavailable(_RAR_UNAVAILABLE_MSG)
    sink = sink or _Sink(target)
    try:
        with rarfile.RarFile(archive_path) as rf:  # type: ignore[union-attr]
            infos = rf.infolist()
            if len(infos) > MAX_EXTRACT_FILES:
                raise UnsafeArchive(
                    f"archive has {len(infos)} entries; cap is {MAX_EXTRACT_FILES}",
                )
            total_uncompressed = sum(
                max(0, int(getattr(ri, "file_size", 0) or 0))
                for ri in infos
                if not ri.is_dir()
            )
            if total_uncompressed > MAX_EXTRACT_TOTAL_BYTES:
                raise UnsafeArchive(
                    f"archive declares {total_uncompressed} uncompressed "
                    f"bytes; cap is {MAX_EXTRACT_TOTAL_BYTES}",
                )
            files_total = sum(1 for ri in infos if not ri.is_dir())
            # Zip-slip pre-flight across EVERY member before extraction.
            # CRITICAL: reject symlink + non-file/non-dir members here,
            # BEFORE rarfile.extractall is reached. rarfile extracts a
            # symlink member via os.symlink(raw_link_target, dst) with an
            # UNSANITIZED target — a symlink whose target is ``../../etc``
            # (or an absolute path) escapes the target dir, and the
            # post-extraction _measure_tree_bytes net deliberately skips
            # symlinks so it would NOT catch it. Mirrors the _extract_7z /
            # _extract_tar guards. Only validated file/dir names ever reach
            # extractall(members=...).
            safe_targets: list[str] = []
            seen_paths: set[str] = set()
            for ri in infos:
                name = ri.filename
                if not name or name in {".", "/"}:
                    raise UnsafeArchive("rar entry has empty/root path")
                if ri.is_symlink():
                    raise UnsafeArchive(
                        f"rar entry is a symlink: {name!r}",
                    )
                if not (ri.is_file() or ri.is_dir()):
                    raise UnsafeArchive(
                        f"rar entry has unsupported type: {name!r}",
                    )
                dest = _safe_member_path(target, name)
                _check_duplicate_member(seen_paths, dest, name)
                if ri.is_dir():
                    sink.makedirs(name, dest)
                    continue
                _check_bomb_ratio(
                    int(getattr(ri, "file_size", 0) or 0),
                    int(getattr(ri, "compress_size", 0) or 0),
                    name,
                )
                safe_targets.append(name)
            if progress is not None:
                progress(0, files_total, "")
            # rarfile writes by path: into a private folder, then copied in.
            sink.staged(lambda out: rf.extractall(path=out, members=safe_targets))
    except (rarfile.RarCannotExec, rarfile.RarExecError) as exc:  # type: ignore[union-attr]
        # Backend tool (unrar/unar) missing or unrunnable. Surface the
        # same remediation hint as the import-failure path.
        raise RarUnavailable(_RAR_UNAVAILABLE_MSG) from exc
    files_written = len(safe_targets)
    if progress is not None:
        progress(files_written, files_written, "")
    return files_written


# --------------------------------------------------------------------------
# Partial extraction — pick a subset of members
# --------------------------------------------------------------------------


def _norm_member(name: str) -> str:
    """Normalise an archive member name for selection matching:
    backslashes → ``/`` and a single trailing ``/`` stripped. Used only
    to compare *requested* names against *archive* names — the actual
    extraction still flows through :func:`_safe_member_path` on the raw
    member name, so this normalisation is never a security boundary."""
    return name.replace("\\", "/").rstrip("/")


def _is_selected(member_name: str, requested_norm: set[str]) -> bool:
    """True iff *member_name* is either an exactly-requested name OR a
    descendant of a requested DIRECTORY. Directory match is by PATH
    SEGMENT prefix (``d`` matches ``d/a.txt`` but NOT ``d2.txt``) so a
    requested name never grabs a string-prefix sibling.
    """
    norm = _norm_member(member_name)
    if norm in requested_norm:
        return True
    return any(prefix in requested_norm for prefix in _slash_prefixes(norm))


def _slash_prefixes(norm: str):
    """Every ``p`` with ``norm.startswith(p + "/")``: the text before each
    ``/``. Walking these is O(depth) instead of comparing against every
    requested (or every archive) name."""
    pos = norm.find("/")
    while pos >= 0:
        yield norm[:pos]
        pos = norm.find("/", pos + 1)


def _resolve_selection(
    all_member_names: list[str],
    members: list[str],
) -> set[str]:
    """Map the caller's *members* request onto the archive's actual
    member names. A requested name matches if it equals a member OR is
    a directory whose descendants exist. Every requested name MUST match
    at least one archive member; an unmatched request raises
    :class:`KeyError` listing the missing name(s) — validated up front so
    a typo never produces a partial extraction.

    Returns the set of NORMALISED member names that were selected.
    """
    norm_all = {_norm_member(n) for n in all_member_names}
    requested_norm = {_norm_member(m) for m in members}
    ancestors = {prefix for other in norm_all for prefix in _slash_prefixes(other)}

    def _matches(req_norm: str) -> bool:
        # Exact member OR a directory with at least one descendant.
        return req_norm in norm_all or req_norm in ancestors

    missing = [m for m in members if not _matches(_norm_member(m))]
    if missing:
        raise KeyError(
            f"requested member(s) not found in archive: {missing!r}",
        )
    return requested_norm


def _extract_members_zip(
    archive_path: str,
    target: str,
    members: list[str],
    progress: Callable[[int, int, str], None] | None,
    sink: _Sink | None = None,
) -> int:
    """Partial ZIP extraction. Mirrors :func:`_extract_zip`'s guards
    (zip-slip, duplicate, bomb-ratio, count + total-byte caps) but
    applies them ONLY to the SELECTED subset. Caps are enforced across
    the selection, not the whole archive."""
    sink = sink or _Sink(target)
    _check_zip_entry_count(archive_path, MAX_LIST_ENTRIES)
    with zipfile.ZipFile(archive_path) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_LIST_ENTRIES:
            raise UnsafeArchive(
                f"archive has {len(infos)} entries; cap is {MAX_LIST_ENTRIES}"
            )
        requested = _resolve_selection([i.filename for i in infos], members)
        selected = [i for i in infos if _is_selected(i.filename, requested)]
        skipped = [i.filename for i in selected if _zip_is_link(i)]
        selected = [i for i in selected if not _zip_is_link(i)]
        sel_files = [i for i in selected if not i.is_dir()]
        if len(sel_files) > MAX_EXTRACT_FILES:
            raise UnsafeArchive(
                f"selection has {len(sel_files)} files; cap is {MAX_EXTRACT_FILES}",
            )
        total_uncompressed = sum(max(0, i.file_size) for i in sel_files)
        if total_uncompressed > MAX_EXTRACT_TOTAL_BYTES:
            raise UnsafeArchive(
                f"selection declares {total_uncompressed} uncompressed "
                f"bytes; cap is {MAX_EXTRACT_TOTAL_BYTES}",
            )
        files_total = len(sel_files)
        files_done = 0
        seen_paths: set[str] = set()
        for info in selected:
            name = info.filename
            if info.is_dir():
                dest = _safe_member_path(target, name)
                _check_duplicate_member(seen_paths, dest, name)
                sink.makedirs(name, dest)
                continue
            _check_bomb_ratio(info.file_size, info.compress_size, name)
            dest = _safe_member_path(target, name)
            _check_duplicate_member(seen_paths, dest, name)
            with zf.open(info) as src:
                sink.write(name, dest, src, _zip_mode(info), _zip_mtime(info))
            files_done += 1
            if progress is not None:
                progress(files_done, files_total, name)
        return _as_result(files_done, skipped)


def _extract_members_tar(
    archive_path: str,
    target: str,
    members: list[str],
    progress: Callable[[int, int, str], None] | None,
    sink: _Sink | None = None,
) -> int:
    """Partial TAR extraction. Mirrors :func:`_extract_tar`'s guards
    (symlink/hardlink + non-file/dir refusal, zip-slip, duplicate, count
    + total-byte caps) applied ONLY to the SELECTED subset."""
    sink = sink or _Sink(target)
    with _open_tar(archive_path, _stream_budget(MAX_LIST_TAR_BYTES, MAX_LIST_ENTRIES)) as tf:
        members_all = _tar_members_capped(
            tf,
            MAX_LIST_ENTRIES,
            max_bytes=MAX_LIST_TAR_BYTES,
            poll=(lambda name: progress(0, 0, name)) if progress is not None else None,
        )
        requested = _resolve_selection([m.name for m in members_all], members)
        selected = [m for m in members_all if _is_selected(m.name, requested)]
        sel_files = [m for m in selected if m.isfile()]
        if len(sel_files) > MAX_EXTRACT_FILES:
            raise UnsafeArchive(
                f"selection has {len(sel_files)} files; cap is {MAX_EXTRACT_FILES}",
            )
        total_uncompressed = sum(max(0, m.size) for m in sel_files)
        if total_uncompressed > MAX_EXTRACT_TOTAL_BYTES:
            raise UnsafeArchive(
                f"selection declares {total_uncompressed} uncompressed "
                f"bytes; cap is {MAX_EXTRACT_TOTAL_BYTES}",
            )
        files_total = len(sel_files)
        files_done = 0
        skipped: list[str] = []
        seen_paths: set[str] = set()
        for m in selected:
            # SAME type guards as _extract_tar: leave links out, refuse
            # anything else that isn't a plain file or dir BEFORE writing.
            if m.issym() or m.islnk():
                skipped.append(m.name)
                continue
            if not (m.isfile() or m.isdir()):
                raise UnsafeArchive(
                    f"tar entry has unsupported type {getattr(m, 'type', b'?')!r}: {m.name!r}",
                )
            if m.isdir():
                if _is_root_dir_entry(m.name):
                    continue
                dest = _safe_member_path(target, m.name)
                _check_duplicate_member(seen_paths, dest, m.name)
                sink.makedirs(m.name, dest)
                continue
            dest = _safe_member_path(target, m.name)
            _check_duplicate_member(seen_paths, dest, m.name)
            src = tf.extractfile(m)
            if src is None:
                continue
            try:
                sink.write(m.name, dest, src, m.mode, m.mtime)
            finally:
                src.close()
            files_done += 1
            if progress is not None:
                progress(files_done, files_total, m.name)
        return _as_result(files_done, skipped)


def extract_members(
    archive_path: str,
    target: str,
    members: list[str],
    progress: Callable[[int, int, str], None] | None = None,
    *,
    parent_dir=None,
) -> ExtractResult:
    """Extract ONLY the named *members* from *archive_path* into *target*.

    *members* is a list of member names as reported by
    :func:`list_archive`. A name that refers to a DIRECTORY pulls in
    every descendant (path-segment prefix match on the archive's
    normalised names — ``d`` selects ``d/a.txt`` but never a sibling
    ``d2.txt``). Returns the count of regular files written, as an
    :class:`ExtractResult` that also names the link members left out.

    Behaviour:

    * **Missing member** — any requested name absent from the archive
      raises :class:`KeyError` (message lists the missing name(s)),
      validated BEFORE writing so a typo never leaves partial state.
    * **Target contract** — mirrors :func:`extract`: *target* must NOT
      pre-exist; it is created (0o755) and removed on any failure, so
      the caller never sees partial / attacker-controlled content.
    * **Safety guards** — the SAME guards as the full extractors apply
      per selected member: links left out, non-file-non-dir refusal,
      :func:`_safe_member_path` zip-slip check, :func:`_check_duplicate_member`,
      :func:`_check_bomb_ratio`, and the MAX_EXTRACT_FILES /
      MAX_EXTRACT_TOTAL_BYTES caps — enforced across the SELECTED set.
      None are weakened or skipped; the shared guard helpers are reused
      verbatim (the per-format loops mirror the full extractors rather
      than refactoring shared state out of them, to avoid perturbing
      the full-extract behaviour).

    Format support:

    * **ZIP family** and **TAR family** are fully supported.
    * **7z** and **RAR** partial extraction raise
      :class:`NotImplementedError`. ZIP + TAR are the must-haves for the
      UI MVP; the 7z/RAR member-filtered library APIs (``py7zr`` ``targets=``,
      ``rarfile.extractall(members=...)``) extract by RAW archive name
      and would need a separate descendant-expansion + guard pass to
      match the contract here — deferred rather than shipped half-guarded.
    """
    if not os.path.isfile(archive_path):
        raise FileNotFoundError(
            f"archive not found or not a regular file: {archive_path!r}",
        )
    if os.path.exists(target):
        raise FileExistsError(
            f"target already exists: {target!r} — caller must pass a "
            "fresh path (see auto_suffix_dir)",
        )
    lower = archive_path.lower()
    runner = None
    for ext in _TAR_EXTENSIONS:
        if lower.endswith(ext):
            runner = _extract_members_tar
            break
    if runner is None:
        for ext in _ZIP_EXTENSIONS:
            if lower.endswith(ext):
                runner = _extract_members_zip
                break
    if runner is None and _single_ext(lower) is not None:
        name = _single_member_name(archive_path)
        missing = [m for m in members if m.rstrip("/") != name]
        if missing:
            raise KeyError(f"not in the archive: {', '.join(missing)}")

        def runner(path, tgt, _members, prog, sink=None):
            return _extract_single(path, tgt, prog, sink)

    if runner is None:
        for ext in _SEVEN_Z_EXTENSIONS + _RAR_EXTENSIONS:
            if lower.endswith(ext):
                raise NotImplementedError(
                    "partial extraction is not supported for 7z/RAR; "
                    "use extract() for the whole archive (ZIP and TAR "
                    "support extract_members())",
                )
    if runner is None:
        raise UnsafeArchive(
            f"unsupported archive extension: {archive_path!r}",
        )
    # Same symlink-swap-race guard as extract(): written beneath a
    # descriptor of the folder made here, nothing followed (_Sink).
    sink = _Sink.create(target, parent_dir)
    try:
        written = runner(archive_path, target, members, progress, sink)
        # Post-extraction size re-verification, same as extract(): the
        # selected members' declared sizes can lie.
        actual_bytes = sink.measure()
        if actual_bytes > MAX_EXTRACT_TOTAL_BYTES:
            raise UnsafeArchive(
                f"selection extracted {actual_bytes} bytes; cap is "
                f"{MAX_EXTRACT_TOTAL_BYTES} — likely bomb with "
                "declared-size metadata smaller than reality",
            )
        return written if isinstance(written, ExtractResult) else ExtractResult(written)
    except BaseException:
        # Clean on ANY failure (UnsafeArchive, KeyError, ExtractCancelled,
        # OSError, KeyboardInterrupt) — never leave partial content.
        sink.discard()
        raise
    finally:
        sink.close()


# --------------------------------------------------------------------------
# Read-only listing
# --------------------------------------------------------------------------


def _zip_date_time_to_epoch(date_time: tuple[int, ...]) -> float | None:
    """Convert a zipfile ``date_time`` 6-tuple to an epoch float.
    Returns ``None`` on any malformed value (e.g. a year/month of 0,
    which zipfile uses for entries without a timestamp)."""
    try:
        return time.mktime((*date_time, 0, 0, -1))
    except (ValueError, OverflowError, TypeError):
        return None


def _list_zip(p: str) -> list[ArchiveEntry]:
    out: list[ArchiveEntry] = []
    _check_zip_entry_count(p, MAX_LIST_ENTRIES)
    with zipfile.ZipFile(p) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_LIST_ENTRIES:
            raise UnsafeArchive(f"archive has {len(infos)} entries; cap is {MAX_LIST_ENTRIES}")
        for zi in infos:
            unix = (zi.external_attr >> 16) if zi.create_system == 3 else 0
            if zi.is_dir():
                kind = "dir"
            elif unix and stat.S_ISLNK(unix):
                kind = "symlink"
            else:
                kind = "file"
            out.append(
                ArchiveEntry(
                    name=zi.filename,
                    size=int(zi.file_size),
                    compressed=int(zi.compress_size),
                    mtime=_zip_date_time_to_epoch(zi.date_time),
                    is_dir=zi.is_dir(),
                    mode=_zip_mode(zi),
                    kind=kind,
                ),
            )
    return out


def _list_tar(p: str, cancel: Callable[[], bool] | None = None) -> list[ArchiveEntry]:
    out: list[ArchiveEntry] = []

    def poll(_name: str) -> None:
        if cancel is not None and cancel():
            raise ExtractCancelled("listing cancelled")

    with _open_tar(p, _stream_budget(MAX_LIST_TAR_BYTES, MAX_LIST_ENTRIES)) as tf:
        for ti in _tar_members_capped(tf, MAX_LIST_ENTRIES, max_bytes=MAX_LIST_TAR_BYTES,
                                      poll=poll):
            is_dir = ti.isdir()
            name = ti.name + "/" if is_dir and not ti.name.endswith("/") else ti.name
            size = int(ti.size)
            out.append(
                ArchiveEntry(
                    name=name,
                    size=size,
                    # Tar is a single compressed stream — no per-member
                    # compressed size. Mirror size so ratio reads 0.0.
                    compressed=size,
                    mtime=float(ti.mtime) if ti.mtime is not None else None,
                    is_dir=is_dir,
                    mode=(ti.mode & 0o7777) if ti.mode is not None else None,
                    kind=_tar_kind(ti),
                ),
            )
    return out


def _tar_kind(ti: tarfile.TarInfo) -> str:
    if ti.isdir():
        return "dir"
    if ti.issym():
        return "symlink"
    if ti.islnk():
        return "hardlink"
    return "file" if ti.isreg() else "other"


def _list_7z(p: str) -> list[ArchiveEntry]:
    if not SEVEN_Z_AVAILABLE:
        raise UnsafeArchive(
            "7z listing requires py7zr — install with: pip install py7zr",
        )
    seven_zip = _seven_zip("7z listing")
    out: list[ArchiveEntry] = []
    with seven_zip.SevenZipFile(p, mode="r") as sz:
        for fi in sz.list():
            size = int(getattr(fi, "uncompressed", 0) or 0)
            out.append(
                ArchiveEntry(
                    name=getattr(fi, "filename", ""),
                    size=size,
                    compressed=int(getattr(fi, "compressed", 0) or 0),
                    # py7zr's FileInfo doesn't expose a portable epoch
                    # mtime across versions — leave it None for now.
                    mtime=None,
                    is_dir=bool(getattr(fi, "is_directory", False)),
                ),
            )
    return out


def _list_rar(p: str) -> list[ArchiveEntry]:
    # Availability gate fires BEFORE any file IO so callers get
    # RarUnavailable even for a path that doesn't exist / isn't a rar.
    if not RAR_AVAILABLE:
        raise RarUnavailable(_RAR_UNAVAILABLE_MSG)
    out: list[ArchiveEntry] = []
    try:
        with rarfile.RarFile(p) as rf:  # type: ignore[union-attr]
            for ri in rf.infolist():
                is_dir = ri.is_dir()
                dt = getattr(ri, "date_time", None)
                mtime: float | None = None
                if dt:
                    try:
                        mtime = time.mktime((*dt, 0, 0, -1))
                    except (ValueError, OverflowError, TypeError):
                        mtime = None
                out.append(
                    ArchiveEntry(
                        name=ri.filename,
                        size=int(getattr(ri, "file_size", 0) or 0),
                        compressed=int(getattr(ri, "compress_size", 0) or 0),
                        mtime=mtime,
                        is_dir=is_dir,
                    ),
                )
    except (rarfile.RarCannotExec, rarfile.RarExecError) as exc:  # type: ignore[union-attr]
        raise RarUnavailable(_RAR_UNAVAILABLE_MSG) from exc
    return out


def list_archive(
    archive_path: str, *, cancel: Callable[[], bool] | None = None
) -> list[ArchiveEntry]:
    """Return the member listing of *archive_path* WITHOUT extracting
    anything to disk. Dispatch is by filename extension (case-
    insensitive), reusing the same extension tables as :func:`extract`.

    * ZIP / TAR families are always supported (stdlib).
    * ``.7z`` requires py7zr — raises :class:`UnsafeArchive` if absent.
    * ``.rar`` requires ``rarfile`` + an ``unrar``/``unar`` backend —
      raises :class:`RarUnavailable` if either is missing. The
      availability check fires before any file IO.
    * An unknown extension raises :class:`UnsafeArchive` — the same
      error family :func:`extract` raises for unsupported input.

    Listing is strictly read-only: no files are written, no target
    directory is created.

    *cancel* (zero-argument, true once a stop was asked for) is polled per
    tar header: :class:`ExtractCancelled` then. A compressed tar whose
    members declare more than :data:`MAX_LIST_TAR_BYTES` is refused
    (:class:`UnsafeArchive`) before that much is decompressed.
    """
    lower = archive_path.lower()
    # RAR is checked first so the availability gate fires before file
    # IO (per contract). The .rar extension is unambiguous.
    for ext in _RAR_EXTENSIONS:
        if lower.endswith(ext):
            return _list_rar(archive_path)
    # TAR before ZIP/7z to match extract()'s ordering (compound
    # extensions live in the TAR table and must win the longest match).
    for ext in _TAR_EXTENSIONS:
        if lower.endswith(ext):
            return _list_tar(archive_path, cancel)
    for ext in _ZIP_EXTENSIONS:
        if lower.endswith(ext):
            return _list_zip(archive_path)
    for ext in _SEVEN_Z_EXTENSIONS:
        if lower.endswith(ext):
            return _list_7z(archive_path)
    if _single_ext(lower) is not None:
        # The uncompressed size is not known without decompressing.
        st = os.stat(archive_path)
        return [
            ArchiveEntry(
                name=_single_member_name(archive_path),
                size=0,
                compressed=int(st.st_size),
                mtime=float(st.st_mtime),
                is_dir=False,
            ),
        ]
    raise UnsafeArchive(
        f"unsupported archive extension: {archive_path!r}",
    )


def extract_nested_archive(
    archive_path: str,
    member: str,
    workdir: str,
    *,
    depth: int,
    progress: Callable[[int, int, str], None] | None = None,
) -> str:
    """Extract *member* of *archive_path* - itself an archive - into
    *workdir* so it can be listed and extracted like any archive, and
    return its path there (it keeps its file name, which picks the format).

    *depth* is the nesting level the member would open at: 1 for an archive
    inside the archive on disk. Refused with :class:`UnsafeArchive` past
    :data:`MAX_NESTED_DEPTH`, for a member that is not a supported archive,
    a folder, or larger than :data:`MAX_NESTED_ARCHIVE_BYTES` - by the
    listing and again by the bytes written, as a listing can lie. The
    extraction is :func:`extract_members` with all its guards (zip-slip,
    links, ratio, count and size caps). A missing member is a
    :class:`KeyError`; *workdir* holds nothing of a refused member.
    *progress* is handed to :func:`extract_members` (it may raise
    :class:`ExtractCancelled`).
    """
    if depth > MAX_NESTED_DEPTH:
        raise UnsafeArchive(
            f"archives nested deeper than {MAX_NESTED_DEPTH} levels are not opened"
        )
    if not is_supported_archive(member):
        raise UnsafeArchive(f"not an archive: {member!r}")
    entry = next((e for e in list_archive(archive_path) if e.name == member), None)
    if entry is None:
        raise KeyError(f"not in the archive: {member}")
    if entry.is_dir:
        raise UnsafeArchive(f"a folder, not an archive: {member!r}")
    if entry.size > MAX_NESTED_ARCHIVE_BYTES:
        raise UnsafeArchive(
            f"{member!r} is larger than {MAX_NESTED_ARCHIVE_BYTES} bytes, the limit "
            "for an archive opened inside another one"
        )
    target = os.path.join(workdir, "nested")
    extract_members(archive_path, target, [member], progress=progress)
    path = os.path.join(target, *[seg for seg in member.replace("\\", "/").split("/") if seg])
    try:
        if not os.path.isfile(path):
            raise UnsafeArchive(f"{member!r} did not extract to a file")
        if os.path.getsize(path) > MAX_NESTED_ARCHIVE_BYTES:
            raise UnsafeArchive(
                f"{member!r} extracted to more than {MAX_NESTED_ARCHIVE_BYTES} bytes, the "
                "limit for an archive opened inside another one"
            )
    except BaseException:
        shutil.rmtree(target, ignore_errors=True)
        raise
    return path


# --------------------------------------------------------------------------
# Dispatcher
# --------------------------------------------------------------------------


def extract(
    archive_path: str,
    target: str,
    *,
    progress: Callable[[int, int, str], None] | None = None,
    parent_dir=None,
) -> ExtractResult:
    """Extract *archive_path* into *target*.

    *target* must NOT exist yet; the function creates it (0o755) and
    removes it on any failure so the caller never sees a partial
    state. That matters because a failure mid-extract can leave the
    target populated with attacker-controlled files even when the
    exception correctly refuses the run — callers treating the
    failure as "tried to extract, ignore" would then be fooled into
    trusting partial content. Clean-on-fail removes the temptation.

    Returns the number of regular files written, as an
    :class:`ExtractResult` whose ``skipped_links`` names the symlink and
    hardlink members left out (tar, and ZIP symlinks).

    Every folder and file is created beneath a descriptor of the new
    *target*, never through a symlink and never over a file that appeared
    meanwhile (:class:`_Sink`). *parent_dir(target)*: a context manager
    giving ``(descriptor of target's folder, name)`` - the MCP server's
    confined backend passes its ``parent_dir``, so even the folder the
    target is made in is reached without following a symlink.
    """
    if not os.path.isfile(archive_path):
        raise FileNotFoundError(
            f"archive not found or not a regular file: {archive_path!r}",
        )
    if os.path.exists(target):
        raise FileExistsError(
            f"target already exists: {target!r} — caller must pass a "
            "fresh path (see auto_suffix_dir)",
        )
    lower = archive_path.lower()
    runner = None
    for ext in _TAR_EXTENSIONS:
        if lower.endswith(ext):
            runner = _extract_tar
            break
    if runner is None:
        for ext in _ZIP_EXTENSIONS:
            if lower.endswith(ext):
                runner = _extract_zip
                break
    if runner is None and SEVEN_Z_AVAILABLE:
        for ext in _SEVEN_Z_EXTENSIONS:
            if lower.endswith(ext):
                runner = _extract_7z
                break
    if runner is None:
        # ``.rar`` is its own branch: a matching extension but a
        # missing backend must raise RarUnavailable (a capability
        # error), NOT the generic "unsupported extension" UnsafeArchive
        # — the file IS a supported format, we just can't read it here.
        for ext in _RAR_EXTENSIONS:
            if lower.endswith(ext):
                if not RAR_AVAILABLE:
                    raise RarUnavailable(_RAR_UNAVAILABLE_MSG)
                runner = _extract_rar
                break
    if runner is None and _single_ext(lower) is not None:
        runner = _extract_single
    if runner is None:
        raise UnsafeArchive(
            f"unsupported archive extension: {archive_path!r}",
        )
    # Defence against a symlink-swap race: a parallel process with write
    # access to the parent dir could replace the new folder - or a folder
    # an entry creates in it - with a symlink (e.g. to
    # ~/.config/autostart) while entries are written. The sink creates
    # the target relative to its parent's descriptor, holds a descriptor
    # of it and writes every entry beneath that without following a
    # symlink (_Sink). A symlink in an ANCESTOR of the target (macOS
    # ``/tmp`` → ``/private/tmp``) is the caller's and stays usable;
    # *parent_dir* (the MCP server's confined backend) opens the parent
    # beneath its root instead.
    sink = _Sink.create(target, parent_dir)
    try:
        written = runner(archive_path, target, progress, sink)
        # Post-extraction sanity: some archive formats (notably 7z via
        # py7zr) let per-entry metadata claim smaller than the actual
        # decompressed size. We track the declared total during
        # pre-flight (MAX_EXTRACT_TOTAL_BYTES) but the declared total
        # can lie. Walk target once and re-verify against the cap,
        # then roll back if we over-shot.
        actual_bytes = sink.measure()
        if actual_bytes > MAX_EXTRACT_TOTAL_BYTES:
            raise UnsafeArchive(
                f"archive extracted {actual_bytes} bytes; cap is "
                f"{MAX_EXTRACT_TOTAL_BYTES} — likely bomb with "
                "declared-size metadata smaller than reality",
            )
        return written if isinstance(written, ExtractResult) else ExtractResult(written)
    except BaseException:
        # Cleanup on ANY failure — UnsafeArchive, ExtractCancelled,
        # OSError, KeyboardInterrupt. Leaving partial content behind
        # would let a malformed archive plant a handful of attacker-
        # controlled files before the escape check fires on a later
        # entry.
        sink.discard()
        raise
    finally:
        sink.close()


#: Public name of :func:`_open_tar` for readers outside this module.
open_tar_archive = _open_tar


def _measure_tree_bytes(root: str) -> int:
    """Sum the sizes of all regular files under *root*, skipping
    symlinks (we never write them; following them during
    measurement would allow escape). Used by :func:`extract` as a
    post-extraction size-cap re-verification that doesn't depend
    on archive-declared metadata.
    """
    total = 0
    for dirpath, _dirnames, filenames in os.walk(
        root,
        followlinks=False,
    ):
        for name in filenames:
            p = os.path.join(dirpath, name)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            # Only count regular files. Symlinks shouldn't be here
            # (we refuse them during extraction) but if one slipped
            # through it stays uncounted.
            if os.path.isfile(p) and not os.path.islink(p):
                total += st.st_size
    return total


__all__ = [
    "ArchiveEntry",
    "ExtractCancelled",
    "MAX_COMPRESSION_RATIO",
    "MAX_EXTRACT_FILES",
    "MAX_EXTRACT_TOTAL_BYTES",
    "MAX_LIST_ENTRIES",
    "RAR_AVAILABLE",
    "RarUnavailable",
    "SEVEN_Z_AVAILABLE",
    "UnsafeArchive",
    "archive_family",
    "auto_suffix_dir",
    "MAX_NESTED_ARCHIVE_BYTES",
    "MAX_NESTED_DEPTH",
    "check_bomb_ratio",
    "extract",
    "extract_members",
    "extract_nested_archive",
    "is_supported_archive",
    "list_archive",
    "open_tar_archive",
    "strip_archive_extension",
    "zip_declared_entries",
]
