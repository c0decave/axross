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
3. **No symlink / hardlink entries** in tarballs — tarfile
   represents these with distinct type flags; we reject every
   non-``REGTYPE`` / non-``DIRTYPE`` entry. ZIPs don't have a
   symlink concept in the standard (some toolchains abuse mode
   bits for it — we don't honour those either).
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

import io
import logging
import os
import shutil
import tarfile
import zipfile
from pathlib import Path
from typing import Callable, IO

log = logging.getLogger("core.archive")


try:  # pragma: no cover — optional dep
    import py7zr  # type: ignore[import-not-found]
    SEVEN_Z_AVAILABLE = True
except ImportError:  # pragma: no cover
    py7zr = None  # type: ignore[assignment]
    SEVEN_Z_AVAILABLE = False


# --------------------------------------------------------------------------
# Config caps
# --------------------------------------------------------------------------

# Max number of entries we'll extract from one archive. A zip bomb
# can claim millions of small files to exhaust inodes; 10k is above
# any realistic real-world archive.
MAX_EXTRACT_FILES = 10_000

# Max total uncompressed bytes. 1 GiB is generous for realistic
# archives (a 600 MiB app-bundle expands to a few hundred MiB),
# tight enough that a 42-kB bomb expanding to 4 GiB is refused.
MAX_EXTRACT_TOTAL_BYTES = 1 * 1024 * 1024 * 1024

# Max per-entry compression ratio (uncompressed / max(1,compressed)).
# The canonical "zip of zeros" bomb hits ratios of 1000:1. 100:1
# accommodates legitimate text archives (which can legitimately
# compress 20:1 or so) without admitting the pathological case.
MAX_COMPRESSION_RATIO = 100


# --------------------------------------------------------------------------
# Extension table — single source of truth for "is this extractable?"
# --------------------------------------------------------------------------

_ZIP_EXTENSIONS = (
    ".zip", ".xpi", ".jar", ".war", ".apk", ".epub",
    ".docx", ".xlsx", ".odt",
)
_TAR_EXTENSIONS = (
    # Compound extensions MUST be listed before their plain .tar
    # counterpart so the extension-stripping logic grabs the longer
    # match first.
    ".tar.gz", ".tgz",
    ".tar.bz2", ".tbz2",
    ".tar.xz", ".txz",
    ".tar",
)
_SEVEN_Z_EXTENSIONS = (".7z",)


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


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def is_supported_archive(name_or_path: str) -> bool:
    """True iff the filename matches a supported archive extension.
    Case-insensitive. ``.7z`` is included only when ``py7zr`` is
    importable; extracting it without the library would fail late,
    and hiding the menu item up-front is the honest UX."""
    lower = name_or_path.lower()
    for ext in _ZIP_EXTENSIONS + _TAR_EXTENSIONS:
        if lower.endswith(ext):
            return True
    if SEVEN_Z_AVAILABLE:
        for ext in _SEVEN_Z_EXTENSIONS:
            if lower.endswith(ext):
                return True
    return False


def strip_archive_extension(name_or_path: str) -> str:
    """Return the basename of *name_or_path* with its archive
    extension removed. Compound extensions (``.tar.gz`` etc.) are
    recognised and both parts are stripped. Returns the basename
    verbatim when no extension matches — caller must decide whether
    that's a bug or a pass-through."""
    base = os.path.basename(name_or_path)
    lower = base.lower()
    for ext in _TAR_EXTENSIONS + _ZIP_EXTENSIONS + _SEVEN_Z_EXTENSIONS:
        if lower.endswith(ext):
            return base[: -len(ext)]
    return base


def auto_suffix_dir(parent: str, base: str) -> str:
    """Return an absolute path for a directory named *base* under
    *parent* that does NOT yet exist. Tries the plain base first,
    then ``base-1``, ``base-2``, … up to 999; raises OSError if the
    counter wraps (clearly a bug in the caller's flow — 999
    identical extractions in one folder is not a real workload).

    Pure path math — does not create the directory.
    """
    candidate = os.path.join(parent, base)
    if not os.path.exists(candidate):
        return candidate
    for i in range(1, 1000):
        candidate = os.path.join(parent, f"{base}-{i}")
        if not os.path.exists(candidate):
            return candidate
    raise OSError(
        f"auto_suffix_dir: exhausted 999 suffix candidates under "
        f"{parent!r} for base {base!r} — clean up before retrying",
    )


# --------------------------------------------------------------------------
# Safety probes
# --------------------------------------------------------------------------


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
    normalised = member_name.replace("\\", "/")
    joined = os.path.join(target_root, normalised)
    # realpath collapses ``..`` AND any symlink in the ancestor chain
    # of target_root — the comparison is against the *resolved* form.
    resolved_root = os.path.realpath(target_root)
    resolved_member = os.path.realpath(joined)
    # Must be equal to the root OR a descendant. Use os.sep in the
    # check so ``target_root_evil`` isn't accepted as a prefix of
    # ``target_root``.
    if (resolved_member != resolved_root
            and not resolved_member.startswith(resolved_root + os.sep)):
        raise UnsafeArchive(
            f"archive entry escapes target directory: {member_name!r} "
            f"would write to {resolved_member!r}",
        )
    return resolved_member


def _check_bomb_ratio(uncompressed: int, compressed: int,
                      member_name: str) -> None:
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
    archive_path: str, target: str,
    progress: Callable[[int, int, str], None] | None,
) -> int:
    """Extract a ZIP-family archive. Returns the count of files
    actually written (directories don't count; they're created as
    a side effect of ensuring parents for file entries)."""
    with zipfile.ZipFile(archive_path) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_EXTRACT_FILES:
            raise UnsafeArchive(
                f"archive has {len(infos)} entries; cap is "
                f"{MAX_EXTRACT_FILES}",
            )
        # Pre-sum uncompressed sizes so a declaration of 10 GiB total
        # is refused before we've written even one byte.
        total_uncompressed = sum(
            max(0, i.file_size) for i in infos if not i.is_dir()
        )
        if total_uncompressed > MAX_EXTRACT_TOTAL_BYTES:
            raise UnsafeArchive(
                f"archive declares {total_uncompressed} uncompressed "
                f"bytes; cap is {MAX_EXTRACT_TOTAL_BYTES}",
            )
        files_total = sum(1 for i in infos if not i.is_dir())
        files_done = 0
        for info in infos:
            name = info.filename
            # zipfile flags directories by trailing slash OR
            # explicit attrs; use is_dir() to cover both.
            if info.is_dir():
                dest = _safe_member_path(target, name)
                os.makedirs(dest, exist_ok=True)
                continue
            _check_bomb_ratio(
                info.file_size, info.compress_size, name,
            )
            dest = _safe_member_path(target, name)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            # Stream decompressed bytes — no whole-file buffer.
            with zf.open(info) as src, open(dest, "wb") as dst:
                shutil.copyfileobj(src, dst, length=64 * 1024)
            files_done += 1
            if progress is not None:
                progress(files_done, files_total, name)
        return files_done


def _extract_tar(
    archive_path: str, target: str,
    progress: Callable[[int, int, str], None] | None,
) -> int:
    """Extract a TAR-family archive. Tarfile sniffs gz/bz2/xz from
    the magic bytes so a single ``mode='r:*'`` open handles all
    four compressed variants."""
    with tarfile.open(archive_path, mode="r:*") as tf:
        members = tf.getmembers()
        if len(members) > MAX_EXTRACT_FILES:
            raise UnsafeArchive(
                f"archive has {len(members)} entries; cap is "
                f"{MAX_EXTRACT_FILES}",
            )
        total_uncompressed = sum(
            max(0, m.size) for m in members if m.isfile()
        )
        if total_uncompressed > MAX_EXTRACT_TOTAL_BYTES:
            raise UnsafeArchive(
                f"archive declares {total_uncompressed} uncompressed "
                f"bytes; cap is {MAX_EXTRACT_TOTAL_BYTES}",
            )
        files_total = sum(1 for m in members if m.isfile())
        files_done = 0
        for m in members:
            # Tar members can be symlinks, hardlinks, device nodes,
            # FIFOs — all of which can escape the target dir or
            # trigger host-side side-effects we never want to
            # execute automatically. Only REG + DIR pass.
            if m.issym() or m.islnk():
                raise UnsafeArchive(
                    f"tar entry is a link (sym or hard): {m.name!r}",
                )
            if not (m.isfile() or m.isdir()):
                raise UnsafeArchive(
                    f"tar entry has unsupported type "
                    f"{getattr(m, 'type', b'?')!r}: {m.name!r}",
                )
            if m.isdir():
                dest = _safe_member_path(target, m.name)
                os.makedirs(dest, exist_ok=True)
                continue
            # Tarfile doesn't expose per-entry compressed size the
            # same way zipfile does — the whole archive is a single
            # compressed stream. The total-bytes cap above catches
            # declared bloat; skip per-entry ratio checks.
            dest = _safe_member_path(target, m.name)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            src = tf.extractfile(m)
            if src is None:
                # Some non-regular types leak through isfile() on
                # older Python versions — defensive skip.
                continue
            try:
                with open(dest, "wb") as dst:
                    shutil.copyfileobj(src, dst, length=64 * 1024)
            finally:
                src.close()
            files_done += 1
            if progress is not None:
                progress(files_done, files_total, m.name)
        return files_done


def _extract_7z(
    archive_path: str, target: str,
    progress: Callable[[int, int, str], None] | None,
) -> int:
    """Extract a 7z archive via py7zr. Safety caps are applied
    before extraction starts; py7zr's own ``extractall`` is called
    only after every path has passed the zip-slip check."""
    if not SEVEN_Z_AVAILABLE:
        raise UnsafeArchive(
            "7z extraction requires py7zr — install with: "
            "pip install py7zr",
        )
    with py7zr.SevenZipFile(archive_path, mode="r") as sz:  # type: ignore[misc]
        # py7zr.list() returns FileInfo objects with uncompressed
        # sizes but no compressed size per entry; cap on count +
        # total bytes.
        entries = sz.list()
        if len(entries) > MAX_EXTRACT_FILES:
            raise UnsafeArchive(
                f"archive has {len(entries)} entries; cap is "
                f"{MAX_EXTRACT_FILES}",
            )
        total_uncompressed = sum(
            max(0, getattr(e, "uncompressed", 0)) for e in entries
        )
        if total_uncompressed > MAX_EXTRACT_TOTAL_BYTES:
            raise UnsafeArchive(
                f"archive declares {total_uncompressed} uncompressed "
                f"bytes; cap is {MAX_EXTRACT_TOTAL_BYTES}",
            )
        # Zip-slip pre-flight — validate every name BEFORE py7zr
        # starts writing. If we detect an escape on entry 50 of
        # 100 after extraction began, entries 1..49 are already on
        # disk and we'd have to reverse them.
        for e in entries:
            name = getattr(e, "filename", "")
            if not name:
                continue
            _safe_member_path(target, name)
        # py7zr.extractall can't cooperate with a per-entry progress
        # callback in a portable way; emit a single "starting"
        # progress and a single "done" progress.
        if progress is not None:
            progress(0, len(entries), "")
    # py7zr needs its own fresh open for extraction — the sz.list()
    # above advanced internal state.
    with py7zr.SevenZipFile(archive_path, mode="r") as sz:  # type: ignore[misc]
        sz.extractall(path=target)
    files_written = sum(
        1 for e in entries if not getattr(e, "is_directory", False)
    )
    if progress is not None:
        progress(files_written, files_written, "")
    return files_written


# --------------------------------------------------------------------------
# Dispatcher
# --------------------------------------------------------------------------


def extract(
    archive_path: str, target: str, *,
    progress: Callable[[int, int, str], None] | None = None,
) -> int:
    """Extract *archive_path* into *target*.

    *target* must NOT exist yet; the function creates it (0o755) and
    removes it on any failure so the caller never sees a partial
    state. That matters because a failure mid-extract can leave the
    target populated with attacker-controlled files even when the
    exception correctly refuses the run — callers treating the
    failure as "tried to extract, ignore" would then be fooled into
    trusting partial content. Clean-on-fail removes the temptation.

    Returns the number of regular files written.
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
        raise UnsafeArchive(
            f"unsupported archive extension: {archive_path!r}",
        )
    os.makedirs(target, mode=0o755, exist_ok=False)
    # Defence against a symlink-swap race: right after makedirs we
    # created a real directory at *target*. A parallel process with
    # write access to the parent dir could, in principle, rm -rf the
    # new dir and replace it with a symlink (e.g. to /etc) before we
    # start writing entries. ``exist_ok=False`` blocks pre-planted
    # symlinks; this check closes the post-makedirs window.
    #
    # We only test whether ``target`` itself is a symlink — NOT
    # whether its realpath equals abspath. A realpath-vs-abspath
    # comparison would reject legitimate cases where an ANCESTOR of
    # target is a symlink (macOS ``/tmp`` → ``/private/tmp``, distro
    # ``/var/run`` → ``/run``), which isn't the attack we care
    # about.
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
    try:
        written = runner(archive_path, target, progress)
        # Post-extraction sanity: some archive formats (notably 7z via
        # py7zr) let per-entry metadata claim smaller than the actual
        # decompressed size. We track the declared total during
        # pre-flight (MAX_EXTRACT_TOTAL_BYTES) but the declared total
        # can lie. Walk target once and re-verify against the cap,
        # then roll back if we over-shot.
        actual_bytes = _measure_tree_bytes(target)
        if actual_bytes > MAX_EXTRACT_TOTAL_BYTES:
            shutil.rmtree(target, ignore_errors=True)
            raise UnsafeArchive(
                f"archive extracted {actual_bytes} bytes; cap is "
                f"{MAX_EXTRACT_TOTAL_BYTES} — likely bomb with "
                "declared-size metadata smaller than reality",
            )
        return written
    except BaseException:
        # Cleanup on ANY failure — UnsafeArchive, ExtractCancelled,
        # OSError, KeyboardInterrupt. Leaving partial content behind
        # would let a malformed archive plant a handful of attacker-
        # controlled files before the escape check fires on a later
        # entry.
        shutil.rmtree(target, ignore_errors=True)
        raise


def _measure_tree_bytes(root: str) -> int:
    """Sum the sizes of all regular files under *root*, skipping
    symlinks (we never write them; following them during
    measurement would allow escape). Used by :func:`extract` as a
    post-extraction size-cap re-verification that doesn't depend
    on archive-declared metadata.
    """
    total = 0
    for dirpath, _dirnames, filenames in os.walk(
        root, followlinks=False,
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
    "ExtractCancelled",
    "MAX_COMPRESSION_RATIO",
    "MAX_EXTRACT_FILES",
    "MAX_EXTRACT_TOTAL_BYTES",
    "SEVEN_Z_AVAILABLE",
    "UnsafeArchive",
    "auto_suffix_dir",
    "extract",
    "is_supported_archive",
    "strip_archive_extension",
]
