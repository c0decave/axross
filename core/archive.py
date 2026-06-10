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

import logging
import os
import shutil
import tarfile
import time
import zipfile
from dataclasses import dataclass
from typing import Callable

log = logging.getLogger(__name__)


try:  # pragma: no cover — optional dep
    import py7zr  # type: ignore[import-not-found]

    SEVEN_Z_AVAILABLE = True
except ImportError:  # pragma: no cover
    py7zr = None  # type: ignore[assignment]
    SEVEN_Z_AVAILABLE = False


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
    ".tar",
)
_SEVEN_Z_EXTENSIONS = (".7z",)
_RAR_EXTENSIONS = (".rar",)


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
            return True
    if SEVEN_Z_AVAILABLE:
        for ext in _SEVEN_Z_EXTENSIONS:
            if lower.endswith(ext):
                return True
    if RAR_AVAILABLE:
        for ext in _RAR_EXTENSIONS:
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
    for ext in _TAR_EXTENSIONS + _ZIP_EXTENSIONS + _SEVEN_Z_EXTENSIONS + _RAR_EXTENSIONS:
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
) -> int:
    """Extract a ZIP-family archive. Returns the count of files
    actually written (directories don't count; they're created as
    a side effect of ensuring parents for file entries)."""
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
        files_total = sum(1 for i in infos if not i.is_dir())
        files_done = 0
        seen_paths: set[str] = set()
        for info in infos:
            name = info.filename
            # zipfile flags directories by trailing slash OR
            # explicit attrs; use is_dir() to cover both.
            if info.is_dir():
                dest = _safe_member_path(target, name)
                _check_duplicate_member(seen_paths, dest, name)
                os.makedirs(dest, exist_ok=True)
                continue
            _check_bomb_ratio(
                info.file_size,
                info.compress_size,
                name,
            )
            dest = _safe_member_path(target, name)
            _check_duplicate_member(seen_paths, dest, name)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            # Stream decompressed bytes — no whole-file buffer.
            with zf.open(info) as src, open(dest, "wb") as dst:
                shutil.copyfileobj(src, dst, length=64 * 1024)
            files_done += 1
            if progress is not None:
                progress(files_done, files_total, name)
        return files_done


def _extract_tar(
    archive_path: str,
    target: str,
    progress: Callable[[int, int, str], None] | None,
) -> int:
    """Extract a TAR-family archive. Tarfile sniffs gz/bz2/xz from
    the magic bytes so a single ``mode='r:*'`` open handles all
    four compressed variants."""
    with tarfile.open(archive_path, mode="r:*") as tf:
        members = tf.getmembers()
        if len(members) > MAX_EXTRACT_FILES:
            raise UnsafeArchive(
                f"archive has {len(members)} entries; cap is {MAX_EXTRACT_FILES}",
            )
        total_uncompressed = sum(max(0, m.size) for m in members if m.isfile())
        if total_uncompressed > MAX_EXTRACT_TOTAL_BYTES:
            raise UnsafeArchive(
                f"archive declares {total_uncompressed} uncompressed "
                f"bytes; cap is {MAX_EXTRACT_TOTAL_BYTES}",
            )
        files_total = sum(1 for m in members if m.isfile())
        files_done = 0
        seen_paths: set[str] = set()
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
                    f"tar entry has unsupported type {getattr(m, 'type', b'?')!r}: {m.name!r}",
                )
            if m.isdir():
                dest = _safe_member_path(target, m.name)
                _check_duplicate_member(seen_paths, dest, m.name)
                os.makedirs(dest, exist_ok=True)
                continue
            # Tarfile doesn't expose per-entry compressed size the
            # same way zipfile does — the whole archive is a single
            # compressed stream. The total-bytes cap above catches
            # declared bloat; skip per-entry ratio checks.
            dest = _safe_member_path(target, m.name)
            _check_duplicate_member(seen_paths, dest, m.name)
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
    archive_path: str,
    target: str,
    progress: Callable[[int, int, str], None] | None,
) -> int:
    """Extract a 7z archive via py7zr. Safety caps are applied
    before extraction starts; py7zr's own ``extractall`` is called
    only after every path has passed the zip-slip check."""
    if not SEVEN_Z_AVAILABLE:
        raise UnsafeArchive(
            "7z extraction requires py7zr — install with: pip install py7zr",
        )
    with py7zr.SevenZipFile(archive_path, mode="r") as sz:  # type: ignore[misc]
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
    with py7zr.SevenZipFile(archive_path, mode="r") as sz:  # type: ignore[misc]
        sz.extract(path=target, targets=safe_targets)
    files_written = sum(1 for e in entries if not getattr(e, "is_directory", False))
    if progress is not None:
        progress(files_written, files_written, "")
    return files_written


def _extract_rar(
    archive_path: str,
    target: str,
    progress: Callable[[int, int, str], None] | None,
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
                    os.makedirs(dest, exist_ok=True)
                    continue
                _check_bomb_ratio(
                    int(getattr(ri, "file_size", 0) or 0),
                    int(getattr(ri, "compress_size", 0) or 0),
                    name,
                )
                safe_targets.append(name)
            if progress is not None:
                progress(0, files_total, "")
            rf.extractall(path=target, members=safe_targets)
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
    return any(norm.startswith(req + "/") for req in requested_norm)


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

    def _matches(req_norm: str) -> bool:
        # Exact member OR a directory with at least one descendant.
        return req_norm in norm_all or any(
            other.startswith(req_norm + "/") for other in norm_all
        )

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
) -> int:
    """Partial ZIP extraction. Mirrors :func:`_extract_zip`'s guards
    (zip-slip, duplicate, bomb-ratio, count + total-byte caps) but
    applies them ONLY to the SELECTED subset. Caps are enforced across
    the selection, not the whole archive."""
    with zipfile.ZipFile(archive_path) as zf:
        infos = zf.infolist()
        requested = _resolve_selection([i.filename for i in infos], members)
        selected = [i for i in infos if _is_selected(i.filename, requested)]
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
                os.makedirs(dest, exist_ok=True)
                continue
            _check_bomb_ratio(info.file_size, info.compress_size, name)
            dest = _safe_member_path(target, name)
            _check_duplicate_member(seen_paths, dest, name)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with zf.open(info) as src, open(dest, "wb") as dst:
                shutil.copyfileobj(src, dst, length=64 * 1024)
            files_done += 1
            if progress is not None:
                progress(files_done, files_total, name)
        return files_done


def _extract_members_tar(
    archive_path: str,
    target: str,
    members: list[str],
    progress: Callable[[int, int, str], None] | None,
) -> int:
    """Partial TAR extraction. Mirrors :func:`_extract_tar`'s guards
    (symlink/hardlink + non-file/dir refusal, zip-slip, duplicate, count
    + total-byte caps) applied ONLY to the SELECTED subset."""
    with tarfile.open(archive_path, mode="r:*") as tf:
        members_all = tf.getmembers()
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
        seen_paths: set[str] = set()
        for m in selected:
            # SAME type guards as _extract_tar: reject links + anything
            # that isn't a plain file or dir BEFORE writing.
            if m.issym() or m.islnk():
                raise UnsafeArchive(
                    f"tar entry is a link (sym or hard): {m.name!r}",
                )
            if not (m.isfile() or m.isdir()):
                raise UnsafeArchive(
                    f"tar entry has unsupported type {getattr(m, 'type', b'?')!r}: {m.name!r}",
                )
            if m.isdir():
                dest = _safe_member_path(target, m.name)
                _check_duplicate_member(seen_paths, dest, m.name)
                os.makedirs(dest, exist_ok=True)
                continue
            dest = _safe_member_path(target, m.name)
            _check_duplicate_member(seen_paths, dest, m.name)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            src = tf.extractfile(m)
            if src is None:
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


def extract_members(
    archive_path: str,
    target: str,
    members: list[str],
    progress: Callable[[int, int, str], None] | None = None,
) -> int:
    """Extract ONLY the named *members* from *archive_path* into *target*.

    *members* is a list of member names as reported by
    :func:`list_archive`. A name that refers to a DIRECTORY pulls in
    every descendant (path-segment prefix match on the archive's
    normalised names — ``d`` selects ``d/a.txt`` but never a sibling
    ``d2.txt``). Returns the count of regular files written.

    Behaviour:

    * **Missing member** — any requested name absent from the archive
      raises :class:`KeyError` (message lists the missing name(s)),
      validated BEFORE writing so a typo never leaves partial state.
    * **Target contract** — mirrors :func:`extract`: *target* must NOT
      pre-exist; it is created (0o755) and removed on any failure, so
      the caller never sees partial / attacker-controlled content.
    * **Safety guards** — the SAME guards as the full extractors apply
      per selected member: symlink / non-file-non-dir refusal,
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
    os.makedirs(target, mode=0o755, exist_ok=False)
    # Same symlink-swap-race guard as extract(): the dir we just created
    # could be rm'd + replaced with a symlink by a parallel process
    # before we start writing.
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
        written = runner(archive_path, target, members, progress)
        # Post-extraction size re-verification, same as extract(): the
        # selected members' declared sizes can lie.
        actual_bytes = _measure_tree_bytes(target)
        if actual_bytes > MAX_EXTRACT_TOTAL_BYTES:
            shutil.rmtree(target, ignore_errors=True)
            raise UnsafeArchive(
                f"selection extracted {actual_bytes} bytes; cap is "
                f"{MAX_EXTRACT_TOTAL_BYTES} — likely bomb with "
                "declared-size metadata smaller than reality",
            )
        return written
    except BaseException:
        # Clean on ANY failure (UnsafeArchive, KeyError, ExtractCancelled,
        # OSError, KeyboardInterrupt) — never leave partial content.
        shutil.rmtree(target, ignore_errors=True)
        raise


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
    with zipfile.ZipFile(p) as zf:
        for zi in zf.infolist():
            out.append(
                ArchiveEntry(
                    name=zi.filename,
                    size=int(zi.file_size),
                    compressed=int(zi.compress_size),
                    mtime=_zip_date_time_to_epoch(zi.date_time),
                    is_dir=zi.is_dir(),
                ),
            )
    return out


def _list_tar(p: str) -> list[ArchiveEntry]:
    out: list[ArchiveEntry] = []
    with tarfile.open(p, mode="r:*") as tf:
        for ti in tf.getmembers():
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
                ),
            )
    return out


def _list_7z(p: str) -> list[ArchiveEntry]:
    if not SEVEN_Z_AVAILABLE:
        raise UnsafeArchive(
            "7z listing requires py7zr — install with: pip install py7zr",
        )
    out: list[ArchiveEntry] = []
    with py7zr.SevenZipFile(p, mode="r") as sz:  # type: ignore[misc]
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


def list_archive(archive_path: str) -> list[ArchiveEntry]:
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
            return _list_tar(archive_path)
    for ext in _ZIP_EXTENSIONS:
        if lower.endswith(ext):
            return _list_zip(archive_path)
    for ext in _SEVEN_Z_EXTENSIONS:
        if lower.endswith(ext):
            return _list_7z(archive_path)
    raise UnsafeArchive(
        f"unsupported archive extension: {archive_path!r}",
    )


# --------------------------------------------------------------------------
# Dispatcher
# --------------------------------------------------------------------------


def extract(
    archive_path: str,
    target: str,
    *,
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
    "RAR_AVAILABLE",
    "RarUnavailable",
    "SEVEN_Z_AVAILABLE",
    "UnsafeArchive",
    "auto_suffix_dir",
    "extract",
    "extract_members",
    "is_supported_archive",
    "list_archive",
    "strip_archive_extension",
]
