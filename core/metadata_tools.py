"""View, remove and export file metadata on any backend.

The format work lives in :mod:`core.metadata_formats`; this module adds
what every caller (pane, viewers, scripting) needs around it:

* **Backends.** A local file is read where it is. A file on any other
  backend is copied into a private temp directory first, bounded by the
  open-size limit (:mod:`core.open_limits`) through
  :func:`core.file_analysis.copy_bounded`; the cleaned file goes back
  through the backend's atomic write path (:mod:`core.atomic_io`).
* **Write modes** (a setting, default in place):

  ``in_place``
      The original is kept in the trash (:func:`core.trash.trash_copy` -
      a hard link locally), then the file is replaced atomically, and one
      ``metadata_remove`` journal entry per run lets Ctrl+Z put every
      original back (:mod:`core.undo`). On a remote connection whose
      trash cannot be written the cleaned file is written as a copy
      instead, and the result says so.
  ``copy``
      A cleaned copy ``name.clean.ext`` next to the original, never
      overwriting anything (``name.clean (1).ext`` and so on).

  A file that changed while it was being cleaned is not overwritten.
* **Directories.** :func:`scan_metadata` / :func:`remove_folder` walk with
  :func:`core.media_collect.collect_media` (item, depth and folder caps,
  symlinked folders not followed, cancellable, progress).
* **Export** as JSON or CSV (spreadsheet formulas neutralised).

Security mode: reading and removing are explicit user actions and work in
the paranoid mode too - removal is an ordinary write, which that mode does
not block anywhere else. Only audio / video is refused there, because it
means running the external ffprobe / ffmpeg on the file's contents, which
is what the mode keeps away from untrusted bytes (it blocks the media
viewer and external viewers for the same reason).

No Qt here.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import os
import shutil
import stat
import tempfile
import threading
from collections.abc import Callable, Collection, Iterable
from dataclasses import dataclass, field

from core import metadata_formats as MF
from core import open_limits as OL
from core.metadata_formats import AUDIO, IMAGE, KINDS, OFFICE, PDF, VIDEO, Field, kind_of

log = logging.getLogger(__name__)

MODE_IN_PLACE = "in_place"
MODE_COPY = "copy"
MODES = (MODE_IN_PLACE, MODE_COPY)

#: Statuses of a :class:`RemoveResult`.
CLEANED = "cleaned"
UNCHANGED = "unchanged"
UNSUPPORTED = "unsupported"
ERROR = "error"

#: Longest a remote copy may take.
COPY_TIMEOUT = 300.0
#: Most ``name.clean (n).ext`` candidates tried for a cleaned copy.
MAX_COPY_SUFFIX = 999
#: Kinds whose whole file is held in memory while it is read or cleaned;
#: the open-size limit applies to them even on the local file system.
_IN_MEMORY_KINDS = frozenset({IMAGE, PDF})

_SETTING_MODE = "metadata_write_mode"
_SETTING_CONFIRM = "metadata_confirm_remove"

Cancel = "threading.Event | Callable[[], bool] | None"


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------


@dataclass
class MetadataReport:
    """What one file carries. ``error`` is set when it could not be read
    (completely); ``fields`` may still hold what was read before that."""

    path: str
    name: str
    kind: str | None
    fields: list[Field] = field(default_factory=list)
    error: str = ""
    size: int = 0
    truncated: bool = False

    @property
    def removable(self) -> int:
        return sum(1 for f in self.fields if f.removable)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "name": self.name,
            "kind": self.kind,
            "size": self.size,
            "error": self.error,
            "truncated": self.truncated,
            "removable_count": self.removable,
            "fields": [
                {"group": f.group, "name": f.name, "value": f.value, "removable": f.removable}
                for f in self.fields
            ],
        }


@dataclass
class RemoveResult:
    path: str
    #: ``cleaned``, ``unchanged`` (nothing to remove), ``unsupported`` or ``error``.
    status: str
    mode: str = MODE_IN_PLACE
    #: Where the cleaned file is: *path* in place, the new copy otherwise.
    output: str = ""
    #: How many removable fields the file had.
    removed: int = 0
    error: str = ""
    #: In place: the trash entry holding the original.
    trash_id: str = ""
    #: SHA-256 of what was written (undo checks it is still there).
    sha256: str = ""
    #: Anything the user should know (e.g. "wrote a copy instead").
    note: str = ""

    def to_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class BatchResult:
    """A folder or a selection: reports when reading, results when removing."""

    reports: list[MetadataReport] = field(default_factory=list)
    results: list[RemoveResult] = field(default_factory=list)
    scan: object | None = None  # core.media_collect.MediaScan of the walk
    cancelled: bool = False
    #: The journal entry of a removal ("" when nothing was written).
    operation_id: str = ""


@dataclass(frozen=True)
class Capability:
    kind: str
    read: bool
    remove: bool
    #: Why reading or removing is unavailable ("" when both work).
    reason: str = ""


# ---------------------------------------------------------------------------
# Settings (stored with the other small preferences in settings.json)
# ---------------------------------------------------------------------------


def write_mode() -> str:
    """The configured write mode; in place unless set otherwise."""
    value = OL.read_setting(_SETTING_MODE)
    return value if value in MODES else MODE_IN_PLACE


def set_write_mode(mode: str) -> None:
    if mode not in MODES:
        raise ValueError(f"metadata write mode must be one of {MODES}, not {mode!r}")
    OL.write_setting(_SETTING_MODE, mode)


def confirm_before_remove() -> bool:
    """Whether the UI asks before removing; off unless set."""
    return OL.read_setting(_SETTING_CONFIRM) is True


def set_confirm_before_remove(value: bool) -> None:
    if not isinstance(value, bool):
        raise TypeError(f"confirm_before_remove must be True or False, not {value!r}")
    OL.write_setting(_SETTING_CONFIRM, value)


# ---------------------------------------------------------------------------
# Capabilities
# ---------------------------------------------------------------------------

PYPDF_HINT = "removing PDF metadata needs pypdf (pip install 'axross[metadata]')"


def capabilities() -> dict[str, Capability]:
    """Per kind: can it be read, can it be removed, and if not, why."""
    from core.security_mode import current_policy

    caps = {
        IMAGE: Capability(IMAGE, True, True),
        OFFICE: Capability(OFFICE, True, True),
    }
    pypdf, qtpdf = MF.have_pypdf(), MF.have_qtpdf()
    caps[PDF] = Capability(
        PDF,
        pypdf or qtpdf,
        pypdf,
        "" if pypdf else (PYPDF_HINT if qtpdf else "reading PDF metadata needs pypdf or QtPdf"),
    )
    policy = current_policy()
    for kind in (AUDIO, VIDEO):
        if not policy.allow_auto_preview:
            caps[kind] = Capability(
                kind,
                False,
                False,
                f"the '{policy.name}' security mode blocks running ffprobe / ffmpeg on file "
                "contents",
            )
            continue
        probe, mpeg = MF.ffprobe_path() is not None, MF.ffmpeg_path() is not None
        reason = ""
        if not probe:
            reason = "audio/video metadata needs ffprobe (FFmpeg), which is not installed"
        elif not mpeg:
            reason = "removing audio/video metadata needs ffmpeg, which is not installed"
        caps[kind] = Capability(kind, probe, probe and mpeg, reason)
    return caps


# ---------------------------------------------------------------------------
# Getting the bytes
# ---------------------------------------------------------------------------


class _Refused(Exception):
    def __init__(self, status: str, message: str) -> None:
        super().__init__(message)
        self.status = status


class _CancelView:
    """``is_set()`` over an Event or a callable (ScanJob passes the latter)."""

    def __init__(self, cancel) -> None:
        self._cancel = cancel

    def is_set(self) -> bool:
        c = self._cancel
        if c is None:
            return False
        if isinstance(c, threading.Event):
            return c.is_set()
        try:
            return bool(c())
        except Exception:  # noqa: BLE001 - a broken callback is not a cancel
            return False


def _is_local(backend) -> bool:
    from core.local_fs import LocalFS

    return isinstance(backend, LocalFS)


def _name(backend, path: str) -> str:
    sep = "/"
    try:
        sep = backend.separator() or "/"
    except Exception:  # noqa: BLE001
        pass
    return path.rstrip(sep).rsplit(sep, 1)[-1] or path


def _too_large(size: int, limit: int) -> str:
    return (
        f"too large ({size / 1048576:.1f} MB, limit {limit / 1048576:.0f} MB; "
        "View → Open Size Limit…)"
    )


def _signature(backend, path: str) -> tuple:
    if _is_local(backend):
        st = os.stat(path)
        return (st.st_size, st.st_mtime_ns, st.st_ino)
    item = backend.stat(path)
    try:
        when = item.modified.timestamp()
    except (AttributeError, OverflowError, OSError, ValueError):
        when = None
    return (int(item.size or 0), when)


@dataclass
class _Source:
    local_path: str
    size: int
    signature: tuple
    tmpdir: str = ""

    def cleanup(self) -> None:
        if self.tmpdir:
            shutil.rmtree(self.tmpdir, ignore_errors=True)


def _open_source(backend, path: str, kind: str, cancel: _CancelView, *, for_remove: bool):
    limit = OL.max_open_bytes()
    if _is_local(backend):
        try:
            lst = os.lstat(path)
        except OSError as exc:
            raise _Refused(ERROR, f"cannot read: {exc.strerror or exc}") from exc
        if stat.S_ISLNK(lst.st_mode) and for_remove:
            raise _Refused(ERROR, "is a symbolic link; clean the file it points to instead")
        try:
            st = os.stat(path)
        except OSError as exc:
            raise _Refused(ERROR, f"cannot read: {exc.strerror or exc}") from exc
        if not stat.S_ISREG(st.st_mode):
            raise _Refused(ERROR, "not a regular file")
        if kind in _IN_MEMORY_KINDS and st.st_size > limit:
            raise _Refused(ERROR, _too_large(st.st_size, limit))
        return _Source(path, st.st_size, (st.st_size, st.st_mtime_ns, st.st_ino))
    try:
        item = backend.stat(path)
    except OSError as exc:
        raise _Refused(ERROR, f"cannot read: {exc}") from exc
    if item.is_dir:
        raise _Refused(ERROR, "is a folder")
    if item.is_link and for_remove:
        raise _Refused(ERROR, "is a symbolic link; clean the file it points to instead")
    size = int(item.size or 0)
    if size > limit:
        raise _Refused(ERROR, _too_large(size, limit))
    from core.file_analysis import Target, copy_bounded

    try:
        mtime = item.modified.timestamp()
    except (AttributeError, OverflowError, OSError, ValueError):
        mtime = 0.0
    copy = copy_bounded(
        Target(backend, path, _name(backend, path), size, mtime),
        limit,
        cancel,  # type: ignore[arg-type] - duck-typed is_set()
        COPY_TIMEOUT,
        prefix="axross-metadata-",
    )
    if copy.status != "ok":
        copy.cleanup()
        if copy.status == "too_large":
            raise _Refused(ERROR, _too_large(copy.total, limit))
        if copy.status == "cancelled":
            raise _Refused(ERROR, "cancelled")
        raise _Refused(ERROR, copy.error or f"copy {copy.status}")
    return _Source(copy.path, copy.total, _signature(backend, path), copy.tmpdir)


def _read_fields(kind: str, local_path: str, cancel: _CancelView):
    if kind == IMAGE:
        with open(local_path, "rb") as fh:
            data = fh.read()
        return MF.image_fields(data)
    if kind == OFFICE:
        return MF.office_fields(local_path)
    if kind == PDF:
        return MF.pdf_fields(local_path)
    return MF.av_fields(local_path, kind, cancel)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


def read_metadata(backend, path: str, *, cancel=None) -> MetadataReport:
    """The metadata of one file. Never raises for what the file contains:
    an unreadable or hostile file comes back with ``error`` set."""
    name = _name(backend, path)
    kind = kind_of(name)
    report = MetadataReport(path=path, name=name, kind=kind)
    if kind is None:
        report.error = "not a supported file type"
        return report
    cap = capabilities()[kind]
    if not cap.read:
        report.error = cap.reason
        return report
    view = _CancelView(cancel)
    source = None
    try:
        source = _open_source(backend, path, kind, view, for_remove=False)
        report.size = source.size
        fields, error, truncated = _read_fields(kind, source.local_path, view)
        report.fields, report.error, report.truncated = list(fields), error, truncated
    except _Refused as exc:
        report.error = str(exc)
    except Exception as exc:  # noqa: BLE001 - hostile input must not escape as an exception
        log.warning("metadata: reading %s failed: %r", path, exc)
        report.error = f"cannot read: {type(exc).__name__}: {exc}"
    finally:
        if source is not None:
            source.cleanup()
    return report


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


def clean_copy_name(name: str, n: int = 0) -> str:
    """``photo.jpg`` -> ``photo.clean.jpg``; with *n*: ``photo.clean (n).jpg``."""
    stem, ext = os.path.splitext(name)
    if not stem:
        stem, ext = name, ""
    suffix = ".clean" if n == 0 else f".clean ({n})"
    return f"{stem}{suffix}{ext}"


def _sibling(backend, path: str, name: str) -> str:
    from core.path_policy import safe_join

    return safe_join(backend, backend.parent(path), name)


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_new(backend, dst: str, local_file: str, mode_bits: int | None) -> None:
    """Create *dst* from *local_file*; FileExistsError when *dst* exists.

    Locally the file is written beside *dst* and hard-linked into place,
    which fails atomically when the name is taken. Elsewhere existence is
    checked first and the upload goes through the atomic write path."""
    if _is_local(backend):
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(dst), prefix=".tmp-", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as out, open(local_file, "rb") as src:
                shutil.copyfileobj(src, out, 1024 * 1024)
            if mode_bits is not None:
                os.chmod(tmp, mode_bits)
            os.link(tmp, dst)
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        return
    if backend.exists(dst):
        raise FileExistsError(dst)
    from core.atomic_io import atomic_write_stream

    with open(local_file, "rb") as fh:
        atomic_write_stream(backend, dst, fh)


def _write_copy(backend, path: str, local_file: str, mode_bits: int | None) -> str:
    name = _name(backend, path)
    for n in range(MAX_COPY_SUFFIX + 1):
        dst = _sibling(backend, path, clean_copy_name(name, n))
        if backend.exists(dst):
            continue
        try:
            _write_new(backend, dst, local_file, mode_bits)
        except FileExistsError:
            continue
        return dst
    raise OSError(f"no free name for a cleaned copy of {name}")


def _clean(kind: str, src: str, dst: str, cancel: _CancelView) -> None:
    if kind == IMAGE:
        with open(src, "rb") as fh:
            data = fh.read()
        cleaned = MF.image_clean(data)
        with open(dst, "wb") as out:
            out.write(cleaned)
    elif kind == OFFICE:
        MF.office_clean(src, dst)
    elif kind == PDF:
        MF.pdf_clean(src, dst)
    else:
        MF.av_clean(src, dst, kind, cancel)  # type: ignore[arg-type]


def _remove_one(backend, path: str, mode: str, view: _CancelView) -> RemoveResult:
    name = _name(backend, path)
    kind = kind_of(name)
    result = RemoveResult(path=path, status=ERROR, mode=mode)
    if kind is None:
        result.status, result.error = UNSUPPORTED, "not a supported file type"
        return result
    cap = capabilities()[kind]
    if not cap.remove:
        result.status, result.error = UNSUPPORTED, cap.reason
        return result
    source = None
    workdir = tempfile.mkdtemp(prefix="axross-metadata-clean-")
    try:
        source = _open_source(backend, path, kind, view, for_remove=True)
        fields, read_error, _ = _read_fields(kind, source.local_path, view)
        result.removed = sum(1 for f in fields if f.removable)
        if not read_error and result.removed == 0:
            result.status = UNCHANGED
            return result
        cleaned = os.path.join(workdir, "clean" + os.path.splitext(name)[1].lower())
        _clean(kind, source.local_path, cleaned, view)
        if view.is_set():
            result.error = "cancelled"
            return result
        result.sha256 = _sha256_file(cleaned)
        if _signature(backend, path) != source.signature:
            result.error = "the file changed while it was being cleaned; left as it is"
            return result
        mode_bits = None
        if _is_local(backend):
            mode_bits = os.stat(path).st_mode & 0o777
        if mode == MODE_IN_PLACE:
            from core import trash as _trash

            try:
                result.trash_id = _trash.trash_copy(
                    backend, path, local_source=None if _is_local(backend) else source.local_path
                )
            except OSError as exc:
                if _is_local(backend):
                    result.error = f"cannot keep the original in the trash: {exc}"
                    return result
                mode = result.mode = MODE_COPY
                result.note = (
                    f"the original could not be kept in this connection's trash ({exc}); "
                    "a cleaned copy was written instead"
                )
            if mode == MODE_IN_PLACE:
                from core.atomic_io import atomic_write_stream

                try:
                    with open(cleaned, "rb") as fh:
                        atomic_write_stream(backend, path, fh)
                except BaseException:
                    _trash.discard(backend, result.trash_id)
                    result.trash_id = ""
                    raise
                result.output = path
        if mode == MODE_COPY:
            result.output = _write_copy(backend, path, cleaned, mode_bits)
        result.status = CLEANED
        return result
    except _Refused as exc:
        result.status, result.error = exc.status, str(exc)
    except MF.Unavailable as exc:
        result.status, result.error = UNSUPPORTED, str(exc)
    except MF.FormatError as exc:
        result.error = str(exc)
    except Exception as exc:  # noqa: BLE001 - one file must not end a batch
        log.warning("metadata: removing from %s failed: %r", path, exc)
        result.error = f"{type(exc).__name__}: {exc}"
    finally:
        if source is not None:
            source.cleanup()
        shutil.rmtree(workdir, ignore_errors=True)
    return result


class _Journal:
    """One ``metadata_remove`` entry per run, started at the first write."""

    def __init__(self, backend, source: str, mode: str) -> None:
        self.backend = backend
        self.source = source
        self.mode = mode
        self.op_id = ""
        self.items: list[dict] = []
        self.label = getattr(backend, "name", "") or type(backend).__name__

    def add(self, result: RemoveResult) -> None:
        if result.status != CLEANED:
            return
        if not self.op_id:
            try:
                from core.operation_journal import start_operation

                self.op_id = start_operation(
                    "metadata_remove",
                    source=self.source,
                    backend=self.label,
                    details={"mode": self.mode},
                )
            except Exception as exc:  # noqa: BLE001 - the journal must not stop the work
                log.debug("metadata: journal start failed: %s", exc)
                self.op_id = ""
        item = {"path": result.path, "mode": result.mode, "sha256": result.sha256}
        if result.mode == MODE_IN_PLACE:
            item["trash_id"] = result.trash_id
        else:
            item["output"] = result.output
        self.items.append(item)

    def finish(self, failures: int, cancelled: bool) -> None:
        if not self.op_id:
            return
        try:
            from core.operation_journal import finish_operation

            finish_operation(
                self.op_id,
                "metadata_remove",
                status="done",
                source=self.source,
                backend=self.label,
                details={
                    "mode": self.mode,
                    "items": self.items,
                    "failed": failures,
                    "cancelled": cancelled,
                },
            )
        except Exception as exc:  # noqa: BLE001
            log.debug("metadata: journal finish failed: %s", exc)


def _check_mode(mode: str | None) -> str:
    chosen = write_mode() if mode is None else mode
    if chosen not in MODES:
        raise ValueError(f"metadata write mode must be one of {MODES}, not {chosen!r}")
    return chosen


def remove_many(
    backend,
    paths: Iterable[str],
    *,
    mode: str | None = None,
    cancel=None,
    progress: Callable[[int, int, str], None] | None = None,
    source: str = "",
) -> BatchResult:
    """Remove the metadata of every file in *paths* as one undoable run.

    ``mode`` defaults to the configured write mode. ``progress(done,
    total, path)`` after every file; ``cancel`` (an Event or a callable)
    is checked between files and inside long remuxes."""
    chosen = _check_mode(mode)
    todo = list(paths)
    view = _CancelView(cancel)
    batch = BatchResult()
    journal = _Journal(backend, source or (todo[0] if len(todo) == 1 else ""), chosen)
    try:
        for n, path in enumerate(todo):
            if view.is_set():
                batch.cancelled = True
                break
            result = _remove_one(backend, path, chosen, view)
            batch.results.append(result)
            journal.add(result)
            if progress is not None:
                try:
                    progress(n + 1, len(todo), path)
                except Exception as exc:  # noqa: BLE001 - a UI callback must not end the run
                    log.debug("metadata: progress callback failed: %s", exc)
        else:
            # Cancelled while the last file was being cleaned.
            batch.cancelled = view.is_set()
    finally:
        failures = sum(1 for r in batch.results if r.status == ERROR)
        journal.finish(failures, batch.cancelled)
    batch.operation_id = journal.op_id
    return batch


def remove_metadata(backend, path: str, *, mode: str | None = None, cancel=None) -> RemoveResult:
    """Remove the metadata of one file (see the module docstring for modes)."""
    return remove_many(backend, [path], mode=mode, cancel=cancel, source=path).results[0]


# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------


def collect_targets(
    backend,
    root: str,
    *,
    recursive: bool = False,
    max_depth: int | None = None,
    max_items: int | None = None,
    include_hidden: bool = False,
    only_names: Collection[str] | None = None,
    cancel=None,
    progress: Callable[[int, int, str], None] | None = None,
):
    """The supported files under *root* (a :class:`core.media_collect.MediaScan`)."""
    from core import media_collect as MC

    view = _CancelView(cancel)
    return MC.collect_media(
        backend,
        root,
        kinds=KINDS,
        recursive=recursive,
        max_depth=MC.DEFAULT_MAX_DEPTH if max_depth is None else max_depth,
        max_items=MC.DEFAULT_MAX_ITEMS if max_items is None else max_items,
        include_hidden=include_hidden,
        only_names=only_names,
        cancel=view.is_set,
        progress=progress,
        classify=kind_of,
    )


def scan_metadata(
    backend,
    root: str,
    *,
    recursive: bool = False,
    include_hidden: bool = False,
    only_names: Collection[str] | None = None,
    cancel=None,
    progress: Callable[[int, int, str], None] | None = None,
    **caps,
) -> BatchResult:
    """Read the metadata of every supported file under *root*.

    ``progress(done, total, path)`` per file read (and per folder listed
    while walking, with total 0)."""
    view = _CancelView(cancel)
    scan = collect_targets(
        backend,
        root,
        recursive=recursive,
        include_hidden=include_hidden,
        only_names=only_names,
        cancel=view,
        progress=(lambda f, i, p: progress(0, 0, p)) if progress is not None else None,
        **caps,
    )
    batch = BatchResult(scan=scan, cancelled=scan.cancelled)
    for n, item in enumerate(scan.items):
        if view.is_set():
            batch.cancelled = True
            break
        batch.reports.append(read_metadata(backend, item.path, cancel=view))
        if progress is not None:
            try:
                progress(n + 1, len(scan.items), item.path)
            except Exception as exc:  # noqa: BLE001
                log.debug("metadata: progress callback failed: %s", exc)
    return batch


def remove_folder(
    backend,
    root: str,
    *,
    recursive: bool = False,
    mode: str | None = None,
    include_hidden: bool = False,
    only_names: Collection[str] | None = None,
    cancel=None,
    progress: Callable[[int, int, str], None] | None = None,
) -> BatchResult:
    """Remove the metadata of every supported file under *root*, as one
    undoable run."""
    view = _CancelView(cancel)
    scan = collect_targets(
        backend,
        root,
        recursive=recursive,
        include_hidden=include_hidden,
        only_names=only_names,
        cancel=view,
    )
    if scan.cancelled:
        return BatchResult(scan=scan, cancelled=True)
    batch = remove_many(
        backend,
        [item.path for item in scan.items],
        mode=mode,
        cancel=view,
        progress=progress,
        source=root,
    )
    batch.scan = scan
    return batch


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

EXPORT_FORMATS = ("json", "csv")
_CSV_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def _csv_cell(value) -> str:
    text = "" if value is None else str(value)
    # A value starting like a formula would run as one in a spreadsheet.
    return "'" + text if text.startswith(_CSV_FORMULA_START) else text


def export_reports(reports: Iterable[MetadataReport], fmt: str = "json") -> str:
    """The reports as JSON (``{"files": [...]}``) or CSV (one row per field)."""
    fmt = (fmt or "").lower()
    if fmt not in EXPORT_FORMATS:
        raise ValueError(f"export format must be one of {EXPORT_FORMATS}, not {fmt!r}")
    reports = list(reports)
    if fmt == "json":
        return json.dumps(
            {"files": [r.to_dict() for r in reports]}, indent=2, ensure_ascii=False
        )
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["path", "kind", "group", "field", "value", "removable", "error"])
    for r in reports:
        rows = r.fields or [None]
        for f in rows:
            writer.writerow(
                [
                    _csv_cell(r.path),
                    r.kind or "",
                    _csv_cell(f.group if f else ""),
                    _csv_cell(f.name if f else ""),
                    _csv_cell(f.value if f else ""),
                    ("yes" if f.removable else "no") if f else "",
                    _csv_cell(r.error),
                ]
            )
    return buf.getvalue()


__all__ = [
    "BatchResult",
    "CLEANED",
    "Capability",
    "ERROR",
    "EXPORT_FORMATS",
    "MODES",
    "MODE_COPY",
    "MODE_IN_PLACE",
    "MetadataReport",
    "RemoveResult",
    "UNCHANGED",
    "UNSUPPORTED",
    "capabilities",
    "clean_copy_name",
    "collect_targets",
    "confirm_before_remove",
    "export_reports",
    "read_metadata",
    "remove_folder",
    "remove_many",
    "remove_metadata",
    "scan_metadata",
    "set_confirm_before_remove",
    "set_write_mode",
    "write_mode",
]
