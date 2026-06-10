"""Resumable cross-backend copy.

Today axross's :func:`scripting.copy` runs a single straight-through
stream — if the link drops at byte 1.4 GiB into a 2 GiB transfer, the
whole operation has to start over. This module wires a manifest-based
resumable copy that:

1. Splits the source into segments (default 4 MiB each).
2. After each successful segment, atomically updates a JSON manifest
   on disk listing which segments are done and their hashes.
3. On a re-run, loads the manifest, verifies the destination's
   first-N-bytes match the recorded hash for the already-done
   segments, and resumes from the first incomplete segment.
4. Uses :class:`core.adaptive_io.AdaptiveChunker` inside each segment
   so the user gets adaptive throughput on top of resumability.

Resumability requires:

* The source backend supports byte-range reads. Backends with
  ``open_read_range(path, start, length)`` are preferred; otherwise
  we attempt a seek+read on the regular ``open_read`` handle.
* The destination supports ``open_write(append=True)`` (POSIX-y
  backends do, S3 does NOT — multipart upload is the right primitive
  there but is out of scope for this first cut; S3-as-target with
  resume falls back to "restart on failure").
* The manifest is stored locally next to the destination
  (``<dst>.axross-resume.json``) by default; pass ``manifest_path`` to
  override. Manifest is mode 0o600.

The verification on resume is conservative: every "done" segment must
match the destination's current bytes for that range *and* hash to the
expected SHA-256. Any mismatch → the manifest is discarded and the
copy restarts. Better to retransfer than to land a half-corrupt file.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import logging
import os
import tempfile
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path

from security.resume_freshness import coerce_mtime_epoch, manifest_predates_source

log = logging.getLogger(__name__)


DEFAULT_SEGMENT_SIZE = 4 * 1024 * 1024
MIN_SEGMENT_SIZE = 64 * 1024
MAX_SEGMENT_SIZE = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


@dataclass
class _Segment:
    index: int
    offset: int
    length: int
    sha256: str = ""
    done: bool = False


@dataclass
class _Manifest:
    src_label: str
    src_path: str
    dst_label: str
    dst_path: str
    total_bytes: int
    segment_size: int
    started_at: float
    updated_at: float = 0.0
    segments: list[_Segment] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "src_label": self.src_label,
            "src_path": self.src_path,
            "dst_label": self.dst_label,
            "dst_path": self.dst_path,
            "total_bytes": self.total_bytes,
            "segment_size": self.segment_size,
            "started_at": self.started_at,
            "updated_at": self.updated_at,
            "segments": [asdict(s) for s in self.segments],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "_Manifest":
        m = cls(
            src_label=str(d.get("src_label", "")),
            src_path=str(d.get("src_path", "")),
            dst_label=str(d.get("dst_label", "")),
            dst_path=str(d.get("dst_path", "")),
            total_bytes=int(d.get("total_bytes", 0) or 0),
            segment_size=int(d.get("segment_size", DEFAULT_SEGMENT_SIZE) or DEFAULT_SEGMENT_SIZE),
            started_at=float(d.get("started_at", 0.0) or 0.0),
            updated_at=float(d.get("updated_at", 0.0) or 0.0),
        )
        for entry in d.get("segments", []):
            if not isinstance(entry, dict):
                continue
            m.segments.append(
                _Segment(
                    index=int(entry.get("index", 0) or 0),
                    offset=int(entry.get("offset", 0) or 0),
                    length=int(entry.get("length", 0) or 0),
                    sha256=str(entry.get("sha256", "")),
                    done=bool(entry.get("done", False)),
                )
            )
        return m


def _load_manifest(path: Path) -> _Manifest | None:
    if not path.exists():
        return None
    if path.is_symlink():
        log.warning("copy_resume: refusing symlinked manifest %s", path)
        return None
    try:
        size = path.stat().st_size
    except OSError as exc:
        log.warning("copy_resume: cannot stat manifest %s: %s", path, exc)
        return None
    if size > MAX_MANIFEST_BYTES:
        log.warning("copy_resume: manifest %s is %d bytes — discarding", path, size)
        return None
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("copy_resume: cannot read manifest %s: %s", path, exc)
        return None
    try:
        manifest = _Manifest.from_dict(d)
        _validate_manifest(manifest)
        return manifest
    except (TypeError, ValueError) as exc:
        log.warning("copy_resume: malformed manifest %s: %s", path, exc)
        return None


def _validate_manifest(manifest: _Manifest) -> None:
    """Fail closed on hostile or stale manifest shape."""
    if manifest.total_bytes <= 0:
        raise ValueError("total_bytes must be positive")
    if not (MIN_SEGMENT_SIZE <= manifest.segment_size <= MAX_SEGMENT_SIZE):
        raise ValueError("segment_size outside supported range")
    if not manifest.segments:
        raise ValueError("manifest has no segments")
    expected_offset = 0
    for expected_index, seg in enumerate(manifest.segments):
        if seg.index != expected_index:
            raise ValueError("segment indexes are not contiguous")
        if seg.offset != expected_offset:
            raise ValueError("segment offsets are not contiguous")
        if seg.length <= 0:
            raise ValueError("segment length must be positive")
        expected_offset += seg.length
        if seg.done:
            if len(seg.sha256) != 64 or any(
                c not in "0123456789abcdef" for c in seg.sha256.lower()
            ):
                raise ValueError("done segment has invalid sha256")
    if expected_offset != manifest.total_bytes:
        raise ValueError("segments do not cover total_bytes")


def _save_manifest(manifest: _Manifest, path: Path) -> None:
    manifest.updated_at = time.time()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise OSError(f"copy_resume: refusing symlinked manifest directory {path.parent}")
    if path.is_symlink():
        raise OSError(f"copy_resume: refusing symlinked manifest {path}")
    fd, tmp = tempfile.mkstemp(
        prefix=".resume-",
        suffix=".tmp",
        dir=str(path.parent),
    )
    try:
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(manifest.to_dict(), fh)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Backend capability probes
# ---------------------------------------------------------------------------


def _supports_range_read(backend) -> bool:
    return hasattr(backend, "open_read_range") or _supports_seek(backend)


def _supports_seek(backend) -> bool:
    """Best-effort check: the backend's ``open_read`` returns a seekable
    handle. We can't know for sure without opening one — the runtime
    fallback in :func:`_read_segment` handles the actual case."""
    return hasattr(backend, "supports_seek_read") and bool(backend.supports_seek_read)


def _read_segment(backend, path: str, offset: int, length: int) -> bytes:
    """Read one segment from any source backend."""
    if hasattr(backend, "open_read_range"):
        h = backend.open_read_range(path, offset, length)
        try:
            return h.read(length)
        finally:
            try:
                h.close()
            except Exception as exc:  # noqa: BLE001
                log.debug("copy_resume: close raised: %s", exc)
    h = backend.open_read(path)
    try:
        if hasattr(h, "seek"):
            try:
                h.seek(offset)
                return h.read(length)
            except (OSError, ValueError):
                # Fall through to drain.
                h.close()
                h = backend.open_read(path)
        # Drain to offset — last-resort fallback.
        skipped = 0
        while skipped < offset:
            buf = h.read(min(64 * 1024, offset - skipped))
            if not buf:
                return b""
            skipped += len(buf)
        return h.read(length)
    finally:
        try:
            h.close()
        except Exception as exc:  # noqa: BLE001
            log.debug("copy_resume: close raised: %s", exc)


def _verify_segment_bytes(
    backend,
    path: str,
    offset: int,
    length: int,
    expected_hash: str,
) -> bool:
    """Return True iff ``backend:path`` for ``[offset, offset+length)``
    currently hashes to ``expected_hash``. Used to verify both that the
    destination's already-written prefix is intact AND that the source's
    bytes for a previously-completed segment still match what we
    recorded — if a same-size in-place rewrite of the source happened
    between runs, the destination prefix could still match the old hash
    while the source bytes for the same range no longer do. Continuing
    would splice an old-source prefix to a new-source suffix.
    """
    try:
        data = _read_segment(backend, path, offset, length)
    except OSError as exc:
        log.debug("copy_resume: verify read failed: %s", exc)
        return False
    if len(data) != length:
        return False
    return hashlib.sha256(data).hexdigest() == expected_hash


def _src_mtime_epoch(src_stat) -> float:
    """Pull a unix-epoch mtime out of a backend stat result.

    Delegates the shape-shimming to
    :func:`security.resume_freshness.coerce_mtime_epoch`; FileItem
    exposes ``modified: datetime`` while a handful of older shims still
    surface ``mtime: float``. Returns 0.0 when no mtime is reported so
    the freshness check correctly abstains.
    """
    raw = getattr(src_stat, "modified", None)
    if raw is None:
        raw = getattr(src_stat, "mtime", None)
    return coerce_mtime_epoch(raw)


def _dst_size(backend, path: str) -> int | None:
    try:
        item = backend.stat(path)
    except OSError:
        return None
    try:
        return int(getattr(item, "size", 0) or 0)
    except (TypeError, ValueError):
        return None


def _open_write_for_resume(backend, path: str, *, append: bool):
    """Open a destination write handle with a clear failure for backends
    that cannot append.

    Some older backend doubles expose ``open_write(path)`` only. Fresh
    copies can still use them; true resume needs append semantics after
    verified bytes.
    """
    open_write = backend.open_write
    try:
        sig = inspect.signature(open_write)
    except (TypeError, ValueError):
        sig = None
    accepts_append = True
    if sig is not None:
        accepts_append = "append" in sig.parameters or any(
            p.kind is inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
        )
    if accepts_append:
        try:
            return open_write(path, append=append)
        except TypeError as exc:
            if append:
                raise OSError(
                    f"{getattr(backend, 'name', type(backend).__name__)} "
                    "does not support append writes required to resume"
                ) from exc
            return open_write(path)
    if append:
        raise OSError(
            f"{getattr(backend, 'name', type(backend).__name__)} does not "
            "support append writes required to resume"
        )
    return open_write(path)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


@dataclass
class ResumeReport:
    src_label: str
    src_path: str
    dst_label: str
    dst_path: str
    total_bytes: int
    bytes_transferred: int
    segments_skipped: int
    segments_transferred: int
    elapsed_s: float
    manifest_path: str
    completed: bool

    def summary(self) -> str:
        return (
            f"copy_resume: {self.src_label}:{self.src_path} → "
            f"{self.dst_label}:{self.dst_path} "
            f"({self.bytes_transferred}/{self.total_bytes} bytes, "
            f"{self.segments_skipped} skipped + "
            f"{self.segments_transferred} transferred, "
            f"{self.elapsed_s:.1f}s)" + (" — done" if self.completed else " — INCOMPLETE")
        )


def resumable_copy(
    src_backend,
    src_path: str,
    dst_backend,
    dst_path: str,
    *,
    segment_size: int = DEFAULT_SEGMENT_SIZE,
    manifest_path: str | os.PathLike[str] | None = None,
    overwrite: bool = False,
    progress: Callable[[int, int], None] | None = None,
) -> ResumeReport:
    """Copy with checkpoint-resume.

    Args:
        src_backend, src_path: source.
        dst_backend, dst_path: destination.
        segment_size: bytes per segment. Clamped to
            ``[MIN_SEGMENT_SIZE, MAX_SEGMENT_SIZE]``.
        manifest_path: where to keep the resume manifest. Defaults to
            ``"<dst>.axross-resume.json"`` next to the destination
            path on the local filesystem (NOT on the destination
            backend).
        overwrite: when True, ignore any existing destination
            content. Default False — refuse if the destination already
            exists and the manifest can't account for it.
        progress: optional callable ``progress(bytes_done, total)``.
    """
    seg_size = max(MIN_SEGMENT_SIZE, min(MAX_SEGMENT_SIZE, int(segment_size)))
    src_label = getattr(src_backend, "name", type(src_backend).__name__)
    dst_label = getattr(dst_backend, "name", type(dst_backend).__name__)
    started = time.monotonic()
    started_at = time.time()

    # Manifest path — local file, default beside the destination's basename.
    if manifest_path is None:
        local_dir = Path(tempfile.gettempdir()) / "axross-resume"
        local_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(local_dir, 0o700)
        except OSError as exc:
            log.debug("copy_resume: cannot chmod %s: %s", local_dir, exc)
        safe = (dst_label + dst_path).replace("/", "_").replace(":", "_")[:120]
        mpath = local_dir / f"{safe}.json"
    else:
        mpath = Path(manifest_path)

    # Probe source size.
    try:
        src_stat = src_backend.stat(src_path)
    except OSError as exc:
        raise OSError(f"resumable_copy: cannot stat source {src_path!r}: {exc}") from exc
    total = int(getattr(src_stat, "size", 0) or 0)
    if total <= 0:
        raise OSError(
            f"resumable_copy: source {src_path!r} reports size={total}; "
            "refusing — resume only makes sense for sized files"
        )

    # Build / load manifest.
    manifest = _load_manifest(mpath)
    loaded_resume_manifest = manifest is not None
    if manifest and (
        manifest.src_path != src_path
        or manifest.dst_path != dst_path
        or manifest.total_bytes != total
        or manifest.segment_size != seg_size
    ):
        log.warning(
            "copy_resume: existing manifest does not match the current "
            "transfer (src/dst/size/segment differ) — discarding"
        )
        manifest = None
        loaded_resume_manifest = False

    # Defense-in-depth: if the source backend surfaces an
    # mtime, an O(1) compare against manifest.started_at catches an
    # in-place rewrite that happened after we recorded segment hashes.
    # The per-segment hash check below is still the inner authority;
    # this layer just short-circuits the obvious-stale case without
    # paying full re-hash cost. Backends that report mtime=0.0 (some
    # S3 listings) abstain from this layer — that is fine and
    # matches pre-fix behaviour.
    if manifest is not None:
        src_mtime = _src_mtime_epoch(src_stat)
        if manifest_predates_source(
            started_at=manifest.started_at,
            current_source_mtime=src_mtime,
        ):
            log.warning(
                "copy_resume: source mtime (%.3f) is newer than manifest "
                "started_at (%.3f); discarding stale manifest",
                src_mtime, manifest.started_at,
            )
            manifest = None
            loaded_resume_manifest = False

    if manifest is None:
        segments: list[_Segment] = []
        for i, off in enumerate(range(0, total, seg_size)):
            length = min(seg_size, total - off)
            segments.append(_Segment(index=i, offset=off, length=length))
        manifest = _Manifest(
            src_label=src_label,
            src_path=src_path,
            dst_label=dst_label,
            dst_path=dst_path,
            total_bytes=total,
            segment_size=seg_size,
            started_at=started_at,
            segments=segments,
        )
        _save_manifest(manifest, mpath)

    # On resume, verify already-done segments against the destination.
    bytes_skipped = 0
    restart_from_scratch = False
    if any(s.done for s in manifest.segments):
        log.info(
            "copy_resume: verifying %d segment(s) of prior progress …",
            sum(1 for s in manifest.segments if s.done),
        )
        for seg in manifest.segments:
            if not seg.done:
                continue
            dst_ok = _verify_segment_bytes(
                dst_backend,
                dst_path,
                seg.offset,
                seg.length,
                seg.sha256,
            )
            src_ok = _verify_segment_bytes(
                src_backend,
                src_path,
                seg.offset,
                seg.length,
                seg.sha256,
            )
            if not (dst_ok and src_ok):
                log.warning(
                    "copy_resume: segment %d verification failed "
                    "(dst_ok=%s, src_ok=%s); discarding manifest and "
                    "restarting",
                    seg.index,
                    dst_ok,
                    src_ok,
                )
                for s in manifest.segments:
                    s.done = False
                    s.sha256 = ""
                _save_manifest(manifest, mpath)
                bytes_skipped = 0
                restart_from_scratch = True
                break
            bytes_skipped += seg.length

    existing_size = _dst_size(dst_backend, dst_path)
    if bytes_skipped > 0 and existing_size != bytes_skipped:
        log.warning(
            "copy_resume: destination size is %s but verified resume "
            "prefix is %d bytes; restarting from scratch to avoid "
            "appending after a partial segment",
            "unknown" if existing_size is None else existing_size,
            bytes_skipped,
        )
        for s in manifest.segments:
            s.done = False
            s.sha256 = ""
        _save_manifest(manifest, mpath)
        bytes_skipped = 0
        restart_from_scratch = True

    # Refuse to overwrite a destination that exists if no matching
    # resume manifest accounts for it. A matching partial manifest is
    # allowed to restart from byte 0; otherwise a broken transfer could
    # never recover after failing before the first segment checkpoint.
    if not overwrite and bytes_skipped == 0:
        if existing_size and existing_size > 0:
            if loaded_resume_manifest or restart_from_scratch:
                log.warning(
                    "copy_resume: overwriting partial destination %s "
                    "while restarting a recorded resumable transfer",
                    dst_path,
                )
            else:
                raise FileExistsError(
                    f"resumable_copy: destination {dst_path!r} exists "
                    f"({existing_size} bytes) and no resume state. "
                    "Pass overwrite=True to replace."
                )

    # Open destination.
    append_mode = bytes_skipped > 0
    try:
        dst_handle = _open_write_for_resume(
            dst_backend,
            dst_path,
            append=append_mode,
        )
    except OSError as exc:
        raise OSError(f"resumable_copy: cannot open destination {dst_path!r}: {exc}") from exc

    bytes_done = bytes_skipped
    transferred = 0
    try:
        for seg in manifest.segments:
            if seg.done:
                continue
            data = _read_segment(src_backend, src_path, seg.offset, seg.length)
            if len(data) != seg.length:
                raise OSError(
                    f"resumable_copy: short read at offset {seg.offset} "
                    f"({len(data)} of {seg.length} bytes)"
                )
            written = dst_handle.write(data)
            if written is not None and int(written) != len(data):
                raise OSError(
                    f"resumable_copy: short write at offset {seg.offset} "
                    f"({written} of {len(data)} bytes)"
                )
            seg.sha256 = hashlib.sha256(data).hexdigest()
            seg.done = True
            transferred += 1
            bytes_done += len(data)
            _save_manifest(manifest, mpath)
            if progress is not None:
                try:
                    progress(bytes_done, total)
                except Exception as exc:  # noqa: BLE001
                    log.warning("resumable_copy: progress raised: %s", exc)
    finally:
        try:
            dst_handle.close()
        except Exception as exc:  # noqa: BLE001
            log.debug("resumable_copy: close raised: %s", exc)

    completed = all(s.done for s in manifest.segments)
    if completed:
        # Successful end-to-end: clean the manifest. Keeping it would
        # confuse a future copy of the same path.
        try:
            mpath.unlink(missing_ok=True)
        except OSError as exc:
            log.debug("resumable_copy: cannot unlink manifest: %s", exc)

    return ResumeReport(
        src_label=src_label,
        src_path=src_path,
        dst_label=dst_label,
        dst_path=dst_path,
        total_bytes=total,
        bytes_transferred=bytes_done,
        segments_skipped=sum(1 for s in manifest.segments if s.done) - transferred,
        segments_transferred=transferred,
        elapsed_s=time.monotonic() - started,
        manifest_path=str(mpath),
        completed=completed,
    )


__all__ = [
    "DEFAULT_SEGMENT_SIZE",
    "MAX_SEGMENT_SIZE",
    "MIN_SEGMENT_SIZE",
    "ResumeReport",
    "resumable_copy",
]
