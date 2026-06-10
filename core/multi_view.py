"""Multi-backend file inspection — "is this the same file on N hosts?"

Two related verbs that both lean on the same primitive (parallel
``stat`` + ``open_read`` against multiple backends):

* :func:`compare_file` — feature #1. Take a single path and a list of
  backends; pull each one's content + metadata; emit a side-by-side
  diff record. Classic sysadmin "why does nginx run differently on
  box 4?" workflow.
* :func:`inspect_targets` — feature #2. Take a list of (backend, path)
  pairs; pull metadata + content-hash for each; emit a comparison
  matrix. Classic "is the local /tmp/foo.bin the same file as the
  S3 object and the SFTP copy?" workflow.

Both run their per-target work in a bounded thread pool so 20 hosts
do not block on the slowest one. Both have a hard size cap on
content reads (default 8 MiB per target) — passing a ``content=False``
flag suppresses content download entirely and only diffs metadata.

The diff format is intentionally machine-readable (lists of dicts,
``EQUAL``/``DIFFER``/``MISSING``/``ERROR`` markers per axis) so an
LLM agent can plan the next action. There's also a
:func:`render_compare` helper for the REPL.
"""

from __future__ import annotations

import difflib
import hashlib
import logging
import math
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field

from security.federation_timeout import probe_overdue_indices as _probe_overdue_indices

log = logging.getLogger(__name__)


DEFAULT_CONTENT_CAP_BYTES = 8 * 1024 * 1024
DEFAULT_PARALLELISM = 8
DEFAULT_PER_TARGET_TIMEOUT_S = 30.0
MAX_CONTENT_CAP_BYTES = 256 * 1024 * 1024


# ---------------------------------------------------------------------------
# Per-target probe result
# ---------------------------------------------------------------------------


@dataclass
class TargetProbe:
    """One backend × one path probe result."""

    label: str
    path: str
    exists: bool = False
    size: int = -1
    mtime: float = 0.0
    permissions: int | None = None
    is_dir: bool = False
    is_link: bool = False
    sha256: str = ""  # empty unless content was read
    content: bytes | None = None
    truncated: bool = False
    error: str = ""
    elapsed_s: float = 0.0


# ---------------------------------------------------------------------------
# Comparison verdicts
# ---------------------------------------------------------------------------


@dataclass
class CompareReport:
    """Result of comparing the SAME path across N backends."""

    path: str
    probes: list[TargetProbe] = field(default_factory=list)
    content_diff: dict[str, str] = field(default_factory=dict)
    """Pairwise human-readable diff between the first probe with
    content and each other probe. Keys are ``label`` of the right-hand
    side; values are unified-diff strings."""

    def all_equal(self, *, content: bool = True) -> bool:
        successful = [p for p in self.probes if p.exists and not p.error]
        if len(successful) <= 1:
            return False
        sizes = {p.size for p in successful}
        mtimes = {round(p.mtime, 1) for p in successful}
        if len(sizes) > 1:
            return False
        if content:
            if any(p.truncated for p in successful):
                return False
            hashes = {p.sha256 for p in successful if p.sha256}
            if hashes and len(hashes) > 1:
                return False
        return len(mtimes) == 1


@dataclass
class InspectReport:
    """Result of inspecting an arbitrary list of (backend, path) pairs."""

    targets: list[TargetProbe] = field(default_factory=list)

    def hashes_consistent(self) -> bool:
        if any(p.truncated for p in self.targets if p.sha256):
            return False
        hashes = {p.sha256 for p in self.targets if p.sha256}
        return len(hashes) <= 1


# ---------------------------------------------------------------------------
# Probe primitive
# ---------------------------------------------------------------------------


def _label_of(backend) -> str:
    return getattr(backend, "name", type(backend).__name__)


def _probe(
    backend,
    path: str,
    *,
    want_content: bool,
    content_cap: int,
    label_override: str | None = None,
) -> TargetProbe:
    """Run one stat (+ optional read) against ``backend``."""
    label = label_override or _label_of(backend)
    probe = TargetProbe(label=label, path=path)
    t0 = time.monotonic()
    try:
        item = backend.stat(path)
    except OSError as exc:
        probe.error = f"{type(exc).__name__}: {exc}"
        probe.elapsed_s = time.monotonic() - t0
        return probe

    probe.exists = True
    probe.size = int(getattr(item, "size", 0) or 0)
    probe.is_dir = bool(getattr(item, "is_dir", False))
    probe.is_link = bool(getattr(item, "is_link", False))
    probe.permissions = getattr(item, "permissions", None)
    raw_mtime = getattr(item, "modified", None)
    if raw_mtime is not None:
        try:
            probe.mtime = float(raw_mtime.timestamp())  # type: ignore[union-attr]
        except (AttributeError, OSError, OverflowError, ValueError):
            try:
                probe.mtime = float(raw_mtime)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                probe.mtime = 0.0

    if want_content and not probe.is_dir and probe.size >= 0:
        try:
            handle = backend.open_read(path)
        except OSError as exc:
            probe.error = f"open_read: {type(exc).__name__}: {exc}"
            probe.elapsed_s = time.monotonic() - t0
            return probe
        try:
            data = handle.read(content_cap + 1)
        except OSError as exc:
            probe.error = f"read: {type(exc).__name__}: {exc}"
            data = b""
        finally:
            try:
                handle.close()
            except Exception as exc:  # noqa: BLE001
                log.debug("multi_view: close raised: %s", exc)
        if len(data) > content_cap:
            probe.truncated = True
            data = data[:content_cap]
        probe.content = data
        probe.sha256 = hashlib.sha256(data).hexdigest()

    probe.elapsed_s = time.monotonic() - t0
    return probe


def _probe_parallel(
    pairs: list[tuple[object, str, str | None]],
    *,
    want_content: bool,
    content_cap: int,
    parallelism: int,
    per_target_timeout_s: float,
) -> list[TargetProbe]:
    if not pairs:
        return []
    max_workers = max(1, min(parallelism, len(pairs)))
    out: list[TargetProbe | None] = [None] * len(pairs)

    # Per-probe start timestamps so the timeout budget begins when the
    # adapter actually starts executing, not when the future was queued.
    # Without this, a probe serialised behind a busy worker shares one
    # global deadline with the workers that already started.
    started_at: dict[int, float] = {}
    started_lock = threading.Lock()

    def _run(i: int, backend, path: str, label: str | None) -> tuple[int, TargetProbe]:
        with started_lock:
            started_at[i] = time.monotonic()
        probe = _probe(
            backend,
            path,
            want_content=want_content,
            content_cap=content_cap,
            label_override=label,
        )
        return (i, probe)

    pool = ThreadPoolExecutor(max_workers=max_workers)
    futures = {
        pool.submit(_run, i, backend, path, label): (i, backend, path, label)
        for i, (backend, path, label) in enumerate(pairs)
    }
    pending = set(futures)
    budget = max(0.0, float(per_target_timeout_s))
    queue_poll_s = min(0.05, budget) if budget > 0 else 0.05
    try:
        while pending:
            now = time.monotonic()
            running_deadlines: list[float] = []
            for fut in pending:
                i = futures[fut][0]
                with started_lock:
                    st = started_at.get(i)
                if st is not None:
                    running_deadlines.append(st + budget)
            if running_deadlines:
                wake_in = min(running_deadlines) - now
            else:
                wake_in = queue_poll_s
            if wake_in <= 0:
                # Defense-in-depth: the overdue computation is
                # delegated to security/federation_timeout.py so the
                # invariant — queued probes (no started_at yet)
                # are NEVER overdue — is preserved even if this loop is
                # later refactored.
                with started_lock:
                    pending_started = {
                        futures[fut][0]: started_at.get(futures[fut][0])
                        for fut in pending
                    }
                overdue_ids = set(_probe_overdue_indices(
                    started_at=pending_started,
                    budget_s=budget,
                    now=now,
                ))
                timed_out: list = [
                    fut for fut in pending
                    if futures[fut][0] in overdue_ids
                ]
                for fut in timed_out:
                    i, backend, path, label = futures[fut]
                    fut.cancel()
                    out[i] = TargetProbe(
                        label=label or _label_of(backend),
                        path=path,
                        error=f"TimeoutError: exceeded {per_target_timeout_s:.1f}s",
                        elapsed_s=per_target_timeout_s,
                    )
                    pending.discard(fut)
                continue
            done, pending = wait(
                pending,
                timeout=wake_in,
                return_when=FIRST_COMPLETED,
            )
            if not done:
                continue
            for fut in done:
                original_i, backend, path, label = futures[fut]
                probe_label = label or _label_of(backend)
                if fut.cancelled():
                    out[original_i] = TargetProbe(
                        label=probe_label,
                        path=path,
                        error=f"TimeoutError: exceeded {per_target_timeout_s:.1f}s",
                        elapsed_s=per_target_timeout_s,
                    )
                    continue
                try:
                    i, probe = fut.result()
                except Exception as exc:  # noqa: BLE001
                    log.warning("multi_view probe raised: %s", exc)
                    probe = TargetProbe(
                        label=probe_label,
                        path=path,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                    i = original_i
                out[i] = probe
        for fut in pending:
            i, backend, path, label = futures[fut]
            fut.cancel()
            out[i] = TargetProbe(
                label=label or _label_of(backend),
                path=path,
                error=f"TimeoutError: exceeded {per_target_timeout_s:.1f}s",
                elapsed_s=per_target_timeout_s,
            )
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    return [p for p in out if p is not None]


def _validate_content_cap(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("content_cap_bytes must be an integer")
    if value < 0:
        raise ValueError("content_cap_bytes must be >= 0")
    if value > MAX_CONTENT_CAP_BYTES:
        raise ValueError(f"content_cap_bytes exceeds {MAX_CONTENT_CAP_BYTES} byte safety limit")
    return value


def _validate_parallelism(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("parallelism must be an integer")
    if value < 1:
        raise ValueError("parallelism must be >= 1")
    return value


def _validate_timeout(value: object) -> float:
    if isinstance(value, bool):
        raise ValueError("per_target_timeout_s must be a finite number")
    try:
        out = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("per_target_timeout_s must be a finite number") from exc
    if not math.isfinite(out) or out < 0:
        raise ValueError("per_target_timeout_s must be a finite number >= 0")
    return out


# ---------------------------------------------------------------------------
# Public verbs
# ---------------------------------------------------------------------------


def compare_file(
    backends: list,
    path: str,
    *,
    content: bool = True,
    content_cap_bytes: int = DEFAULT_CONTENT_CAP_BYTES,
    parallelism: int = DEFAULT_PARALLELISM,
    per_target_timeout_s: float = DEFAULT_PER_TARGET_TIMEOUT_S,
) -> CompareReport:
    """Compare the SAME path across N backends.

    Returns a :class:`CompareReport` with a per-backend
    :class:`TargetProbe` and pairwise unified diffs against the first
    backend that successfully delivered content. ``backends`` may be
    a list of opened backends (``axross.open(...)`` style) or pairs
    ``[(backend, optional_label), ...]`` where the override-label is
    used in render output.
    """
    content_cap_bytes = _validate_content_cap(content_cap_bytes)
    parallelism = _validate_parallelism(parallelism)
    per_target_timeout_s = _validate_timeout(per_target_timeout_s)
    pairs: list[tuple[object, str, str | None]] = []
    for entry in backends:
        label: str | None = None
        backend = entry
        if isinstance(entry, tuple) and len(entry) == 2:
            backend, label = entry
            label = str(label) if label is not None else None
        pairs.append((backend, path, label))
    probes = _probe_parallel(
        pairs,
        want_content=content,
        content_cap=content_cap_bytes,
        parallelism=parallelism,
        per_target_timeout_s=per_target_timeout_s,
    )
    report = CompareReport(path=path, probes=probes)
    if content:
        report.content_diff = _build_content_diffs(probes)
    return report


def inspect_targets(
    targets: list[tuple[object, str]],
    *,
    content: bool = True,
    content_cap_bytes: int = DEFAULT_CONTENT_CAP_BYTES,
    parallelism: int = DEFAULT_PARALLELISM,
    per_target_timeout_s: float = DEFAULT_PER_TARGET_TIMEOUT_S,
) -> InspectReport:
    """Inspect a list of (backend, path) pairs in parallel.

    ``targets`` is a list of ``(backend, path)``. Returns an
    :class:`InspectReport` whose ``targets`` aligns with the input
    order; entries that errored have ``exists=False`` and a populated
    ``error`` field.
    """
    content_cap_bytes = _validate_content_cap(content_cap_bytes)
    parallelism = _validate_parallelism(parallelism)
    per_target_timeout_s = _validate_timeout(per_target_timeout_s)
    normalised_targets: list[tuple[object, str, str | None]] = [
        (backend, target_path, None) for backend, target_path in targets
    ]
    probes = _probe_parallel(
        normalised_targets,
        want_content=content,
        content_cap=content_cap_bytes,
        parallelism=parallelism,
        per_target_timeout_s=per_target_timeout_s,
    )
    return InspectReport(targets=probes)


# ---------------------------------------------------------------------------
# Diff helpers
# ---------------------------------------------------------------------------


def _build_content_diffs(probes: list[TargetProbe]) -> dict[str, str]:
    """Build a unified diff from the FIRST probe with text content
    against every other probe. Binary-looking content (any NUL byte
    in the first 4 KiB) is skipped — the diff is only useful for
    text. Truncation is honoured."""
    base: TargetProbe | None = None
    for p in probes:
        if p.exists and p.content is not None and not p.error:
            if _looks_text(p.content):
                base = p
                break
    if base is None:
        return {}
    diffs: dict[str, str] = {}
    base_lines = (
        base.content.decode("utf-8", errors="replace").splitlines(keepends=False)
        if base.content is not None
        else []
    )
    for p in probes:
        if p is base or p.content is None or not p.exists:
            continue
        if not _looks_text(p.content):
            diffs[p.label] = "<binary — diff suppressed>"
            continue
        their_lines = p.content.decode("utf-8", errors="replace").splitlines(keepends=False)
        if base_lines == their_lines:
            diffs[p.label] = ""  # explicit "no diff"
            continue
        diff_text = "\n".join(
            difflib.unified_diff(
                base_lines,
                their_lines,
                fromfile=base.label,
                tofile=p.label,
                lineterm="",
            )
        )
        # Annotate truncation so the user knows the diff isn't whole-file.
        if base.truncated or p.truncated:
            diff_text = "(comparison limited to first content_cap bytes)\n" + diff_text
        diffs[p.label] = diff_text
    return diffs


def _looks_text(blob: bytes, *, sniff: int = 4096) -> bool:
    head = blob[:sniff]
    if not head:
        return True
    if b"\x00" in head:
        return False
    # Mostly-printable ASCII heuristic.
    printable = sum(1 for b in head if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(head) >= 0.85


# ---------------------------------------------------------------------------
# REPL renderer
# ---------------------------------------------------------------------------


def render_compare(report: CompareReport, *, max_diff_lines: int = 80) -> str:
    """Pretty-print a :class:`CompareReport` for the REPL."""
    lines: list[str] = []
    lines.append(f"compare {report.path!r} across {len(report.probes)} backend(s):")
    for p in report.probes:
        if p.error:
            lines.append(f"  ✗ {p.label:<28} ERROR {p.error[:120]}")
            continue
        if not p.exists:
            lines.append(f"  · {p.label:<28} <missing>")
            continue
        size = f"{p.size}B"
        h = (p.sha256[:12] + "…") if p.sha256 else "(no hash)"
        marker = "📁" if p.is_dir else "🔗" if p.is_link else "·"
        lines.append(
            f"  {marker} {p.label:<28} size={size:<10} sha256={h} "
            f"mtime={p.mtime:.0f} ({p.elapsed_s * 1000:.0f}ms)"
        )
    if report.all_equal():
        lines.append("→ all targets identical.")
    if report.content_diff:
        for label, text in report.content_diff.items():
            if not text:
                continue
            head = text.splitlines()
            if len(head) > max_diff_lines:
                extra = len(head) - max_diff_lines
                head = head[:max_diff_lines] + [f"... ({extra} more lines)"]
            lines.append(f"\n--- diff against {label} ---")
            lines.extend(head)
    return "\n".join(lines)


def render_inspect(report: InspectReport) -> str:
    lines: list[str] = []
    lines.append(f"inspect {len(report.targets)} target(s):")
    for p in report.targets:
        if p.error:
            lines.append(f"  ✗ {p.label:<28} {p.path:<40} ERROR {p.error[:120]}")
            continue
        if not p.exists:
            lines.append(f"  · {p.label:<28} {p.path:<40} <missing>")
            continue
        h = (p.sha256[:12] + "…") if p.sha256 else "(no hash)"
        lines.append(f"  · {p.label:<28} {p.path:<40} size={p.size:<10} sha256={h}")
    if report.hashes_consistent():
        lines.append("→ all collected hashes match.")
    return "\n".join(lines)


__all__ = [
    "CompareReport",
    "DEFAULT_CONTENT_CAP_BYTES",
    "DEFAULT_PARALLELISM",
    "InspectReport",
    "TargetProbe",
    "compare_file",
    "inspect_targets",
    "render_compare",
    "render_inspect",
]
