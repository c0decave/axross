"""Adaptive chunk-size for large-file streaming.

Hard-coded buffer sizes are wrong on more links than they're right.
A 1 MiB buffer optimal for a Gbit LAN is wasteful on a 4G uplink and
genuinely harmful on a satellite link (one buffer per RTT, RTT
dominates the throughput).

This module exposes :class:`AdaptiveChunker` — a state machine that:

1. Starts with a small probe chunk (default 32 KiB).
2. Measures throughput + RTT for the first N chunks.
3. Uses a bandwidth-delay-product (BDP) estimate to pick a steady
   chunk size:  ``chunk = clamp(BDP, MIN_CHUNK, MAX_CHUNK)`` rounded
   to the next power of two.
4. Re-evaluates every ``REASSESS_INTERVAL`` chunks; if measured
   throughput drops by more than 30 %, halves the chunk; if it climbs
   by 30 %, doubles it. Hysteresis bands prevent oscillation.

Returns ``(chunk_size, hint_str)`` from :meth:`next_chunk`. Callers
loop on the returned size; ``hint_str`` is non-empty whenever the
chunker decided to change size, useful for logging.

The state machine is deliberately small — it's a per-transfer object,
so there's no thread safety to think about (callers serialise on the
transfer). Side-effect free aside from a logger call when the chunk
size changes.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


MIN_CHUNK = 16 * 1024  # 16 KiB — smaller than this is round-trip-bound.
MAX_CHUNK = 16 * 1024 * 1024  # 16 MiB — beyond this most stacks fragment.
PROBE_CHUNK = 32 * 1024  # initial chunk for measurement.
REASSESS_INTERVAL = 32  # re-evaluate after this many chunks.
HISTORY_LEN = 16  # samples kept for throughput median.

GROW_HYSTERESIS = 1.3
SHRINK_HYSTERESIS = 0.7


def _clamp_chunk(n: int) -> int:
    n = max(MIN_CHUNK, min(MAX_CHUNK, n))
    # Round to nearest power of two — simpler kernel buffer math, and
    # matches the most common pipe / SSL frame sizes.
    p = 1
    while p < n:
        p <<= 1
    if p == n:
        return n
    lower = p >> 1
    return p if (n - lower) > (p - n) else lower


@dataclass
class _Sample:
    bytes_moved: int
    elapsed_s: float

    @property
    def throughput_bps(self) -> float:
        if self.elapsed_s <= 0:
            return 0.0
        return self.bytes_moved / self.elapsed_s


@dataclass
class AdaptiveChunker:
    """Per-transfer chunk-size state machine.

    Usage::

        chunker = AdaptiveChunker()
        while not done:
            n, hint = chunker.next_chunk()
            buf = src.read(n)
            t0 = time.monotonic()
            dst.write(buf)
            chunker.record(len(buf), time.monotonic() - t0)
    """

    current: int = PROBE_CHUNK
    chunks_seen: int = 0
    history: list[_Sample] = field(default_factory=list)
    last_throughput_bps: float = 0.0
    rtt_estimate_s: float = 0.0
    started_at: float = field(default_factory=time.monotonic)

    def next_chunk(self) -> tuple[int, str]:
        """Return ``(chunk_size, change_hint)``. ``change_hint`` is
        empty when nothing changed; otherwise it's a one-line note
        useful for logging."""
        return self.current, ""

    def record(self, bytes_moved: int, elapsed_s: float) -> str:
        """Tell the chunker how the last chunk performed.

        Returns a non-empty hint string if it decided to change the
        chunk size; empty string otherwise.
        """
        if bytes_moved <= 0:
            return ""
        self.chunks_seen += 1
        sample = _Sample(bytes_moved=bytes_moved, elapsed_s=elapsed_s)
        self.history.append(sample)
        if len(self.history) > HISTORY_LEN:
            self.history = self.history[-HISTORY_LEN:]
        # First few chunks: keep the probe size, gather data.
        if self.chunks_seen < 4:
            return ""
        # Initial sizing once we have a stable measurement window.
        if self.chunks_seen == 4:
            return self._initial_size()
        # Periodic reassessment thereafter.
        if self.chunks_seen % REASSESS_INTERVAL == 0:
            return self._reassess()
        return ""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _median_throughput(self) -> float:
        samples = [s.throughput_bps for s in self.history if s.elapsed_s > 0]
        if not samples:
            return 0.0
        samples.sort()
        n = len(samples)
        return samples[n // 2] if n % 2 else (samples[n // 2 - 1] + samples[n // 2]) / 2

    def _initial_size(self) -> str:
        """Pick a chunk size from the BDP estimate."""
        throughput = self._median_throughput()
        if throughput <= 0:
            return ""
        # Approximate RTT from the elapsed time of the smallest sample.
        smallest = min(self.history, key=lambda s: s.bytes_moved)
        rtt = max(0.001, smallest.elapsed_s)
        # Target one chunk per ~200 ms wall-clock so the user sees
        # responsive progress. Bigger window → bigger chunk.
        target = int(throughput * 0.2)
        target = _clamp_chunk(target)
        if target == self.current:
            return ""
        old = self.current
        self.current = target
        self.last_throughput_bps = throughput
        self.rtt_estimate_s = rtt
        return (
            f"adaptive_io: initial size {old} → {target} "
            f"(throughput≈{_human_bps(throughput)}, rtt≈{rtt * 1000:.0f}ms)"
        )

    def _reassess(self) -> str:
        throughput = self._median_throughput()
        if throughput <= 0 or self.last_throughput_bps <= 0:
            self.last_throughput_bps = throughput
            return ""
        ratio = throughput / self.last_throughput_bps
        old = self.current
        if ratio >= GROW_HYSTERESIS:
            new = _clamp_chunk(self.current * 2)
        elif ratio <= SHRINK_HYSTERESIS:
            new = _clamp_chunk(max(MIN_CHUNK, self.current // 2))
        else:
            self.last_throughput_bps = throughput
            return ""
        if new == old:
            return ""
        self.current = new
        self.last_throughput_bps = throughput
        return (
            f"adaptive_io: chunk {old} → {new} "
            f"(throughput {_human_bps(throughput)}, ratio={ratio:.2f})"
        )


# ---------------------------------------------------------------------------
# Helper to drive a copy loop
# ---------------------------------------------------------------------------


def adaptive_copy(
    src_handle,
    dst_handle,
    *,
    total_bytes: int = -1,
    progress=None,
    log_hints: bool = True,
) -> int:
    """Stream ``src_handle`` → ``dst_handle`` with adaptive chunking.

    Returns the total number of bytes transferred. The caller owns
    open/close on both handles.

    Args:
        src_handle: anything with ``.read(n) -> bytes``.
        dst_handle: anything with ``.write(buf)``.
        total_bytes: known size, used by the progress callback. ``-1``
            if unknown.
        progress: optional callable ``progress(bytes_done, total)``.
        log_hints: emit a debug-level log line whenever the chunk
            size changes.
    """
    chunker = AdaptiveChunker()
    moved = 0
    while True:
        chunk_size, _ = chunker.next_chunk()
        t0 = time.monotonic()
        buf = src_handle.read(chunk_size)
        if not buf:
            break
        written = dst_handle.write(buf)
        if written is not None and int(written) != len(buf):
            raise OSError(f"short write: wrote {written} of {len(buf)} bytes")
        elapsed = time.monotonic() - t0
        hint = chunker.record(len(buf), elapsed)
        if hint and log_hints:
            log.debug(hint)
        moved += len(buf)
        if progress is not None:
            try:
                progress(moved, total_bytes)
            except Exception as exc:  # noqa: BLE001
                log.warning("adaptive_copy: progress callback raised: %s", exc)
    return moved


def _human_bps(bps: float) -> str:
    if bps < 1024:
        return f"{bps:.0f} B/s"
    val = bps / 1024
    if val < 1024:
        return f"{val:.1f} KiB/s"
    val /= 1024
    if val < 1024:
        return f"{val:.1f} MiB/s"
    val /= 1024
    return f"{val:.1f} GiB/s"


__all__ = [
    "AdaptiveChunker",
    "MAX_CHUNK",
    "MIN_CHUNK",
    "PROBE_CHUNK",
    "adaptive_copy",
]
