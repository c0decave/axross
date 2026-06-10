"""Defense-in-depth manifest-freshness check for resumable_copy.

The primary fix re-hashes source bytes against the recorded
segment SHA on resume — that catches any in-place source rewrite. This
module adds a cheaper, O(1) early-out: if the backend reports an
mtime for the source path AND the manifest's ``started_at`` predates
it by more than a small skew tolerance, the manifest CANNOT describe
the current source content. Calling code can discard the manifest
without paying for a full per-segment re-hash.

The helper is intentionally permissive: backends that don't surface
mtime (S3 listings, exotic SFTP servers) return ``mtime=0.0`` from
``stat`` — in that case this layer abstains and the inner per-segment
hash check is the only line of defense, which is exactly the
pre-fix behaviour. A backend that DOES surface mtime now gets
a second layer for free.
"""
from __future__ import annotations

# Skew tolerance for filesystem vs wall-clock comparisons. NTFS and
# many SMB shares only have whole-second resolution; on some platforms
# (e.g. macOS HFS+) the mtime can also lag the actual write by tens of
# microseconds. 1.5s comfortably absorbs both without losing the
# "source was modified hours after we started" case this check is about.
DEFAULT_MTIME_SKEW_S = 1.5


def coerce_mtime_epoch(raw: object) -> float:
    """Coerce a stat-result mtime field to a unix-epoch float, or 0.0.

    Backends report mtimes in several shapes:

    * ``models.file_item.FileItem.modified`` — ``datetime``.
    * Legacy stat-shaped objects — ``mtime: float``.
    * Cloud backends with no mtime — return None / 0 / missing field.

    A return value of ``0.0`` signals "no usable mtime" and matches
    :func:`manifest_predates_source`'s abstain contract. This helper
    lives here (not in ``core/copy_resume``) so a future caller that
    wants to drive the same defense layer from a different module
    does not have to re-derive the datetime → epoch shimming.
    """
    if raw is None:
        return 0.0
    try:
        # ``datetime`` has ``.timestamp()``; we don't import ``datetime``
        # here to keep this module dependency-free, so we duck-type.
        ts = raw.timestamp  # type: ignore[attr-defined]
    except AttributeError:
        ts = None
    if callable(ts):
        try:
            return float(ts())
        except (OverflowError, OSError, ValueError, TypeError):
            return 0.0
    try:
        return float(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0


def manifest_predates_source(
    *,
    started_at: float,
    current_source_mtime: float,
    skew_s: float = DEFAULT_MTIME_SKEW_S,
) -> bool:
    """Return True iff the manifest is older than the current source.

    Args:
        started_at: ``_Manifest.started_at`` — wall-clock seconds when
            the manifest was created.
        current_source_mtime: backend-reported source mtime, in
            wall-clock seconds. ``0.0`` (or any non-positive value)
            means the backend did not surface mtime; in that case the
            helper abstains by returning False.
        skew_s: clock-skew tolerance, in seconds.

    A True result is a strong signal that the source was rewritten
    after the manifest was created, so any "done" segments cannot be
    trusted. Callers should discard the manifest and restart.

    A False result is NOT a guarantee of freshness — the per-segment
    hash check inside ``core.copy_resume`` is still authoritative. This
    helper only short-circuits the obvious-stale case.
    """
    if skew_s < 0:
        raise ValueError("skew_s must be >= 0")
    if current_source_mtime <= 0.0:
        # Backend didn't report mtime; defer to inner hash check.
        return False
    if started_at <= 0.0:
        # No started_at recorded — cannot compare; defer.
        return False
    return current_source_mtime > (started_at + skew_s)
