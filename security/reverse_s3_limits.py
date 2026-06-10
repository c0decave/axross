"""Defense-in-depth caps for reverse-S3 ListBucket responses.

The primary bound against unbounded directory descent in a hostile
backend lives inside ``core/reverse_serve.py::_walk_keys``. This
module is a *second, independent* enforcement point applied at the
HTTP boundary, after ``_walk_keys`` returns, so a future regression
that loosens the inner cap still cannot blow up the response body or
exhaust memory while serializing.

The two checks here are intentionally cheap and stateless so they can
be re-used by any code path that converts a backend listing into a
ListBucket XML body.
"""
from __future__ import annotations

from typing import Iterable

# Hard cap on the running byte cost of all retained entries. Set well
# above 5_000 keys worth of typical (~100B) paths but far below any
# memory-pressure regime for a reverse-server process.
MAX_LIST_BUCKET_BODY_BYTES = 64 * 1024 * 1024  # 64 MiB

# Per-entry rel-path budget. Reject pathological filenames synthesised
# by a hostile backend even if ``_walk_keys`` did not catch them at the
# path-length cap (because they were assembled by the join helper after
# the inner check).
MAX_ENTRY_PATH_BYTES = 4096

# Estimated XML overhead per ``<Contents>...</Contents>`` element. Used
# only for the body-byte estimator; the real serialiser may be slightly
# larger or smaller — overestimating is safer than under for a cap.
_PER_ENTRY_XML_OVERHEAD = 220


def validate_truncation_flag(
    *,
    entry_count: int,
    max_keys: int,
    claimed_truncated: bool,
    walk_truncated: bool,
) -> bool:
    """Defense-in-depth for the truncation-flag contract.

    Return the truncation flag the response MUST advertise, regardless
    of what the caller computed. The S3 contract is "IsTruncated=true
    when more keys exist beyond this response." The reverse-S3 server
    derives that flag from three signals:

    * ``walk_truncated`` — ``_walk_keys`` stopped before exhaustion
      (directory-visit cap, path-length cap, or max_keys reached).
    * ``entry_count >= max_keys`` — we returned the entire requested
      window so more may exist.
    * ``claimed_truncated`` — what the caller already decided.

    The function returns ``True`` if ANY of these signals say
    truncated. The failure mode was missing the walk-truncated
    signal: a directory-cap stop with ``entry_count < max_keys``
    yielded ``IsTruncated=false`` and paginating clients silently
    missed keys. This helper makes the OR explicit at the boundary so
    a regression that loses one signal cannot re-introduce the lie.
    """
    if max_keys < 0:
        raise ValueError("max_keys must be >= 0")
    if entry_count < 0:
        raise ValueError("entry_count must be >= 0")
    return bool(claimed_truncated or walk_truncated or entry_count >= max_keys)


def enforce_listing_caps(
    entries: Iterable[tuple[str, dict]],
    *,
    max_body_bytes: int = MAX_LIST_BUCKET_BODY_BYTES,
    max_entry_path_bytes: int = MAX_ENTRY_PATH_BYTES,
) -> tuple[list[tuple[str, dict]], bool]:
    """Re-enforce response-size caps on ListBucket entries.

    Returns ``(capped_entries, truncated)``. Drops entries whose rel
    path exceeds ``max_entry_path_bytes`` and truncates the list once
    the running byte total crosses ``max_body_bytes``. The ``truncated``
    flag is set whenever at least one entry was rejected or the list
    was cut short, so the caller can correctly populate the S3
    ``IsTruncated`` element.
    """
    if max_body_bytes < 0 or max_entry_path_bytes < 0:
        raise ValueError("caps must be non-negative")
    capped: list[tuple[str, dict]] = []
    running = 0
    truncated = False
    for entry in entries:
        rel, _meta = entry
        rel_bytes = len(rel.encode("utf-8", errors="replace"))
        if rel_bytes > max_entry_path_bytes:
            truncated = True
            continue
        per = rel_bytes + _PER_ENTRY_XML_OVERHEAD
        if running + per > max_body_bytes:
            truncated = True
            break
        running += per
        capped.append(entry)
    return capped, truncated
