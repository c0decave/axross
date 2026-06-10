"""Defense-in-depth per-backend deadline accounting for federated_search.

The primary fix in ``core/search_federation.py`` records each backend's
``started_at`` only after the adapter actually begins executing inside
the worker pool, so a backend queued behind a busy slot is not
falsely timed out. This module exposes the same accounting as a
reusable helper with a tighter invariant:

* a backend whose ``started_at`` is missing or non-positive can NEVER
  be considered overdue, no matter what the wall clock says;
* a backend's deadline is ``started_at + budget``, never derived from
  the queue-submission timestamp.

The two rules together prevent the failure mode where a
queued backend's not-yet-started timer was incorrectly compared
against a global deadline. If a future refactor of the inner loop
re-introduces the queue-submission timer by mistake, this helper
still returns the right answer when called.
"""
from __future__ import annotations

from collections.abc import Iterable


def validate_probe_timeout_keys(keys: Iterable[int]) -> list[int]:
    """Return ``keys`` after validating the timeout-accounting contract.

    Each submitted backend/probe must have its own integer key. In
    particular, duplicate backend objects may not be keyed by object id:
    that collapses independent submissions onto one ``started_at``
    timestamp and re-opens the shared-timestamp collision.
    """
    out: list[int] = []
    seen: set[int] = set()
    for key in keys:
        if not isinstance(key, int) or isinstance(key, bool):
            raise ValueError("probe timeout keys must be integer submission ids")
        if key < 0:
            raise ValueError("probe timeout keys must be non-negative")
        if key in seen:
            raise ValueError("probe timeout keys must be unique per submission")
        seen.add(key)
        out.append(key)
    return out


def probe_timeout_keys_for_count(count: int) -> list[int]:
    """Build validated timeout keys for ``count`` submitted probes."""
    if not isinstance(count, int) or isinstance(count, bool):
        raise ValueError("probe timeout key count must be an integer")
    if count < 0:
        raise ValueError("probe timeout key count must be non-negative")
    return validate_probe_timeout_keys(range(count))


def is_overbudget(
    *,
    started_at: float | None,
    budget_s: float,
    now: float,
) -> bool:
    """Return True iff a backend has actually run for longer than
    ``budget_s`` seconds. Returns False when ``started_at`` is None or
    non-positive (the backend has not started yet) — that's the
    queued-backend invariant: queued backends are never overdue.

    Args:
        started_at: ``time.monotonic()`` recorded when the adapter
            actually entered the worker thread, or ``None`` if it has
            not been recorded yet.
        budget_s: per-backend timeout budget in seconds. Negative
            values raise.
        now: current ``time.monotonic()`` reading.
    """
    if budget_s < 0:
        raise ValueError("budget_s must be >= 0")
    if started_at is None or started_at <= 0.0:
        return False
    return now - started_at > budget_s


def probe_overdue_indices(
    *,
    started_at: dict[int, float | None],
    budget_s: float,
    now: float,
) -> list[int]:
    """Variant of :func:`overdue_labels` keyed by integer probe index.

    multi_view addresses probes by their integer slot in the
    input list rather than by string label, so we expose a thin
    integer-keyed sibling that delegates to :func:`is_overbudget` and
    keeps both call sites on the same invariant.
    """
    return [
        i for i, st in started_at.items()
        if is_overbudget(started_at=st, budget_s=budget_s, now=now)
    ]


def overdue_labels(
    *,
    started_at: dict[str, float | None],
    budget_s: float,
    now: float,
) -> list[str]:
    """Return the labels whose backend has overrun ``budget_s``.

    Convenience wrapper that applies :func:`is_overbudget` to every
    entry. Order matches dict iteration so the caller sees stable
    ordering when iterating over the same dict twice.
    """
    return [
        label for label, st in started_at.items()
        if is_overbudget(started_at=st, budget_s=budget_s, now=now)
    ]
