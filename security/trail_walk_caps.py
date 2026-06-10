"""Defense-in-depth directory-walk caps for trail snapshots.

The primary fix in ``core/trail.py::_walk_collect`` tracks visited-
directory count against ``max_files`` so a backend that returns
endless directories without files cannot starve the per-row cap into
never tripping. This module re-states the invariant as a reusable
helper so the per-walk budget is computed in exactly one place — a
future regression that uses ``max_dirs = float('inf')`` somewhere
loses the budget but still passes the helper unit tests, and the
gate stays loud.

The helper preserves the original ``max(1, int(max_files))`` shape
so existing callers' behaviour is byte-identical. The defense-in-
depth value is in centralisation: any future caller that wants a
different floor passes it explicitly, and there is exactly one place
that knows how to convert ``max_files`` into a dir budget.
"""
from __future__ import annotations

MIN_DIR_BUDGET = 1


def compute_dir_budget(max_files: int, *, floor: int = MIN_DIR_BUDGET) -> int:
    """Return the maximum number of directories the walker may visit.

    Args:
        max_files: caller-supplied per-snapshot file-row cap. Negative
            inputs are clamped to ``floor`` so a degenerate cap does
            not silently disable directory bounding.
        floor: lowest allowed return value. ``MIN_DIR_BUDGET`` (= 1)
            preserves the original directory-bounding behaviour.

    Returns:
        ``max(floor, int(max_files))``. Always positive.
    """
    if floor < 1:
        raise ValueError("floor must be >= 1")
    try:
        budget = int(max_files)
    except (TypeError, ValueError, OverflowError):
        # float('inf') / float('-inf') raise OverflowError
        # under int() — a defense-in-depth helper must clamp to floor
        # on any non-coercible input, not propagate.
        budget = floor
    return max(floor, budget)


def budget_exhausted(*, visited: int, budget: int) -> bool:
    """Return True iff the walker has visited at least ``budget``
    distinct directories. The walker should stop and emit
    ``truncated=True``."""
    if budget < 0:
        raise ValueError("budget must be >= 0")
    if visited < 0:
        raise ValueError("visited must be >= 0")
    return visited >= budget
