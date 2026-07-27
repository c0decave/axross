"""Turning a tree comparison into a sync plan.

:mod:`core.tree_compare` establishes what differs. This module decides
what to do about it — and most of its substance is what it refuses to
decide alone.

A file that exists on one side only has an obvious action: copy it
across. A file that exists on BOTH sides and differs does not. Which
copy is authoritative is a judgement about intent, not about bytes, and
getting it wrong overwrites someone's work with an older version. The
conflict policy is therefore explicit, and the default
(:data:`ConflictPolicy.ASK`) resolves nothing.

Two rules follow from the same principle:

* ``NEWER_WINS`` refuses ties. Equal timestamps with differing content
  is exactly the case where "newer" has no answer; choosing a side
  anyway is a coin flip with someone's data.
* An entry the comparison left as ``UNKNOWN`` — unreadable, or too
  large to hash within budget — is never synced automatically under any
  policy. Acting on a verdict nobody established is how a sync
  overwrites a file it never actually compared.

The plan is always produced before anything runs, so the user can read
it, and so a sync that looks wrong can be called off rather than
interrupted.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum

from core.tree_compare import ComparedEntry, Status

log = logging.getLogger(__name__)


class ConflictPolicy(Enum):
    """What to do when both sides have a file and they differ."""

    ASK = "ask"
    NEWER_WINS = "newer_wins"
    LEFT_WINS = "left_wins"
    RIGHT_WINS = "right_wins"


#: Display name -> policy. The UI builds its dropdown from this, so a
#: policy missing here would be unreachable.
POLICIES: dict[str, ConflictPolicy] = {
    "Ask me (nothing is overwritten)": ConflictPolicy.ASK,
    "Newer file wins": ConflictPolicy.NEWER_WINS,
    "Left side wins": ConflictPolicy.LEFT_WINS,
    "Right side wins": ConflictPolicy.RIGHT_WINS,
}


@dataclass(frozen=True)
class Action:
    """One thing the sync would do."""

    rel_path: str
    #: ``"copy"`` or ``"mkdir"``.
    kind: str
    #: ``"to_left"`` or ``"to_right"``.
    direction: str
    #: True when the destination already holds a different file. The
    #: confirmation has to distinguish "adds 40 files" from
    #: "replaces 40 files".
    overwrites: bool
    reason: str


@dataclass(frozen=True)
class Conflict:
    """A difference the policy would not resolve."""

    rel_path: str
    reason: str


@dataclass(frozen=True)
class SyncPlan:
    actions: list[Action] = field(default_factory=list)
    conflicts: list[Conflict] = field(default_factory=list)


def _depth(rel_path: str) -> int:
    return rel_path.count("/")


def _resolve_conflict(entry: ComparedEntry, policy: ConflictPolicy) -> Action | Conflict:
    left, right = entry.left, entry.right

    if policy is ConflictPolicy.LEFT_WINS:
        return Action(entry.rel_path, "copy", "to_right", True, "left side wins")
    if policy is ConflictPolicy.RIGHT_WINS:
        return Action(entry.rel_path, "copy", "to_left", True, "right side wins")

    if policy is ConflictPolicy.NEWER_WINS:
        if left is None or right is None:
            return Conflict(entry.rel_path, "one side is missing its metadata")
        try:
            left_newer = left.modified > right.modified
            right_newer = right.modified > left.modified
        except TypeError:
            # LocalFS reports naive datetimes straight from the
            # filesystem; S3, Azure and WebDAV report timezone-aware
            # ones. Python refuses to order the two — and local against
            # remote is precisely the pairing this feature exists for,
            # so the crash sat on the main path. Normalising one side
            # would be inventing an offset nobody reported, so this is a
            # conflict for the user, not a guess.
            return Conflict(
                entry.rel_path,
                "the two timestamps cannot be compared (one carries a timezone, "
                "the other does not) — 'newer wins' cannot choose",
            )
        if left_newer:
            return Action(entry.rel_path, "copy", "to_right", True, "left is newer")
        if right_newer:
            return Action(entry.rel_path, "copy", "to_left", True, "right is newer")
        # Same timestamp, different content: "newer" has no answer here,
        # and picking a side would be a coin flip with someone's work.
        return Conflict(
            entry.rel_path,
            "the two copies differ but carry the same timestamp — "
            "'newer wins' cannot choose",
        )

    return Conflict(entry.rel_path, "both sides changed; choose which one to keep")


def plan_sync(
    entries: list[ComparedEntry],
    *,
    policy: ConflictPolicy = ConflictPolicy.ASK,
) -> SyncPlan:
    """Work out what a sync would do, without doing any of it."""
    if not isinstance(policy, ConflictPolicy):
        raise ValueError(f"unknown conflict policy: {policy!r}")

    actions: list[Action] = []
    conflicts: list[Conflict] = []

    for entry in entries:
        if entry.status == Status.SAME:
            continue

        if entry.status == Status.UNKNOWN:
            # Never act on a verdict nobody established.
            conflicts.append(
                Conflict(
                    entry.rel_path,
                    f"the comparison could not be resolved ({entry.reason})",
                )
            )
            continue

        if entry.status == Status.LEFT_ONLY:
            item = entry.left
            kind = "mkdir" if item is not None and item.is_dir else "copy"
            actions.append(
                Action(entry.rel_path, kind, "to_right", False, "missing on the right")
            )
            continue

        if entry.status == Status.RIGHT_ONLY:
            item = entry.right
            kind = "mkdir" if item is not None and item.is_dir else "copy"
            actions.append(
                Action(entry.rel_path, kind, "to_left", False, "missing on the left")
            )
            continue

        if entry.status == Status.DIFFERS:
            resolved = _resolve_conflict(entry, policy)
            if isinstance(resolved, Action):
                actions.append(resolved)
            else:
                conflicts.append(resolved)

    # Shallowest first: copying a file into a directory that has not
    # been created yet fails, so depth order is correctness, not
    # cosmetics.
    actions.sort(key=lambda a: (_depth(a.rel_path), a.rel_path))
    conflicts.sort(key=lambda c: c.rel_path)
    return SyncPlan(actions=actions, conflicts=conflicts)


def summarize_plan(plan: SyncPlan) -> str:
    """One line describing a plan, for the confirmation screen."""
    if not plan.actions and not plan.conflicts:
        return "Nothing to do — the two sides already match."

    to_right = sum(1 for a in plan.actions if a.direction == "to_right")
    to_left = sum(1 for a in plan.actions if a.direction == "to_left")
    overwrites = sum(1 for a in plan.actions if a.overwrites)

    parts = [f"{to_right} → right", f"{to_left} → left"]
    if overwrites:
        parts.append(f"{overwrites} would be replaced")
    if plan.conflicts:
        parts.append(f"{len(plan.conflicts)} conflict(s) left for you")
    return ", ".join(parts)


__all__ = [
    "POLICIES",
    "Action",
    "Conflict",
    "ConflictPolicy",
    "SyncPlan",
    "plan_sync",
    "summarize_plan",
]
