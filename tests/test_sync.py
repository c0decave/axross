#!/usr/bin/env python3
"""Turning a comparison into a sync plan.

:mod:`core.tree_compare` says what differs. This says what to DO about
it, and the interesting part is everything it refuses to decide on its
own.

A one-sided file has an obvious action: copy it to the other side. A
file that exists on both sides and differs does not — which copy is
authoritative is a judgement about intent, not about bytes, and getting
it wrong overwrites work. So the conflict policy is explicit, and the
default asks rather than guesses.

The plan is always produced before anything runs. A sync that starts
executing while the user is still reading it is a sync that cannot be
called off.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.sync import (  # noqa: E402
    POLICIES,
    Action,
    ConflictPolicy,
    SyncPlan,
    plan_sync,
    summarize_plan,
)
from core.tree_compare import ComparedEntry, Status  # noqa: E402
from models.file_item import FileItem  # noqa: E402

BASE = datetime(2026, 5, 1, 12, 0, 0)
LATER = BASE + timedelta(hours=2)


def _item(size=10, mtime=BASE) -> FileItem:
    return FileItem(name="x", size=size, modified=mtime)


def _entry(rel, status, *, left=None, right=None, reason="") -> ComparedEntry:
    return ComparedEntry(
        rel_path=rel, status=status, reason=reason or status, left=left, right=right
    )


def _action_for(plan: SyncPlan, rel: str) -> Action | None:
    for action in plan.actions:
        if action.rel_path == rel:
            return action
    return None


# --------------------------------------------------------------------------
# The unambiguous half
# --------------------------------------------------------------------------


def test_happy_left_only_file_is_copied_right():
    entries = [_entry("a.txt", Status.LEFT_ONLY, left=_item())]
    action = _action_for(plan_sync(entries), "a.txt")
    assert action.kind == "copy"
    assert action.direction == "to_right"


def test_happy_right_only_file_is_copied_left():
    entries = [_entry("b.txt", Status.RIGHT_ONLY, right=_item())]
    action = _action_for(plan_sync(entries), "b.txt")
    assert action.direction == "to_left"


def test_happy_identical_files_produce_no_action():
    plan = plan_sync([_entry("same.txt", Status.SAME, left=_item(), right=_item())])
    assert plan.actions == []


def test_edge_a_directory_present_only_on_one_side_is_created_not_copied():
    """Copying a directory as if it were a file is how a sync ends up
    with an empty file where a tree should be."""
    entries = [_entry("d", Status.LEFT_ONLY, left=FileItem(name="d", is_dir=True))]
    action = _action_for(plan_sync(entries), "d")
    assert action.kind == "mkdir"
    assert action.direction == "to_right"


# --------------------------------------------------------------------------
# Conflicts — what the tool refuses to decide alone
# --------------------------------------------------------------------------


def test_sad_default_policy_leaves_a_conflict_unresolved():
    """Which copy is authoritative is a judgement about intent. The
    default must not make it silently."""
    entries = [_entry("c.txt", Status.DIFFERS, left=_item(), right=_item(20, LATER))]
    plan = plan_sync(entries)
    assert _action_for(plan, "c.txt") is None
    assert [c.rel_path for c in plan.conflicts] == ["c.txt"]


def test_happy_newer_wins_picks_the_later_mtime():
    entries = [_entry("c.txt", Status.DIFFERS, left=_item(), right=_item(20, LATER))]
    action = _action_for(plan_sync(entries, policy=ConflictPolicy.NEWER_WINS), "c.txt")
    assert action.direction == "to_left"  # right is newer, so it travels left


def test_happy_newer_wins_the_other_way_round():
    entries = [_entry("c.txt", Status.DIFFERS, left=_item(20, LATER), right=_item())]
    action = _action_for(plan_sync(entries, policy=ConflictPolicy.NEWER_WINS), "c.txt")
    assert action.direction == "to_right"


def test_sad_newer_wins_cannot_break_a_tie_and_leaves_it_conflicted():
    """Equal timestamps with differing content is exactly the case where
    "newer" has no answer. Picking a side anyway would be a coin flip
    that overwrites someone's work."""
    entries = [_entry("c.txt", Status.DIFFERS, left=_item(10), right=_item(20))]
    plan = plan_sync(entries, policy=ConflictPolicy.NEWER_WINS)
    assert _action_for(plan, "c.txt") is None
    assert plan.conflicts


def test_happy_left_wins_is_unconditional():
    entries = [_entry("c.txt", Status.DIFFERS, left=_item(), right=_item(20, LATER))]
    action = _action_for(plan_sync(entries, policy=ConflictPolicy.LEFT_WINS), "c.txt")
    assert action.direction == "to_right"
    assert action.overwrites is True


def test_happy_right_wins_is_unconditional():
    entries = [_entry("c.txt", Status.DIFFERS, left=_item(20, LATER), right=_item())]
    action = _action_for(plan_sync(entries, policy=ConflictPolicy.RIGHT_WINS), "c.txt")
    assert action.direction == "to_left"
    assert action.overwrites is True


def test_edge_an_unresolved_comparison_is_never_synced_automatically():
    """tree_compare says UNKNOWN when it could not read or could not
    afford to hash. Acting on a verdict nobody established is how a sync
    overwrites a file it never actually compared."""
    entries = [_entry("big.bin", Status.UNKNOWN, left=_item(), right=_item())]
    for policy in POLICIES.values():
        plan = plan_sync(entries, policy=policy)
        assert _action_for(plan, "big.bin") is None
        assert plan.conflicts, policy


# --------------------------------------------------------------------------
# Plan shape
# --------------------------------------------------------------------------


def test_happy_actions_that_overwrite_are_flagged():
    """The confirmation screen has to distinguish "adds 40 files" from
    "replaces 40 files"."""
    entries = [
        _entry("new.txt", Status.LEFT_ONLY, left=_item()),
        _entry("c.txt", Status.DIFFERS, left=_item(), right=_item(20)),
    ]
    plan = plan_sync(entries, policy=ConflictPolicy.LEFT_WINS)
    assert _action_for(plan, "new.txt").overwrites is False
    assert _action_for(plan, "c.txt").overwrites is True


def test_happy_summary_counts_both_directions_and_conflicts():
    entries = [
        _entry("a", Status.LEFT_ONLY, left=_item()),
        _entry("b", Status.RIGHT_ONLY, right=_item()),
        _entry("c", Status.DIFFERS, left=_item(), right=_item(20)),
    ]
    text = summarize_plan(plan_sync(entries))
    assert "1" in text
    assert "conflict" in text.lower()


def test_edge_empty_comparison_yields_an_empty_plan():
    plan = plan_sync([])
    assert plan.actions == [] and plan.conflicts == []
    assert "nothing" in summarize_plan(plan).lower()


def test_edge_plan_is_ordered_so_directories_come_before_their_contents():
    """Copying a file into a directory that has not been created yet
    fails. Depth order is not cosmetic."""
    entries = [
        _entry("d/f.txt", Status.LEFT_ONLY, left=_item()),
        _entry("d", Status.LEFT_ONLY, left=FileItem(name="d", is_dir=True)),
    ]
    plan = plan_sync(entries)
    assert [a.rel_path for a in plan.actions] == ["d", "d/f.txt"]


def test_edge_every_policy_is_registered_by_name():
    """The UI builds its dropdown from POLICIES; a policy missing from
    it would be unreachable."""
    assert set(POLICIES.values()) == set(ConflictPolicy)


def test_sad_unknown_policy_is_rejected():
    with pytest.raises(ValueError):
        plan_sync([], policy="whatever-the-user-typed")


# --------------------------------------------------------------------------
# Mixed timezone awareness
#
# The whole point of this feature is local against remote, and those two
# disagree about tzinfo: LocalFS reports naive datetimes from the
# filesystem while S3, Azure and WebDAV report timezone-aware ones.
# Comparing the two raises TypeError in Python, so the one policy that
# looks at timestamps hit it on exactly the pairing it exists for.
# --------------------------------------------------------------------------


def test_sad_newer_wins_survives_a_naive_versus_aware_timestamp():
    from datetime import timezone

    naive = FileItem(name="x", size=10, modified=BASE)
    aware = FileItem(name="x", size=20, modified=BASE.replace(tzinfo=timezone.utc))
    entries = [_entry("c.txt", Status.DIFFERS, left=naive, right=aware)]

    plan = plan_sync(entries, policy=ConflictPolicy.NEWER_WINS)
    # It must not crash. It also must not guess: without a comparable
    # pair of timestamps, "newer" has no answer.
    assert _action_for(plan, "c.txt") is None
    assert plan.conflicts
    assert "timestamp" in plan.conflicts[0].reason.lower()


def test_happy_two_aware_timestamps_still_compare_normally():
    from datetime import timezone

    older = FileItem(name="x", size=10, modified=BASE.replace(tzinfo=timezone.utc))
    newer = FileItem(name="x", size=20, modified=LATER.replace(tzinfo=timezone.utc))
    entries = [_entry("c.txt", Status.DIFFERS, left=older, right=newer)]
    action = _action_for(plan_sync(entries, policy=ConflictPolicy.NEWER_WINS), "c.txt")
    assert action.direction == "to_left"
