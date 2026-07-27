#!/usr/bin/env python3
"""Deleting duplicates without deleting the data.

The duplicate finder lists groups of files with identical content. The
obvious next action — "delete the copies I don't want" — carries an
equally obvious way to lose everything: select every row in a group and
the content is gone from every location at once. A deduplicating tool
that permits that is a data-destruction tool.

``plan_deletion`` is the guard. It never returns a plan that would empty
a group, and it reports which groups it held back so the UI can say why
rather than silently dropping rows from the user's selection.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.cas import CasEntry  # noqa: E402
from ui.cas_dialog import plan_deletion  # noqa: E402


def _e(path: str, value: str = "h1", backend: str = "local", size: int = 10) -> CasEntry:
    return CasEntry(
        backend_id=backend,
        path=path,
        algorithm="sha256",
        value=value,
        size=size,
        indexed_at=datetime(2026, 1, 1),
    )


# --------------------------------------------------------------------------
# Happy path
# --------------------------------------------------------------------------


def test_happy_deleting_some_copies_of_a_group_is_allowed():
    group = [_e("/a"), _e("/b"), _e("/c")]
    plan = plan_deletion([group[0], group[1]], [group])
    assert [e.path for e in plan.deletable] == ["/a", "/b"]
    assert plan.refused_groups == []


def test_happy_deleting_across_several_groups():
    g1 = [_e("/a", "h1"), _e("/b", "h1")]
    g2 = [_e("/c", "h2"), _e("/d", "h2")]
    plan = plan_deletion([g1[0], g2[1]], [g1, g2])
    assert {e.path for e in plan.deletable} == {"/a", "/d"}
    assert plan.refused_groups == []


# --------------------------------------------------------------------------
# The guard
# --------------------------------------------------------------------------


def test_sad_selecting_every_copy_of_a_group_deletes_nothing_from_it():
    """The whole point: this selection would erase the content
    entirely, so the group is held back rather than partially applied."""
    group = [_e("/a"), _e("/b")]
    plan = plan_deletion(list(group), [group])
    assert plan.deletable == []
    assert plan.refused_groups == ["h1"]


def test_sad_a_fully_selected_group_does_not_block_the_others():
    """One reckless selection must not cost the user the rest of their
    intended cleanup."""
    doomed = [_e("/a", "h1"), _e("/b", "h1")]
    fine = [_e("/c", "h2"), _e("/d", "h2")]
    plan = plan_deletion([*doomed, fine[0]], [doomed, fine])
    assert [e.path for e in plan.deletable] == ["/c"]
    assert plan.refused_groups == ["h1"]


def test_edge_a_lone_file_in_a_group_is_never_deletable():
    """A group of one is not a duplicate; deleting it is just deletion,
    and it does not belong in this window."""
    group = [_e("/only")]
    plan = plan_deletion(group, [group])
    assert plan.deletable == []
    assert plan.refused_groups == ["h1"]


# --------------------------------------------------------------------------
# Edge cases
# --------------------------------------------------------------------------


def test_edge_empty_selection_yields_an_empty_plan():
    group = [_e("/a"), _e("/b")]
    plan = plan_deletion([], [group])
    assert plan.deletable == []
    assert plan.refused_groups == []


def test_edge_selection_of_an_unknown_entry_is_ignored():
    """A row whose group is no longer in the index (refreshed away,
    deleted elsewhere) cannot be reasoned about, so it is not deleted."""
    group = [_e("/a"), _e("/b")]
    plan = plan_deletion([_e("/gone", "other-hash")], [group])
    assert plan.deletable == []


def test_edge_same_path_on_two_backends_counts_as_two_copies():
    """Duplicates across hosts are the common case; identical paths on
    different backends are distinct copies and both are removable as
    long as one survives."""
    group = [_e("/data/x", backend="local"), _e("/data/x", backend="sftp:prod")]
    plan = plan_deletion([group[0]], [group])
    assert [e.backend_id for e in plan.deletable] == ["local"]


def test_edge_plan_reports_how_many_copies_survive():
    group = [_e("/a"), _e("/b"), _e("/c")]
    plan = plan_deletion([group[0]], [group])
    assert plan.survivors == 2
