#!/usr/bin/env python3
"""Undoing a mutating operation from the journal.

``core/operation_journal.py`` has recorded every mutation for a long
time — moves, transfers, trashings, atomic writes — and until now
nothing read it back except the dashboard. Deleting was already
recoverable through the trash; moving four hundred files into the wrong
directory was not.

The hard part is not replaying an inverse. It is being honest about
which operations HAVE one:

* A move records both endpoints. Every move the journal actually
  contains came through the transfer engine, whose only directions are
  UPLOAD, DOWNLOAD and RELAY — all of them BETWEEN backends. Its
  inverse is therefore a transfer back, not a rename; a rename would
  aim the wrong side of the operation at the wrong host.
* A trash records its trash id, and ``core.trash.restore`` already
  refuses to overwrite on the way back.
* A copy records source and destination but NOT whether the
  destination already existed. "Undo" by deleting it would destroy a
  file the copy merely overwrote — so it is reported as
  non-reversible, with the reason, rather than attempted.
* An atomic write replaced content with no backup. Same.

Silently skipping the last two would be the worst outcome: the user
presses undo, nothing says no, and they believe the state was restored.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.undo import UndoPlan, apply_undo, plan_undo, undoable  # noqa: E402


def _event(operation="move", *, status="done", source="/a/x.txt", dest="/b/x.txt",
           backend="Local", details=None, operation_id="op1") -> dict:
    return {
        "operation_id": operation_id,
        "operation": operation,
        "phase": "finish",
        "status": status,
        "source": source,
        "dest": dest,
        "backend": backend,
        "details": details or {},
    }


class _Backend:
    """Records renames and reports which paths exist."""

    def __init__(self, existing=()):
        self.existing = set(existing)
        self.renames: list[tuple[str, str]] = []

    def exists(self, path: str) -> bool:
        return path in self.existing

    def rename(self, src: str, dst: str) -> None:
        if src not in self.existing:
            raise OSError(f"no such file: {src}")
        self.existing.discard(src)
        self.existing.add(dst)
        self.renames.append((src, dst))


# --------------------------------------------------------------------------
# plan_undo — what has an inverse
# --------------------------------------------------------------------------


def test_happy_a_same_backend_move_reverses_by_rename():
    """No direction recorded means it never went through the transfer
    engine, so both endpoints are on the one backend."""
    plan = plan_undo(_event("move"))
    assert plan.reversible is True
    assert plan.action == "move_back"


def test_happy_a_cross_backend_move_reverses_by_transferring_back():
    """UPLOAD / DOWNLOAD / RELAY are all between two backends. Undoing
    one with backend.rename would rename a path that is not even on
    that host."""
    plan = plan_undo(_event("move", details={"direction": "UPLOAD"}))
    assert plan.reversible is True
    assert plan.action == "transfer_back"


def test_happy_a_trash_is_reversible_through_its_id():
    plan = plan_undo(_event("trash", details={"trash_id": "t-42"}))
    assert plan.reversible is True
    assert plan.action == "restore_from_trash"
    assert plan.trash_id == "t-42"


def test_sad_a_copy_is_not_reversible_and_says_why():
    """The journal does not record whether the destination already
    existed, so deleting it could destroy a file the copy overwrote."""
    plan = plan_undo(_event("transfer"))
    assert plan.reversible is False
    assert "overwr" in plan.reason.lower(), plan.reason


def test_sad_an_atomic_write_is_not_reversible_and_says_why():
    plan = plan_undo(_event("atomic_write", dest="/a/conf.yml"))
    assert plan.reversible is False
    assert plan.reason


def test_sad_a_failed_operation_is_not_undone():
    """Nothing happened, or it half happened — replaying an inverse
    against unknown state is how a failed move becomes data loss."""
    plan = plan_undo(_event("move", status="error"))
    assert plan.reversible is False
    assert "did not complete" in plan.reason.lower()


def test_sad_an_unknown_operation_is_refused_not_guessed():
    plan = plan_undo(_event("teleport"))
    assert plan.reversible is False
    assert "teleport" in plan.reason


def test_edge_a_trash_without_an_id_is_not_reversible():
    plan = plan_undo(_event("trash", details={}))
    assert plan.reversible is False


def test_edge_a_move_missing_an_endpoint_is_not_reversible():
    assert plan_undo(_event("move", dest="")).reversible is False
    assert plan_undo(_event("move", source="")).reversible is False


def test_every_plan_carries_a_reason_even_when_reversible():
    """The UI shows this as "Undo: move /b/x.txt back to /a/x.txt" —
    a blank string would make the button unlabelled."""
    for event in (_event("move"), _event("transfer"), _event("teleport")):
        assert plan_undo(event).reason.strip()


# --------------------------------------------------------------------------
# apply_undo — carrying it out
# --------------------------------------------------------------------------


def test_happy_move_back_renames_the_destination_to_the_source():
    backend = _Backend(existing={"/b/x.txt"})
    plan = plan_undo(_event("move"))
    apply_undo(plan, backend)
    assert backend.renames == [("/b/x.txt", "/a/x.txt")]


def test_sad_move_back_refuses_when_the_original_path_is_taken_again():
    """Something new lives there now. Renaming over it would trade one
    lost file for another, which is not what undo means."""
    backend = _Backend(existing={"/b/x.txt", "/a/x.txt"})
    plan = plan_undo(_event("move"))
    with pytest.raises(OSError) as excinfo:
        apply_undo(plan, backend)
    assert "/a/x.txt" in str(excinfo.value)
    assert backend.renames == []


def test_sad_move_back_reports_a_vanished_destination():
    backend = _Backend(existing=set())
    with pytest.raises(OSError):
        apply_undo(plan_undo(_event("move")), backend)


def test_sad_transfer_back_without_the_far_side_refuses():
    """The journal names only the DESTINATION backend, so the caller has
    to supply the other end. Guessing would move data to the wrong
    host."""
    plan = plan_undo(_event("move", details={"direction": "DOWNLOAD"}))
    with pytest.raises(ValueError) as excinfo:
        apply_undo(plan, _Backend())
    assert "backend" in str(excinfo.value).lower()


def test_happy_transfer_back_hands_both_ends_to_the_caller():
    moved: list[tuple] = []
    plan = plan_undo(_event("move", details={"direction": "UPLOAD"}))
    dest_backend, source_backend = _Backend({"/b/x.txt"}), _Backend()

    apply_undo(
        plan,
        dest_backend,
        source_backend=source_backend,
        transfer=lambda **kw: moved.append(kw) or "/a/x.txt",
    )
    assert moved and moved[0]["src_path"] == "/b/x.txt"
    assert moved[0]["dst_path"] == "/a/x.txt"


def test_sad_applying_a_non_reversible_plan_raises():
    """Belt and braces: the UI should never offer it, but the function
    must not quietly do nothing if it is called anyway."""
    backend = _Backend()
    with pytest.raises(ValueError):
        apply_undo(plan_undo(_event("transfer")), backend)


def test_happy_restore_from_trash_calls_the_trash_module():
    calls: list[tuple] = []

    class _Trash:
        @staticmethod
        def restore(backend, trash_id, root=None, target=None):
            calls.append((trash_id, target))
            return "/a/x.txt"

    plan = plan_undo(_event("trash", source="/a/x.txt", details={"trash_id": "t-42"}))
    result = apply_undo(plan, _Backend(), trash_module=_Trash)
    assert calls == [("t-42", "/a/x.txt")]
    assert result == "/a/x.txt"


# --------------------------------------------------------------------------
# undoable — picking candidates out of the journal
# --------------------------------------------------------------------------


def test_happy_undoable_returns_newest_first():
    events = [
        _event("move", operation_id="op1", source="/1", dest="/2"),
        _event("move", operation_id="op2", source="/3", dest="/4"),
    ]
    plans = undoable(events)
    assert [p.operation_id for p in plans] == ["op2", "op1"]


def test_happy_undoable_skips_non_finish_phases():
    """Only the finish event knows whether the operation succeeded."""
    start = _event("move", operation_id="op1")
    start["phase"] = "start"
    assert undoable([start]) == []


def test_edge_undoable_includes_non_reversible_entries_so_the_ui_can_explain():
    plans = undoable([_event("transfer", operation_id="op1")])
    assert len(plans) == 1
    assert plans[0].reversible is False


def test_edge_undoable_on_an_empty_journal():
    assert undoable([]) == []


def test_edge_undoable_tolerates_malformed_rows():
    """The journal is append-only JSONL written by several processes; a
    truncated or foreign row must not take the whole feature down."""
    plans = undoable([{"nonsense": True}, _event("move", operation_id="ok")])
    assert [p.operation_id for p in plans if p.reversible] == ["ok"]


def test_plan_is_immutable():
    plan = plan_undo(_event("move"))
    assert isinstance(plan, UndoPlan)
    with pytest.raises(Exception):
        plan.reversible = False  # type: ignore[misc]


# --------------------------------------------------------------------------
# Choosing what Ctrl+Z acts on
#
# The journal is global — it spans every connection the app has ever
# had, including ones that are closed now. Undo may only offer entries
# it can actually carry out.
# --------------------------------------------------------------------------


def test_happy_pick_returns_the_newest_reversible_entry():
    from core.undo import pick_undoable

    plans = undoable([
        _event("move", operation_id="old", details={}),
        _event("move", operation_id="new", details={}),
    ])
    assert pick_undoable(plans, {"Local"}).operation_id == "new"


def test_edge_pick_skips_non_reversible_entries():
    """A copy on top of the stack must not block undoing the move
    underneath it — it just is not the thing that gets undone."""
    from core.undo import pick_undoable

    plans = undoable([
        _event("move", operation_id="themove"),
        _event("transfer", operation_id="thecopy"),
    ])
    assert pick_undoable(plans, {"Local"}).operation_id == "themove"


def test_sad_pick_skips_entries_on_backends_that_are_not_open():
    """Undoing against a host nobody is connected to would need
    credentials the journal deliberately does not keep."""
    from core.undo import pick_undoable

    plans = undoable([_event("move", backend="SFTP: prod")])
    assert pick_undoable(plans, {"Local"}) is None


def test_edge_pick_on_an_empty_journal_returns_none():
    from core.undo import pick_undoable

    assert pick_undoable([], {"Local"}) is None


def test_edge_pick_matches_the_backend_label_exactly():
    from core.undo import pick_undoable

    plans = undoable([_event("move", backend="SFTP: prod")])
    assert pick_undoable(plans, {"SFTP: prod"}) is not None


def test_sad_pick_returns_nothing_when_no_backend_is_open_at_all():
    """A journal entry can carry an empty backend label. Handing that
    back with nothing open left the caller to pick "any open backend"
    from an empty set — a StopIteration on Ctrl+Z."""
    from core.undo import pick_undoable

    plans = undoable([_event("move", backend="")])
    assert pick_undoable(plans, set()) is None


def test_happy_an_unlabelled_entry_is_offered_when_something_is_open():
    from core.undo import pick_undoable

    plans = undoable([_event("move", backend="")])
    assert pick_undoable(plans, {"Local"}) is not None
