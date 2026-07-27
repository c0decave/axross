"""Reversing a recorded operation.

:mod:`core.operation_journal` has recorded every mutation since it was
written — moves, transfers, trashings, atomic writes — and nothing read
it back except the dashboard. Deleting was already recoverable through
the trash; moving four hundred files into the wrong directory was not.

Replaying an inverse is the easy half. The half that matters is being
honest about which operations HAVE one:

``move``
    Records both endpoints. Every move the journal actually holds came
    through the transfer engine, whose directions are UPLOAD, DOWNLOAD
    and RELAY — all of them BETWEEN backends, so the inverse is a
    transfer back, not a rename. ``backend.rename`` would aim a path at
    a host it does not live on. A move with no recorded direction never
    touched the transfer engine and is a plain same-backend rename.
``trash``
    Records its trash id, and :func:`core.trash.restore` already refuses
    to overwrite on the way back.
``transfer`` (copy)
    Records source and destination but NOT whether the destination
    already existed. Deleting it would destroy a file the copy merely
    overwrote, so this is reported as non-reversible with the reason
    rather than attempted.
``atomic_write``
    Replaced content with no backup. Same.

Quietly skipping the last two would be the worst outcome: the user
presses undo, nothing objects, and they believe the state was restored.
So every plan carries a reason, reversible or not, and applying a
non-reversible one raises instead of doing nothing.

Note on paths: journal events pass through :func:`core.redaction.redact`,
which strips credentials from URL-style destinations but leaves the path
component intact. Undo therefore acts through a live backend object
supplied by the caller and never tries to reconstruct a connection from
the journal.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

log = logging.getLogger(__name__)

#: Journal statuses that mean the operation actually completed.
_SUCCESS = frozenset({"done", "ok", "success", "completed"})


@dataclass(frozen=True)
class UndoPlan:
    """What undoing one journal entry would involve."""

    operation_id: str
    operation: str
    reversible: bool
    #: ``"move_back"``, ``"restore_from_trash"`` or ``""``.
    action: str
    #: Always populated — the UI labels the button with it, and when
    #: ``reversible`` is False it is the explanation the user gets.
    reason: str
    source: str = ""
    dest: str = ""
    backend: str = ""
    trash_id: str = ""
    #: Transfer direction recorded for a cross-backend move, if any.
    direction: str = ""


def _refuse(event: dict, reason: str) -> UndoPlan:
    return UndoPlan(
        operation_id=str(event.get("operation_id", "")),
        operation=str(event.get("operation", "")),
        reversible=False,
        action="",
        reason=reason,
        source=str(event.get("source", "")),
        dest=str(event.get("dest", "")),
        backend=str(event.get("backend", "")),
    )


def plan_undo(event: dict) -> UndoPlan:
    """Decide whether one journal event can be reversed, and how."""
    operation = str(event.get("operation", ""))
    status = str(event.get("status", ""))
    source = str(event.get("source", ""))
    dest = str(event.get("dest", ""))
    details = event.get("details") or {}

    if status not in _SUCCESS:
        return _refuse(
            event,
            f"the operation did not complete (status {status or 'unknown'!s}) — "
            "reversing it against unknown state could lose data",
        )

    if operation == "move":
        if not source or not dest:
            return _refuse(event, "the journal entry is missing one of the two paths")
        direction = str(details.get("direction", ""))
        if direction:
            # UPLOAD / DOWNLOAD / RELAY are all cross-backend.
            return UndoPlan(
                operation_id=str(event.get("operation_id", "")),
                operation=operation,
                reversible=True,
                action="transfer_back",
                reason=f"transfer {dest} back to {source}",
                source=source,
                dest=dest,
                backend=str(event.get("backend", "")),
                direction=direction,
            )
        return UndoPlan(
            operation_id=str(event.get("operation_id", "")),
            operation=operation,
            reversible=True,
            action="move_back",
            reason=f"move {dest} back to {source}",
            source=source,
            dest=dest,
            backend=str(event.get("backend", "")),
        )

    if operation == "trash":
        trash_id = str(details.get("trash_id", ""))
        if not trash_id:
            return _refuse(event, "the journal entry carries no trash id to restore from")
        return UndoPlan(
            operation_id=str(event.get("operation_id", "")),
            operation=operation,
            reversible=True,
            action="restore_from_trash",
            reason=f"restore {source or 'the entry'} from the trash",
            source=source,
            dest=dest,
            backend=str(event.get("backend", "")),
            trash_id=trash_id,
        )

    if operation == "transfer":
        return _refuse(
            event,
            "a copy cannot be undone automatically: the journal does not record "
            "whether the destination already existed, so removing it could "
            "destroy a file the copy overwrote",
        )

    if operation == "atomic_write":
        return _refuse(
            event,
            "the previous contents were replaced and no backup was kept",
        )

    return _refuse(event, f"no inverse is defined for {operation!r}")


def apply_undo(
    plan: UndoPlan,
    backend,
    *,
    source_backend=None,
    transfer=None,
    trash_module=None,
) -> str:
    """Carry out ``plan``. Returns where the entry now lives.

    ``backend`` is the one holding the CURRENT location (the operation's
    destination). A cross-backend move additionally needs
    ``source_backend`` — the journal names only the destination host, so
    the far side has to come from the caller; guessing it would push
    data to the wrong machine.

    Raises :class:`ValueError` for a plan that is not reversible, or for
    one whose prerequisites are missing — the UI should never offer
    either, but a caller that ignores that must get an error rather
    than a silent no-op. Raises :class:`OSError` when the filesystem
    refuses.
    """
    if not plan.reversible:
        raise ValueError(f"not reversible: {plan.reason}")

    if plan.action == "move_back":
        # Refuse if something new occupies the original path. Renaming
        # over it would trade one lost file for another, which is not
        # what undo means.
        if getattr(backend, "exists", None) and backend.exists(plan.source):
            raise OSError(
                f"{plan.source} exists again — undo would overwrite it. "
                "Move or rename it first."
            )
        backend.rename(plan.dest, plan.source)
        log.info("undo: moved %s back to %s", plan.dest, plan.source)
        return plan.source

    if plan.action == "transfer_back":
        if source_backend is None or transfer is None:
            raise ValueError(
                "undoing a cross-backend move needs the source backend and a "
                "transfer callable; the journal records only the destination host"
            )
        result = transfer(
            src_backend=backend,
            src_path=plan.dest,
            dst_backend=source_backend,
            dst_path=plan.source,
        )
        log.info("undo: transferring %s back to %s", plan.dest, plan.source)
        return result or plan.source

    if plan.action == "restore_from_trash":
        if trash_module is None:
            from core import trash as trash_module  # type: ignore[no-redef]
        # Restoring to the recorded original path; core.trash.restore
        # refuses to overwrite an occupied destination itself.
        result = trash_module.restore(backend, plan.trash_id, target=plan.source or None)
        log.info("undo: restored %s from trash", result)
        return result

    raise ValueError(f"unknown undo action: {plan.action!r}")


def undoable(events: list[dict]) -> list[UndoPlan]:
    """Plans for every finished operation in ``events``, newest first.

    Non-reversible entries are included on purpose: the window that
    lists recent operations should be able to say why something cannot
    be undone, which is more useful than omitting it and leaving the
    user to wonder where it went.
    """
    plans: list[UndoPlan] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        # Only the finish event knows whether the operation succeeded.
        if event.get("phase") != "finish":
            continue
        try:
            plans.append(plan_undo(event))
        except Exception as exc:  # noqa: BLE001 — a bad row must not kill the list
            log.debug("undo: skipping malformed journal row: %s", exc)
    plans.reverse()
    return plans


def pick_undoable(plans: list[UndoPlan], available_backends) -> UndoPlan | None:
    """The newest plan that can actually be carried out right now.

    The journal is global: it spans every connection the app has ever
    had, including ones that are closed. Offering an undo against a host
    nobody is connected to would need credentials the journal
    deliberately does not keep, so entries whose backend label is not
    currently open are skipped rather than failing at the last moment.

    Non-reversible entries are skipped too — a copy sitting on top of
    the stack should not block undoing the move underneath it.
    """
    labels = set(available_backends)
    if not labels:
        # Nothing is open, so nothing can be carried out. Returning a
        # plan anyway left the caller to pick "any open backend" out of
        # an empty set, which is a StopIteration on Ctrl+Z.
        return None
    for plan in plans:  # already newest-first
        if not plan.reversible:
            continue
        if plan.backend and plan.backend not in labels:
            continue
        return plan
    return None


__all__ = ["UndoPlan", "apply_undo", "pick_undoable", "plan_undo", "undoable"]
