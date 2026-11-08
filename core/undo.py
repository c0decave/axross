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
``metadata_remove``
    One entry per removal run (a whole folder is one entry, so one undo
    restores all of it). Each item replaced in place names the trash copy
    of its original and the SHA-256 of what was written; undo puts the
    original back only while the file still has that content
    (:func:`core.trash.restore_over`). An item written as a cleaned copy
    is undone by moving that copy to the trash, again only if unchanged.
``undo``
    Written by :func:`record_undone` after an undo succeeded, so the same
    entry is not offered again; not itself reversible.
``move_folder``
    A folder a move created at its destination (the move removes the
    source folder once it is empty). Undone with its move: removed again
    when it is empty, and the source folder made again.

Batches: the entries of one user operation - one F5 / F6 / drop / Paste
(``core.transfer_manager.transfer_files``), one Move to Trash of a
selection - carry one ``details["batch"]`` id, and :func:`undoable` offers
them as ONE plan (action ``"batch"``, the entries in ``parts``): a folder
move is undone with one question, files and folders together. Entries
written before the batch id existed are offered one by one, as before.

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
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace

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
    #: The trash folder *trash_id* is in when it is not the backend's
    #: default one (trash(root=...)); "" for the default.
    trash_root: str = ""
    #: Transfer direction recorded for a cross-backend move, if any.
    direction: str = ""
    #: Label of the connection a transfer-engine move took the data FROM.
    #: Empty for journals written before it was recorded; such a move
    #: cannot be sent back, because the source host is unknown.
    source_backend: str = ""
    #: ``metadata_remove``: one :class:`MetadataUndoItem` per file.
    items: tuple = ()
    #: The user operation the entry was part of ("" before batches).
    batch: str = ""
    #: ``"batch"``: the plans of its entries, newest first.
    parts: tuple = ()


@dataclass(frozen=True)
class MetadataUndoItem:
    """One file of a metadata removal, as the journal recorded it."""

    path: str
    #: ``"in_place"`` (``trash_id`` holds the original) or ``"copy"``
    #: (``output`` is the cleaned copy written next to the original).
    mode: str
    sha256: str
    trash_id: str = ""
    output: str = ""


def _metadata_items(details: dict) -> tuple:
    raw = details.get("items")
    if not isinstance(raw, list):
        return ()
    items = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        path, sha = entry.get("path"), entry.get("sha256")
        mode = entry.get("mode") or details.get("mode") or "in_place"
        if not isinstance(path, str) or not path or not isinstance(sha, str) or not sha:
            continue
        if mode == "copy":
            output = entry.get("output")
            if isinstance(output, str) and output:
                items.append(MetadataUndoItem(path, "copy", sha, output=output))
        elif mode == "in_place":
            trash_id = entry.get("trash_id")
            if isinstance(trash_id, str) and trash_id:
                items.append(MetadataUndoItem(path, "in_place", sha, trash_id=trash_id))
    return tuple(items)


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
                source_backend=str(details.get("source_backend", "")),
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
            trash_root=str(details.get("trash_root") or ""),
        )

    if operation == "metadata_remove":
        items = _metadata_items(details if isinstance(details, dict) else {})
        if not items:
            return _refuse(event, "the journal entry names no file whose original was kept")
        if len(items) == 1:
            what = items[0].path
            reason = (
                f"put back {what} with its metadata"
                if items[0].mode == "in_place"
                else f"move the cleaned copy {items[0].output} to the trash"
            )
        else:
            reason = f"put back the originals of {len(items)} files whose metadata was removed"
        return UndoPlan(
            operation_id=str(event.get("operation_id", "")),
            operation=operation,
            reversible=True,
            action="restore_metadata",
            reason=reason,
            source=source,
            dest=dest,
            backend=str(event.get("backend", "")),
            items=items,
        )

    if operation == "move_folder":
        if not source or not dest:
            return _refuse(event, "the journal entry is missing one of the two paths")
        return UndoPlan(
            operation_id=str(event.get("operation_id", "")),
            operation=operation,
            reversible=True,
            action="folder_back",
            reason=f"remove the folder {dest} the move created and make {source} again",
            source=source,
            dest=dest,
            backend=str(event.get("backend", "")),
            direction=str(details.get("direction", "")),
            source_backend=str(details.get("source_backend", "")),
        )

    if operation == "undo":
        return _refuse(event, "an undo is not itself undoable")

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
        _recreate_parent(source_backend, plan.source)
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
        result = trash_module.restore(backend, plan.trash_id, root=plan.trash_root or None,
                                      target=plan.source or None)
        log.info("undo: restored %s from trash", result)
        return result

    if plan.action == "restore_metadata":
        if trash_module is None:
            from core import trash as trash_module  # type: ignore[no-redef]
        return _restore_metadata(plan, backend, trash_module)

    if plan.action == "folder_back":
        _folders_back((plan,), backend, source_backend or backend)
        return plan.source

    if plan.action == "batch":
        if batch_transfer_pairs(plan):
            raise ValueError(
                "a batch that moves data between connections is carried out by "
                "the transfer engine (batch_transfer_pairs), then apply_batch_folders"
            )
        _done, failures = apply_batch_files(plan, backend, trash_module=trash_module)
        if not failures:  # a folder still holding a file that failed stays
            failures = apply_batch_folders(plan, backend, source_backend or backend)
        if failures:
            shown = "\n".join(failures[:10])
            more = f"\n… and {len(failures) - 10} more" if len(failures) > 10 else ""
            raise OSError(f"{plan.reason}: {len(failures)} of {len(plan.parts)} entries were "
                          "not undone:\n"
                          f"{shown}{more}")
        return plan.source

    raise ValueError(f"unknown undo action: {plan.action!r}")


#: The part actions a batch carries out itself, one after the other.
_FILE_ACTIONS = ("move_back", "restore_from_trash", "restore_metadata")


def batch_transfer_pairs(plan: UndoPlan) -> list[tuple[str, str]]:
    """``(current path, original path)`` of every part of a batch that goes
    back through the transfer engine (a move between or within connections),
    oldest first - the order the move ran in."""
    return [(p.dest, p.source) for p in reversed(plan.parts) if p.action == "transfer_back"]


def apply_batch_files(plan: UndoPlan, backend, *,
                      trash_module=None) -> tuple[list[UndoPlan], list[str]]:
    """Carry out the renames and trash restores of a batch on *backend*;
    every part is tried. Returns the parts carried out and the failures
    ("path: reason")."""
    done: list[UndoPlan] = []
    failures: list[str] = []
    for part in reversed(plan.parts):
        if part.action not in _FILE_ACTIONS:
            continue
        try:
            apply_undo(part, backend, trash_module=trash_module)
            done.append(part)
        except (OSError, ValueError) as exc:
            failures.append(f"{part.source or part.dest}: {exc}")
    return done, failures


def apply_batch_folders(plan: UndoPlan, backend, source_backend) -> list[str]:
    """The folder parts of a batch, after its files are back: each folder
    the move created is removed when it is empty (deepest first) and the
    source folder it came from is made again. A folder that holds
    something now is left; the failures are returned."""
    folders = [p for p in plan.parts if p.action == "folder_back"]
    return _folders_back(folders, backend, source_backend, collect=True)


def _depth(path: str) -> int:
    bare = path.rstrip("/\\")
    return bare.count("/") + bare.count("\\")


def _folders_back(folders, backend, source_backend, collect: bool = False) -> list[str]:
    failures: list[str] = []
    for part in sorted(folders, key=lambda p: _depth(p.dest), reverse=True):
        try:
            if backend.exists(part.dest) and not backend.list_dir(part.dest):
                backend.remove(part.dest)
                log.info("undo: removed the folder %s the move created", part.dest)
        except OSError as exc:
            if not collect:
                raise
            failures.append(f"{part.dest}: {exc}")
    for part in sorted(folders, key=lambda p: _depth(p.source)):
        try:
            if not source_backend.exists(part.source):
                _recreate_parent(source_backend, part.source)
                source_backend.mkdir(part.source)
                log.info("undo: made the folder %s again", part.source)
        except OSError as exc:
            if not collect:
                raise
            failures.append(f"{part.source}: {exc}")
    return failures


def _recreate_parent(backend, path: str) -> None:
    """Make the folder *path* belongs in, with any missing above it.

    A folder move removes every source folder it emptied, and its journal
    holds one entry per FILE. The way back for each file therefore leads
    into a folder that is gone, and the transfer engine creates folders
    only for a folder it copies, not for a single file. Raises OSError
    when something that is not a folder holds the place
    (:func:`core.trash.recreate_parent_folders`).
    """
    from core.trash import recreate_parent_folders

    recreate_parent_folders(backend, path)


def _restore_metadata(plan: UndoPlan, backend, trash_module) -> str:
    """Every item of a metadata removal back; failures are collected and
    raised together after the rest was done, so one edited file does not
    keep the others from coming back."""
    done = 0
    failures: list[str] = []
    for item in plan.items:
        try:
            if item.mode == "in_place":
                trash_module.restore_over(
                    backend, item.trash_id, target=item.path, expected_sha256=item.sha256
                )
            else:
                from core.trash import _sha256_of

                if backend.exists(item.output):
                    if _sha256_of(backend, item.output) != item.sha256:
                        raise OSError(
                            f"{item.output} was changed after it was written; left in place"
                        )
                    trash_module.trash(backend, item.output, journal=False)
            done += 1
        except (OSError, ValueError) as exc:
            failures.append(f"{item.path}: {exc}")
    log.info("undo: metadata removal reversed for %d of %d files", done, len(plan.items))
    if failures:
        shown = "\n".join(failures[:10])
        more = f"\n… and {len(failures) - 10} more" if len(failures) > 10 else ""
        raise OSError(f"restored {done} of {len(plan.items)} files:\n{shown}{more}")
    return plan.source or (plan.items[0].path if plan.items else "")


def record_undone(plan: UndoPlan, *, by: Iterable[str] = (), by_batches: Iterable[str] = ()) -> None:
    """Journal that *plan* was carried out, so :func:`undoable` stops
    offering it - a second Ctrl+Z then reaches the operation before it
    instead of failing on the one already reversed.

    *by* names the journal operations the undo itself ran (the transfer
    engine journals a move back as a new "move"). They are dropped from
    the history too: offered as the newest entry, the next Ctrl+Z would
    redo what was just undone, and the one after that undo it again.
    *by_batches* names their batches (a walk back journals the folders it
    makes in them too). A batch plan records its parts as well.
    """
    from core.operation_journal import finish_operation, new_operation_id

    details: dict = {"undone": plan.operation_id, "reversed": plan.operation}
    reverse = [op for op in by if isinstance(op, str) and op]
    if reverse:
        details["by"] = reverse
    batches = sorted({b for b in by_batches if isinstance(b, str) and b})
    if batches:
        details["by_batches"] = batches
    if plan.parts:
        details["parts"] = [p.operation_id for p in plan.parts]
    finish_operation(
        new_operation_id(),
        "undo",
        status="done",
        source=plan.source,
        dest=plan.dest,
        backend=plan.backend,
        details=details,
    )


def _with_start_fields(event: dict, starts: dict[str, dict]) -> dict:
    """``event`` with the backend label and details its start event recorded.

    Transfer-engine moves journaled before their finish events carried
    these had them on the START event only. Without the direction such a
    move plans as a same-backend rename, and without the label it would
    run against whichever backend is open. Fields the finish event has
    itself win.
    """
    start = starts.get(str(event.get("operation_id", "")))
    if start is None:
        return event
    merged = dict(event)
    if not merged.get("backend") and start.get("backend"):
        merged["backend"] = start["backend"]
    start_details = start.get("details")
    if isinstance(start_details, dict) and start_details:
        own = event.get("details")
        merged["details"] = {**start_details, **(own if isinstance(own, dict) else {})}
    return merged


def undoable(events: list[dict]) -> list[UndoPlan]:
    """Plans for every finished operation in ``events``, newest first.

    Non-reversible entries are included on purpose: the window that
    lists recent operations should be able to say why something cannot
    be undone, which is more useful than omitting it and leaving the
    user to wonder where it went.
    """
    plans: list[UndoPlan] = []
    starts: dict[str, dict] = {}
    undone: set[str] = set()
    undone_batches: set[str] = set()
    for event in events:
        if not isinstance(event, dict):
            continue
        if event.get("phase") == "start" and event.get("operation_id"):
            starts[str(event["operation_id"])] = event
            continue
        # Only the finish event knows whether the operation succeeded.
        if event.get("phase") != "finish":
            continue
        details = event.get("details")
        if event.get("operation") == "undo" and isinstance(details, dict):
            target = details.get("undone")
            if isinstance(target, str) and target:
                undone.add(target)
            for key, into in (("by", undone), ("parts", undone),
                              ("by_batches", undone_batches)):
                listed = details.get(key)
                if isinstance(listed, list):
                    into.update(op for op in listed if isinstance(op, str) and op)
        try:
            merged = _with_start_fields(event, starts)
            plan = plan_undo(merged)
            batch = (merged.get("details") or {}).get("batch")
            if isinstance(batch, str) and batch:
                plan = replace(plan, batch=batch)
            plans.append(plan)
        except Exception as exc:  # noqa: BLE001 — a bad row must not kill the list
            log.debug("undo: skipping malformed journal row: %s", exc)
    plans = [p for p in plans
             if p.operation_id not in undone and p.batch not in undone_batches]
    plans = [p for p in plans if not p.batch or p.batch not in undone]
    plans.reverse()
    return _group_batches(plans)


def _group_batches(plans: list[UndoPlan]) -> list[UndoPlan]:
    """One plan per batch, at the place of its newest entry (newest first
    in, newest first out). A batch of one file entry stays that entry."""
    groups: dict[str, list[UndoPlan]] = {}
    order: list = []
    for plan in plans:
        key = plan.batch or (plan.operation_id if plan.action == "folder_back" else "")
        if not key:
            order.append(plan)
            continue
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(plan)
    out: list[UndoPlan] = []
    for entry in order:
        if isinstance(entry, UndoPlan):
            out.append(entry)
            continue
        parts = groups[entry]
        usable = [p for p in parts if p.reversible]
        if len(usable) == 1 and usable[0].action != "folder_back":
            # One file of it to put back (the trash's sidecar write, a
            # skipped name beside it): offered as that entry, as before.
            out.append(usable[0])
        elif len(parts) == 1 and parts[0].action != "folder_back":
            out.append(parts[0])
        else:
            out.append(_batch_plan(entry, parts))
    return out


def _batch_plan(batch: str, parts: list[UndoPlan]) -> UndoPlan:
    """The plan of a batch's entries (*parts*, newest first).

    Entries that did not complete (a file the move failed on, a name the
    conflict answers skipped) stayed where they were: the batch reverses
    the rest. A batch of nothing reversible (a copy) is refused with the
    reason of its newest entry."""
    from core.i18n import tr, tr_n

    usable = tuple(p for p in parts if p.reversible)
    files = [p for p in usable if p.action != "folder_back"]
    folders = [p for p in usable if p.action == "folder_back"]
    lead = files[0] if files else (folders[0] if folders else parts[0])
    if not usable:
        return replace(parts[0], operation_id=batch, batch=batch, parts=tuple(parts))
    backends = {p.backend for p in usable}
    if len(backends) > 1:
        return replace(_refuse({"operation_id": batch, "operation": lead.operation},
                               "the entries of this operation are on more than one connection"),
                       batch=batch, parts=usable)
    sources = {p.source_backend for p in usable if p.action in ("transfer_back", "folder_back")}
    operation = lead.operation if lead.operation != "move_folder" else "move"
    roots = _roots(usable)
    if operation == "trash":
        reason = tr_n(len(files), "restore {n} item from the trash",
                      "restore {n} items from the trash")
    else:
        what = tr_n(len(files), "{n} file", "{n} files")
        if folders:
            what += ", " + tr_n(len(folders), "{n} folder", "{n} folders")
        if len(roots) == 1:
            reason = tr("move {dest} back to {source} ({what})").format(
                dest=roots[0].dest, source=roots[0].source, what=what)
        else:
            reason = tr("move {count} entries back ({what})").format(
                count=len(roots), what=what)
    shown = "\n".join(f"  {p.source}" for p in roots[:5])
    if len(roots) > 5:
        shown += "\n  " + tr_n(len(roots) - 5, "… and {n} more", "… and {n} more")
    if len(roots) > 1 or operation == "trash":
        reason += "\n" + shown
    return UndoPlan(
        operation_id=batch,
        operation=operation,
        reversible=True,
        action="batch",
        reason=reason,
        source=roots[0].source if len(roots) == 1 else "",
        dest=roots[0].dest if len(roots) == 1 else "",
        backend=lead.backend,
        direction=lead.direction,
        source_backend=next(iter(sources)) if len(sources) == 1 else lead.source_backend,
        batch=batch,
        parts=usable,
    )


def _roots(parts) -> list[UndoPlan]:
    """The entries of a batch the user picked: those not inside a folder
    the batch moved too (by their original path)."""
    folders = {p.source.rstrip("/\\") for p in parts if p.action == "folder_back"}

    def inside(path: str) -> bool:
        bare = path.rstrip("/\\")
        for sep in ("/", "\\"):
            head = bare.rsplit(sep, 1)[0] if sep in bare else ""
            while head:
                if head in folders:
                    return True
                head = head.rsplit(sep, 1)[0] if sep in head else ""
        return False

    roots = [p for p in reversed(parts) if not inside(p.source)]
    return roots or list(reversed(parts))


def gone_reason(plan: UndoPlan, backend) -> str:
    """Why *plan* can no longer be carried out on *backend* because what
    it would put back is gone, or "" (also when the backend cannot tell:
    then apply_undo reports the real error).

    A trash entry disappears without a journal entry - restored or
    deleted in the Trash window, the trash emptied, another tool - and an
    undo that keeps offering it would hide every older operation.
    """
    if plan.action == "batch":
        trashed = [p for p in plan.parts if p.action == "restore_from_trash"]
        if trashed and len(trashed) == len(plan.parts) and all(
                gone_reason(p, backend) for p in trashed):
            return "their trash entries are gone (restored or deleted from the trash since)"
        return ""
    if plan.action != "restore_from_trash" or not plan.trash_id:
        return ""
    from core import trash as trash_module

    try:
        if trash_module.entry_exists(backend, plan.trash_id, root=plan.trash_root or None):
            return ""
    except OSError as exc:
        log.debug("undo: cannot check trash entry %s: %s", plan.trash_id, exc)
        return ""
    return "its trash entry is gone (restored or deleted from the trash since)"


def pick_undoable(
    plans: list[UndoPlan],
    available_backends,
    gone: Callable[[UndoPlan], bool] | None = None,
) -> UndoPlan | None:
    """The newest plan that can actually be carried out right now.

    The journal is global: it spans every connection the app has ever
    had, including ones that are closed. Offering an undo against a host
    nobody is connected to would need credentials the journal
    deliberately does not keep, so entries whose backend label is not
    currently open are skipped rather than failing at the last moment.

    Non-reversible entries are skipped too — a copy sitting on top of
    the stack should not block undoing the move underneath it — and so
    is a plan *gone* says can no longer be carried out (see
    :func:`gone_reason`).
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
        if gone is not None and gone(plan):
            continue
        return plan
    return None


__all__ = [
    "MetadataUndoItem",
    "UndoPlan",
    "apply_batch_files",
    "apply_batch_folders",
    "apply_undo",
    "batch_transfer_pairs",
    "gone_reason",
    "pick_undoable",
    "plan_undo",
    "record_undone",
    "undoable",
]
