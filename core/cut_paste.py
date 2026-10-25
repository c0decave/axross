"""What a Paste of cut entries may do, decided before anything is queued.

Cut (Ctrl+X in a file pane) only remembers entries; Paste moves them into
the folder of the pane it is pressed in, through the transfer queue's move
(``core.transfer_manager`` / ``core.transfer_worker``), which removes a
source only after its own copy completed and was checked.

:func:`plan_paste` sorts the cut entries before that move is requested:

* an entry whose destination would be the entry itself (pasted into the
  folder it came from) is *already here*: nothing is moved, nothing is
  removed - moving a file onto itself and then deleting "the source"
  would delete the only copy;
* a folder pasted into itself or a folder below it refuses the whole
  paste: the copy would list itself while it is being made;
* every other entry is moved.

The transfer manager refuses both cases again per job
(``_self_target_refusal``); this check keeps them from ever reaching the
queue or the conflict prompt. No Qt here.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from core.path_policy import safe_join
from core.storage_identity import is_within, same_entry


@dataclass(frozen=True)
class PastePlan:
    """The outcome of :func:`plan_paste`.

    *paths* are moved, *already_here* are left alone (they already are in
    the destination folder), and a non-empty *refusal* says why nothing may
    be pasted at all."""

    paths: tuple[str, ...] = ()
    already_here: tuple[str, ...] = ()
    refusal: str = ""


def _leaf(backend, path: str) -> str:
    try:
        sep = backend.separator() or "/"
    except Exception:  # noqa: BLE001 - a backend without separator() is POSIX-like
        sep = "/"
    trimmed = path.rstrip(sep) or path
    return trimmed.rsplit(sep, 1)[-1]


def plan_paste(source_backend, paths: Iterable[str], dest_backend, dest_dir: str) -> PastePlan:
    """Sort the cut *paths* of *source_backend* for a paste into *dest_dir*
    of *dest_backend* (see the module docstring)."""
    move: list[str] = []
    here: list[str] = []
    for path in paths:
        if is_within(source_backend, path, dest_backend, dest_dir):
            return PastePlan(
                refusal=f"cannot move the folder {path} into itself ({dest_dir})"
            )
        try:
            dest_path = safe_join(dest_backend, dest_dir, _leaf(source_backend, path))
        except ValueError:
            # A name the destination cannot hold: the transfer refuses it with
            # an error of its own, which is shown in the transfer queue.
            move.append(path)
            continue
        if same_entry(source_backend, path, dest_backend, dest_path):
            here.append(path)
        else:
            move.append(path)
    return PastePlan(paths=tuple(move), already_here=tuple(here))
