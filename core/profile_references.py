"""What names a connection profile, and a rename that takes it along.

A profile is referred to by its name from

* bookmarks - folder and terminal bookmarks (``profile_name``) and the
  folders a Smart Folder searches (``search["scopes"][i]["profile_name"]``),
  all in bookmarks.json;
* the saved layout - every pane and terminal of session.json
  (``{"type": "pane" | "terminal", "profile": NAME}``) in each workspace and
  in the ``splitter`` an older axross reads.

Renaming a profile (Save with a new name in the Connection dialog) used to
leave all of them on the old name: "The profile 'nas' no longer exists".
:func:`rename_profile_references` rewrites them. A running window keeps
its own copy of the layout; it follows through
``MainWindow._on_profile_renamed``.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path

log = logging.getLogger(__name__)

#: The layout's nesting is checked on restore (ui.main_window); a walk here
#: stops at the same order of depth rather than recursing without end.
_MAX_WALK_NODES = 100_000
#: session.json's list of the renames made (``[old, new]``, oldest first):
#: another axross applies them to the layout it saves (apply_recorded_renames)
#: - its own copy still named the old profile and undid the rename at its quit.
RENAMES_KEY = "profile_renames"
MAX_RECORDED_RENAMES = 32


def recorded_renames(session: dict) -> list[tuple[str, str]]:
    """The renames session.json records, oldest first; damaged ones left out."""
    raw = session.get(RENAMES_KEY) if isinstance(session, dict) else None
    if not isinstance(raw, list):
        return []
    return [(pair[0], pair[1]) for pair in raw[-MAX_RECORDED_RENAMES:]
            if isinstance(pair, list) and len(pair) == 2
            and all(isinstance(name, str) and name for name in pair)]


def apply_recorded_renames(session: dict, workspaces: list, known_profiles) -> int:
    """Rename, in the layout *workspaces* a window is about to save, every
    profile a recorded rename took away - only one *known_profiles* does not
    hold any more (a new profile of the old name keeps its panes). Returns
    how many entries changed."""
    known = set(known_profiles)
    changed = 0
    for old, new in recorded_renames(session):
        if old in known:
            continue
        for entry in workspaces:
            if isinstance(entry, dict):
                changed += rename_in_layout(entry.get("splitter"), old, new)
    return changed


def _rename_in_bookmarks(manager, old: str, new: str) -> int:
    from core.bookmarks import LOCAL_SHELL

    changed = 0
    for mark in manager.all():
        if mark.is_host_terminal:
            continue  # its profile_name is its host address, not a profile
        if mark.is_terminal and old == LOCAL_SHELL:
            # "local" is the local shell of a terminal bookmark: an older
            # profile of that name never owned it.
            continue
        touched = False
        if mark.profile_name == old:
            mark.profile_name = new
            if mark.is_terminal and mark.backend_name == old:
                mark.backend_name = new  # a profile terminal's backend name is the profile
            touched = True
        search = mark.search if isinstance(mark.search, dict) else None
        scopes = (search or {}).get("scopes")
        # A damaged Smart Folder (scopes not a list) loads, and must not stop
        # the rename of every other bookmark.
        for scope in scopes if isinstance(scopes, list) else ():
            if isinstance(scope, dict) and scope.get("profile_name") == old:
                scope["profile_name"] = new
                touched = True
        changed += touched
    if changed:
        manager.save()
    return changed


def rename_in_layout(tree, old: str, new: str) -> int:
    """Rename the profile of every pane and terminal in the layout *tree*
    (a session.json splitter), in place. Returns how many changed."""
    changed = 0
    stack = [tree]
    seen = 0
    while stack and seen < _MAX_WALK_NODES:
        node = stack.pop()
        seen += 1
        if not isinstance(node, dict):
            continue
        if node.get("type") in ("pane", "terminal"):
            if node.get("local"):
                continue  # a local pane or shell names no profile
            if node.get("profile") == old:
                node["profile"] = new
                changed += 1
            continue
        children = node.get("children")
        if isinstance(children, list):
            stack.extend(children)
    return changed


def _rename_in_session(path: Path, old: str, new: str) -> int:
    from core.i18n import MAX_SESSION_BYTES
    from core.json_store import read_for_merge
    from core.secure_storage import locked_store_update

    if not path.exists():
        return 0
    # The file lock of every session.json writer: a running window's save
    # in between is not dropped.
    with locked_store_update(path):
        # Bounded as the window reads it: one over 1 MB is never written again.
        data = read_for_merge(path, max_bytes=MAX_SESSION_BYTES)
        changed = rename_in_layout(data.get("splitter"), old, new)
        workspaces = data.get("workspaces")
        if isinstance(workspaces, list):
            for entry in workspaces:
                if isinstance(entry, dict):
                    changed += rename_in_layout(entry.get("splitter"), old, new)
        # Recorded also when nothing here names it: another running axross
        # may hold panes of it and writes its layout at its quit.
        renames = [list(pair) for pair in recorded_renames(data) if list(pair) != [old, new]]
        data[RENAMES_KEY] = (renames + [[old, new]])[-MAX_RECORDED_RENAMES:]
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(data, indent=2))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    return changed


def rename_profile_references(old: str, new: str, *, bookmarks=None,
                              session_file: Path | str | None = None) -> dict:
    """Make every bookmark, Smart Folder scope and saved pane naming the
    profile *old* name *new*. *bookmarks* is the BookmarkManager to change
    (the running window's; a fresh one by default), *session_file* the
    session.json (core.i18n.SETTINGS_FILE by default). Each store is done
    on its own: a failure in one is logged and leaves the others done.
    Returns ``{"bookmarks": n, "session": n}``."""
    counts = {"bookmarks": 0, "session": 0}
    if not old or not new or old == new:
        return counts
    try:
        if bookmarks is None:
            from core.bookmarks import BookmarkManager

            bookmarks = BookmarkManager()
        counts["bookmarks"] = _rename_in_bookmarks(bookmarks, old, new)
    except Exception as exc:  # noqa: BLE001 - each store on its own: the next still follows
        log.warning("Profile rename: bookmarks not updated: %s", exc)
    try:
        if session_file is None:
            from core import i18n

            session_file = i18n.SETTINGS_FILE
        counts["session"] = _rename_in_session(Path(session_file), old, new)
    except Exception as exc:  # noqa: BLE001 - as above
        log.warning("Profile rename: saved layout not updated: %s", exc)
    if any(counts.values()):
        log.info("Profile %r renamed to %r: %d bookmark(s), %d saved pane(s) follow",
                 old, new, counts["bookmarks"], counts["session"])
    return counts


__all__ = ["rename_in_layout", "rename_profile_references"]
