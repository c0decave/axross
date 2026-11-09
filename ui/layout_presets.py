"""Pane-layout presets and a cycle helper.

The user can hotkey through a small set of pre-baked dock layouts
("two file panes side-by-side", "file pane left + two stacked
terminals right", etc.) without manually splitting / closing every
time. Presets are described as a nested tuple grammar::

    ("hsplit", [child, child, …])     # horizontal QSplitter
    ("vsplit", [child, child, …])     # vertical QSplitter
    ("file",   None)                   # one FilePaneWidget on LocalFS
    ("term",   "local")                # one TerminalPaneWidget; arg is
                                       #  "local" or a saved profile name

The :func:`apply_preset` entry point rebuilds the MainWindow's
central splitter from the preset, closing every previously-open
pane first.
"""

from __future__ import annotations

import logging
from typing import Any

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QSplitter, QWidget

log = logging.getLogger(__name__)


# --- Built-in presets -------------------------------------------------------

PRESETS: dict[str, tuple] = {
    "single": ("file", None),
    "dual": (
        "hsplit",
        [("file", None), ("file", None)],
    ),
    "quad-files": (
        "hsplit",
        [
            ("vsplit", [("file", None), ("file", None)]),
            ("vsplit", [("file", None), ("file", None)]),
        ],
    ),
    "commander": (
        "hsplit",
        [("file", None), ("file", None)],
    ),
    "dev-shells": (
        "hsplit",
        [
            ("file", None),
            ("vsplit", [("term", "local"), ("term", "local")]),
        ],
    ),
    "triage": (
        "vsplit",
        [
            ("hsplit", [("file", None), ("file", None)]),
            ("term", "local"),
        ],
    ),
    "shells-quad": (
        "hsplit",
        [
            ("vsplit", [("term", "local"), ("term", "local")]),
            ("vsplit", [("term", "local"), ("term", "local")]),
        ],
    ),
}

# Order in which Ctrl+Alt+L cycles. New presets get appended here so
# muscle memory stays stable across updates.
PRESET_ORDER: list[str] = [
    "single",
    "dual",
    "quad-files",
    "commander",
    "dev-shells",
    "triage",
    "shells-quad",
]

#: The name a menu shows for each preset; the ids above stay the keys of
#: the saved state and the cycle order.
PRESET_LABELS: dict[str, str] = {
    "single": "One File Pane",
    "dual": "Two File Panes",
    "quad-files": "Four File Panes",
    "commander": "Commander (Two File Panes)",
    "dev-shells": "File Pane and Two Shells",
    "triage": "Two File Panes over a Shell",
    "shells-quad": "Four Shells",
}


def preset_label(name: str) -> str:
    """The translated, human name of the preset *name* (the id if unknown)."""
    from core.i18n import tr

    label = PRESET_LABELS.get(name)
    return tr(label) if label else name


# --- Builder ----------------------------------------------------------------


def _build(spec: Any, owner, made: list | None = None) -> QWidget:
    """Recursively materialise ``spec`` into a Qt widget tree.

    ``owner`` is the MainWindow — we call its existing factory
    methods (``_make_file_pane``, ``_make_local_terminal``) so panes
    behave exactly as if the user had created them manually (active-
    pane plumbing, drop targets, etc.). The file panes made are appended
    to *made*, in layout order.
    """
    kind, payload = spec
    if kind in ("hsplit", "vsplit"):
        orientation = Qt.Orientation.Horizontal if kind == "hsplit" else Qt.Orientation.Vertical
        splitter = QSplitter(orientation)
        for child_spec in payload:
            child = _build(child_spec, owner, made)
            splitter.addWidget(child)
        return splitter
    if kind == "file":
        pane = owner._preset_make_file_pane()
        if made is not None:
            made.append(pane)
        return pane
    if kind == "term":
        # payload may be "local" or a saved-profile name.
        return owner._preset_make_terminal_pane(payload or "local")
    raise ValueError(f"Unknown preset node kind: {kind!r}")


def apply_preset(owner, name: str) -> None:
    """Replace the MainWindow's central widget with the preset
    ``name``. Panes from the previous layout are torn down first so
    we don't leak FileBackend sessions / SSH transports."""
    if name not in PRESETS:
        raise KeyError(f"unknown layout preset: {name!r}")
    log.info("Applying layout preset: %s", name)
    carried = _carried_paths(owner)
    owner._preset_tear_down_existing()
    made: list = []
    root = _build(PRESETS[name], owner, made)
    if not isinstance(root, QSplitter):
        # "single" is a bare pane; the window always keeps a root SPLITTER
        # that new panes (connects, Extract Pane) are added to.
        wrapper = QSplitter(Qt.Orientation.Horizontal)
        wrapper.addWidget(root)
        root = wrapper
    # setCentralWidget deletes the previous central widget - the splitter
    # owner._root_splitter pointed at. Without moving the reference every
    # later connect, Extract Pane and the session save on close touched a
    # deleted object ("wrapped C/C++ object of type QSplitter has been
    # deleted").
    install = getattr(owner, "_install_root_splitter", None)
    if install is not None:
        # A window with workspaces: the new root replaces the current
        # workspace's, the others keep theirs.
        install(root)
    else:
        owner._root_splitter = root
        owner.setCentralWidget(root)
    # Track which preset we're on so the cycle helper can rotate.
    owner._current_preset_name = name
    owner._refresh_after_preset()
    # The folders the user was in stay open: the first file pane of the new
    # layout shows the active pane's, the second the target pane's - not
    # every pane the home folder.
    for pane, path in zip(made, carried):
        if path and getattr(pane, "current_path", None) != path:
            try:
                pane.navigate(path)
            except Exception as exc:  # noqa: BLE001 - the pane stays at home
                log.debug("layout preset: cannot open %s: %s", path, exc)


def _carried_paths(owner) -> list:
    """The local folders of the active and the target file pane (None for
    a pane that is missing, remote or not on a folder), read before the
    switch tears them down."""
    import os

    from core.local_fs import LocalFS

    out: list = []
    for attr in ("_active_pane", "_target_pane"):
        pane = getattr(owner, attr, None)
        path = None
        try:
            if pane is not None and type(getattr(pane, "backend", None)) is LocalFS:
                current = pane.current_path
                if isinstance(current, str) and current and os.path.isdir(current):
                    path = current
        except RuntimeError:  # its widget is gone already
            path = None
        out.append(path)
    return out


def cycle_preset(owner, *, forward: bool = True) -> str:
    """Rotate to the next preset in ``PRESET_ORDER``. Returns the
    new preset's name so the caller can update a status-bar hint."""
    current = getattr(owner, "_current_preset_name", PRESET_ORDER[0])
    try:
        idx = PRESET_ORDER.index(current)
    except ValueError:
        idx = -1
    step = 1 if forward else -1
    next_idx = (idx + step) % len(PRESET_ORDER)
    name = PRESET_ORDER[next_idx]
    apply_preset(owner, name)
    return name
