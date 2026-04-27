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
        "hsplit", [("file", None), ("file", None)],
    ),
    "quad-files": (
        "hsplit", [
            ("vsplit", [("file", None), ("file", None)]),
            ("vsplit", [("file", None), ("file", None)]),
        ],
    ),
    "commander": (
        "hsplit", [("file", None), ("file", None)],
    ),
    "dev-shells": (
        "hsplit", [
            ("file", None),
            ("vsplit", [("term", "local"), ("term", "local")]),
        ],
    ),
    "triage": (
        "vsplit", [
            ("hsplit", [("file", None), ("file", None)]),
            ("term", "local"),
        ],
    ),
    "shells-quad": (
        "hsplit", [
            ("vsplit", [("term", "local"), ("term", "local")]),
            ("vsplit", [("term", "local"), ("term", "local")]),
        ],
    ),
}

# Order in which Ctrl+Alt+L cycles. New presets get appended here so
# muscle memory stays stable across updates.
PRESET_ORDER: list[str] = [
    "single", "dual", "quad-files", "commander",
    "dev-shells", "triage", "shells-quad",
]


# --- Builder ----------------------------------------------------------------

def _build(spec: Any, owner) -> QWidget:
    """Recursively materialise ``spec`` into a Qt widget tree.

    ``owner`` is the MainWindow — we call its existing factory
    methods (``_make_file_pane``, ``_make_local_terminal``) so panes
    behave exactly as if the user had created them manually (active-
    pane plumbing, drop targets, etc.).
    """
    kind, payload = spec
    if kind in ("hsplit", "vsplit"):
        orientation = (
            Qt.Orientation.Horizontal if kind == "hsplit"
            else Qt.Orientation.Vertical
        )
        splitter = QSplitter(orientation)
        for child_spec in payload:
            child = _build(child_spec, owner)
            splitter.addWidget(child)
        return splitter
    if kind == "file":
        return owner._preset_make_file_pane()
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
    owner._preset_tear_down_existing()
    root = _build(PRESETS[name], owner)
    owner.setCentralWidget(root)
    # Track which preset we're on so the cycle helper can rotate.
    owner._current_preset_name = name
    owner._refresh_after_preset()


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
