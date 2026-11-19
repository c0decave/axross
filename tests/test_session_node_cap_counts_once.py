"""A layout axross saved itself is restored at the next start.

Review 2026-11-20 (sessions round 2): the start's check of session.json
counted the entries of the legacy ``splitter`` - which _save_session
writes as a copy of the first workspace for an older axross - and of
every workspace: the first one twice, against a cap of 128 entries.
Eighteen workspaces of the four-pane preset (126 entries) were refused as
"more than 128 entries", the default layout came up and the quit wrote
over the user's layout. The legacy tree counts only when there are no
workspaces (the restore uses it only then), and the cap is 256.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")

from ui import main_window as MW  # noqa: E402


def _quad() -> dict:
    pane = {"type": "pane", "path": "/", "local": True}
    row = {"type": "splitter", "orientation": "h", "children": [dict(pane), dict(pane)]}
    return {"type": "splitter", "orientation": "v", "children": [row, dict(row)]}


def _session(workspaces: int) -> dict:
    entries = [{"name": f"W{i}", "splitter": _quad()} for i in range(workspaces)]
    return {"window": {}, "workspaces": entries, "splitter": entries[0]["splitter"]}


def test_sad_eighteen_four_pane_workspaces_are_restorable():
    assert MW._session_problem(_session(18)) == ""


def test_happy_a_session_of_before_the_workspaces_is_still_checked():
    data = {"window": {}, "splitter": {"type": "splitter", "children": [5]}}
    assert MW._session_problem(data) == "A layout entry is not an object."


def test_edge_the_cap_still_holds():
    pane = {"type": "pane", "path": "/", "local": True}
    tree = {"type": "splitter", "children": [dict(pane) for _ in range(MW.MAX_SESSION_NODES)]}
    data = {"window": {}, "workspaces": [{"name": "W", "splitter": tree}]}
    assert "more than" in MW._session_problem(data)
