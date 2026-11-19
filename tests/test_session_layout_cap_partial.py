"""A layout past the 256 entries comes back as far as it fits.

Measured before (review round 3): ``_save_session`` writes every workspace,
and the start refused a session.json whose workspaces held more than 256
layout entries as a whole - 32 workspaces of 8 panes, or 26 of a 2x3 grid,
all made in the window, came back as the default single pane (the file kept
as .unrestorable). docs/USAGE.md: "Up to 256 layout entries come back". Now
the leading workspaces that fit come back; a first workspace that alone is
too large is still refused (a hostile file must not start thousands of
shells).
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


def _workspace(i: int, panes: int) -> dict:
    return {"name": f"W{i}", "splitter": {
        "type": "splitter", "orientation": "h",
        "children": [{"type": "pane", "path": "/", "local": True} for _ in range(panes)],
        "sizes": [1] * panes}}


def _nodes(entries) -> int:
    count = 0
    stack = [e["splitter"] for e in entries]
    while stack:
        node = stack.pop()
        count += 1
        stack.extend(node.get("children", []))
    return count


def test_sad_a_large_layout_the_window_made_comes_back_as_far_as_it_fits():
    data = {"window": {}, "workspaces": [_workspace(i, 8) for i in range(32)]}
    data["workspaces"][0]["current"] = True
    assert MW._session_problem(data) == ""  # refused as a whole before
    kept = MW._session_workspaces(data)
    assert 0 < len(kept) < 32
    assert [w["name"] for w in kept] == [f"W{i}" for i in range(len(kept))]
    assert _nodes(kept) <= MW.MAX_SESSION_NODES
    assert _nodes(data["workspaces"][: len(kept) + 1]) > MW.MAX_SESSION_NODES


def test_happy_a_layout_that_fits_comes_back_whole():
    data = {"window": {}, "workspaces": [_workspace(i, 4) for i in range(10)]}
    assert MW._session_problem(data) == ""
    assert len(MW._session_workspaces(data)) == 10


def test_sad_a_first_workspace_too_large_is_still_refused():
    inner = [_workspace(i, 10)["splitter"] for i in range(30)]
    data = {"window": {}, "workspaces": [{"name": "W0", "splitter": {
        "type": "splitter", "orientation": "v", "children": inner, "sizes": [1] * 30}}]}
    assert "256" in MW._session_problem(data)


def test_sad_a_bad_entry_in_a_workspace_that_fits_is_still_refused():
    data = {"window": {}, "workspaces": [_workspace(0, 2), _workspace(1, 2)]}
    data["workspaces"][1]["splitter"]["children"][0]["path"] = 5
    assert MW._session_problem(data) != ""


def test_e2e_a_window_with_32_workspaces_of_8_panes_restarts_with_them(tmp_path, monkeypatch):
    import json

    from PyQt6 import sip
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    path = home / "session.json"
    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", path)
    data = {"window": {}, "workspaces": [_workspace(i, 8) for i in range(32)]}
    data["workspaces"][31]["current"] = True  # the one past the cap
    path.write_text(json.dumps(data), encoding="utf-8")
    win = MW.MainWindow()
    try:
        win._reconnect_timer.stop()
        assert win.restore_layout_on_start()  # the default single pane before
        app.processEvents()
        assert len(win._panes) > 200
        assert not list(path.parent.glob("session.json.unrestorable-*"))
    finally:
        if not sip.isdeleted(win):
            win.close()
            win.deleteLater()
        app.processEvents()
