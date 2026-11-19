"""A dock bound to a workspace comes back on that workspace when an earlier
one is not restored.

Measured before (review round 3): session.json names a bound dock's
workspace by its place in the list. A workspace whose panes all save as
nothing (a shell of a host terminal bookmark, a remote pane without a saved
profile) is saved empty and not restored, so every later workspace moved up
one place and the dock came back on the workspace after its own - or lost
its binding when its own was the last one.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets")

from PyQt6 import sip  # noqa: E402
from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.1) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)


def _ws(name: str, panes: int) -> dict:
    return {"name": name, "splitter": {
        "type": "splitter", "orientation": "h",
        "children": [{"type": "pane", "path": "/", "local": True} for _ in range(panes)],
        "sizes": [1] * panes}}


@pytest.mark.parametrize("bound_to", [2, 3])
def test_sad_the_binding_follows_its_workspace_past_a_pruned_one(tmp_path, monkeypatch, bound_to):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    from ui import main_window as MW

    path = home / "session.json"
    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", path)
    data = {"window": {"dock_workspaces": {"axLogDock": {"ws": bound_to, "open": True}}},
            "workspaces": [_ws("A", 1), _ws("B", 0), _ws("C", 1), _ws("D", 1)]}
    data["workspaces"][0]["current"] = True
    path.write_text(json.dumps(data), encoding="utf-8")
    win = MW.MainWindow()
    try:
        win._reconnect_timer.stop()
        assert win.restore_layout_on_start()
        pump()
        names = [ws.name for ws in win.workspaces()]
        assert names == ["A", "C", "D"]
        bound = win.dock_workspace(win._log_dock)
        assert bound is not None and bound.name == "CD"[bound_to - 2]
    finally:
        if not sip.isdeleted(win):
            win.close()
            win.deleteLater()
        pump()
