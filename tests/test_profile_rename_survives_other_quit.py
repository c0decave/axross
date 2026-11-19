"""A profile renamed in one axross stays renamed when another one quits.

Measured before (review round 3): the rename rewrote session.json under its
lock, but a second axross keeps its own copy of the layout, renamed only by
its own Connection dialog. When it quit it wrote that copy - still naming
the old profile - over the file, and at the next start its panes said "The
profile 'nas' no longer exists". The rename is now recorded in session.json
and a window's save applies it to what it writes, for a profile that is no
longer there under its old name.
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
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _profiles(win, names):
    win._profile_manager.list_names = lambda: list(names)


def _session(path: Path, profile: str) -> None:
    data = {"window": {}, "workspaces": [{"name": "W", "current": True, "splitter": {
        "type": "splitter", "orientation": "h", "sizes": [1, 1], "children": [
            {"type": "pane", "path": "/srv", "profile": profile},
            {"type": "terminal", "profile": profile, "cwd": "/srv"}]}}]}
    path.write_text(json.dumps(data), encoding="utf-8")


def _profiles_in(path: Path) -> list:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [c.get("profile") for c in data["workspaces"][0]["splitter"]["children"]]


@pytest.mark.parametrize("still_there", [False, True])
def test_sad_a_rename_elsewhere_is_not_undone_by_this_windows_quit(tmp_path, monkeypatch,
                                                                    still_there):
    from core.profile_references import rename_profile_references
    from ui import main_window as MW

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    path = home / "session.json"
    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", path)
    _session(path, "nas")
    win = MW.MainWindow()
    try:
        win._reconnect_timer.stop()
        assert win.restore_layout_on_start()
        APP.processEvents()

        class _NoBookmarks:
            def all(self):
                return []

        rename_profile_references("nas", "nas2", bookmarks=_NoBookmarks(), session_file=path)
        assert _profiles_in(path) == ["nas2", "nas2"]
        # The other axross: "nas" is gone from its profiles - unless a new
        # profile of that name was made since, which keeps its panes.
        _profiles(win, ["nas2", "nas"] if still_there else ["nas2"])
        win._save_session()
        assert _profiles_in(path) == (["nas", "nas"] if still_there else ["nas2", "nas2"])
    finally:
        if not sip.isdeleted(win):
            win.close()
            win.deleteLater()
        end = time.time() + 0.1
        while time.time() < end:
            APP.processEvents()
