"""A session.json whose workspace list holds a non-object never stops the start.

Review 2026-11-19 (sessions, round 1): ``restore_layout_on_start`` refused
``{"workspaces": ["oops"]}`` correctly ("A workspace is not an object."),
then main.py called ``apply_first_start_layout``, which read the file again
and ran ``_session_has_panes`` on it unchecked: ``'str' object has no
attribute 'get'`` out of ``main()``, before the window showed. The file is
only rewritten on quit, so every later start crashed the same way (and left
one more ``session.json.unrestorable-*`` copy).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6 import sip  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def session_file(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    from ui import main_window as MW

    path = home / "session.json"
    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", path)
    return path


@pytest.mark.parametrize("entries", [["oops"], [None, {"splitter": {}}], [3], [[]]])
def test_sad_a_workspace_that_is_no_object_starts_with_the_default_layout(session_file, entries):
    from ui.main_window import MainWindow

    session_file.write_text(json.dumps({"workspaces": entries}))
    win = MainWindow()
    try:
        win._reconnect_timer.stop()
        assert win.restore_layout_on_start() is False
        assert win.apply_first_start_layout() is False  # raised AttributeError before
        assert len(win._panes) == 1
    finally:
        if not sip.isdeleted(win):
            win.close()
            win.deleteLater()
        APP.processEvents()


def test_edge_has_panes_skips_entries_that_are_no_object():
    from ui.main_window import _session_has_panes

    assert _session_has_panes({"workspaces": ["x", {"splitter": {"children": [{}]}}]})
    assert not _session_has_panes({"workspaces": ["x", 3, None]})
