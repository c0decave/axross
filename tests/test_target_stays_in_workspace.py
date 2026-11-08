"""The target pane is always one of the active pane's workspace.

Review round 3: two workspaces - "Workspace 1" with a local pane and an
SFTP pane, "Second" with two local panes - saved on quit and restored at
the next start, the SFTP pane still a "Not connected" placeholder. The
local pane became active, and the target was chosen as "the first other
pane" of ``self._panes``: a pane of the hidden "Second" tab. F5 copied
``todo.txt`` there without a word. ``_set_active_pane`` had the same
fallback, and ``switch_workspace`` kept a target of another workspace when
the workspace it switched to held one file pane only.

Now every fallback picks from the active pane's workspace (its remembered
target first), and with no other pane there the target stays unset: F5
says to choose one.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _settle(seconds: float = 0.1) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.005)


def _window(home: Path):
    from ui import main_window as MW

    with mock.patch("pathlib.Path.home", return_value=home):
        window = MW.MainWindow()
    window._reconnect_timer.stop()
    window._quit_with_transfers = True
    for pane in list(window._panes)[1:]:
        window._close_pane(pane)
    return window


def _close(window) -> None:
    window._pane_profiles.clear()
    window.close()
    window.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


@pytest.fixture
def setup(tmp_path, monkeypatch):
    """Workspace 1: pane *a*; "Second": panes *c* and *b*."""
    from ui import main_window as MW

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", home / "session.json")
    dirs = {n: tmp_path / n for n in "abc"}
    for d in dirs.values():
        d.mkdir()
    window = _window(home)
    a = window._panes[0]
    a.navigate(str(dirs["a"]))
    window.new_workspace("Second")
    c = window._panes[-1]
    c.navigate(str(dirs["c"]))
    b = window._add_pane_to_splitter(window._root_splitter, LocalFS())
    b.navigate(str(dirs["b"]))
    window.switch_workspace(window.workspaces()[0])
    windows = [window]
    yield {"win": window, "a": a, "b": b, "c": c, "dirs": dirs, "home": home,
           "windows": windows}
    for w in windows:
        _close(w)


def test_happy_switching_to_a_one_pane_workspace_leaves_no_hidden_target(setup):
    win, a, c = setup["win"], setup["a"], setup["c"]
    assert win._active_pane is a
    assert win._target_pane is None or win.workspace_of(win._target_pane) is win.workspaces()[0]
    win.switch_workspace(win.workspaces()[1])
    win._set_active_pane(c)
    win.switch_workspace(win.workspaces()[0])
    assert win._active_pane is a
    assert win._target_pane is None  # c (hidden tab) was kept as the target


def test_sad_f5_after_a_restart_does_not_copy_into_a_hidden_workspace(setup):
    win, dirs, home = setup["win"], setup["dirs"], setup["home"]
    win._target_pane = None
    win._save_session()
    _close(win)
    setup["windows"].clear()
    (dirs["a"] / "todo.txt").write_text("t")
    win2 = _window(home)
    setup["windows"].append(win2)
    win2._restore_on_start = True
    assert win2.restore_layout_on_start()
    _settle(0.5)
    active = win2._active_pane
    assert active.current_path == str(dirs["a"])
    assert win2._target_pane is None  # not the pane of the "Second" tab
    with mock.patch.object(active, "selected_items",
                           return_value=[str(dirs["a"] / "todo.txt")]), \
            mock.patch("ui.main_window.QMessageBox.information") as info:
        win2._transfer_to_target()
    _settle(0.3)
    assert info.called and "target" in info.call_args[0][2]
    assert list(dirs["b"].iterdir()) == [] and list(dirs["c"].iterdir()) == []


def test_edge_the_fallback_takes_a_pane_of_the_same_workspace(setup):
    win, b, c = setup["win"], setup["b"], setup["c"]
    win.switch_workspace(win.workspaces()[1])
    win._set_active_pane(c)
    win._target_pane = c  # as a closed or replaced target leaves it
    win._set_active_pane(c)
    assert win._target_pane in (b, None)
    win._target_pane = c
    win._set_active_pane(b)  # c, the old active one, becomes the target
    assert win._target_pane is c
