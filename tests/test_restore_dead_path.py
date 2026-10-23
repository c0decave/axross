"""A restored layout never waits on its folders in the GUI thread.

Found in the startup audit after the "no window" incident: the layout is
restored before the window is shown, and ``_existing_local_folder`` asked
``os.path.isdir`` about every restored local pane's folder and every local
terminal's folder - in the GUI thread. On a dead hard NFS/sshfs mount that
call never returns, and the window never comes. Now a restored pane loads
its folder in the background (falling back to home when it is gone) and a
terminal's shell enters its folder itself, falling back to home.

The dead mount is simulated: os.stat / lstat / listdir / scandir block on
a path below DEAD until the test ends, like a hard mount whose server is
gone. A call from the GUI thread is recorded and released after a moment,
so a regression fails the test instead of hanging it.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QCoreApplication, QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])
#: How long a GUI-thread call on the dead path is held before it is let go
#: (and counted as the failure it is).
GUI_HOLD_SECONDS = 2.0


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)


def wait_until(predicate, timeout: float = 5.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if predicate():
            return True
        time.sleep(0.02)
    return bool(predicate())


class DeadMount:
    """Blocks filesystem calls below *prefix* like a hard mount of a gone server."""

    def __init__(self, prefix: str) -> None:
        self.prefix = prefix
        self.release = threading.Event()
        self.gui_calls: list[str] = []
        self.worker_calls: list[str] = []
        self._patches = []

    def _wrap(self, real):
        def blocked(path, *args, **kwargs):
            text = path if isinstance(path, str) else (
                os.fsdecode(path) if isinstance(path, (bytes, os.PathLike)) else "")
            if text.startswith(self.prefix):
                if threading.current_thread() is threading.main_thread():
                    self.gui_calls.append(text)
                    self.release.wait(GUI_HOLD_SECONDS)
                    raise OSError(5, "simulated dead mount (GUI thread)", text)
                self.worker_calls.append(text)
                self.release.wait()
                raise OSError(5, "simulated dead mount", text)
            return real(path, *args, **kwargs)

        return blocked

    def __enter__(self):
        for name in ("stat", "lstat", "listdir", "scandir"):
            patch = mock.patch.object(os, name, self._wrap(getattr(os, name)))
            patch.start()
            self._patches.append(patch)
        return self

    def __exit__(self, *exc):
        self.release.set()
        for patch in reversed(self._patches):
            patch.stop()


@pytest.fixture
def home():
    path = Path(tempfile.mkdtemp())
    yield path
    shutil.rmtree(path, ignore_errors=True)


def _session(home: Path, children: list[dict]) -> Path:
    path = home / "session.json"
    path.write_text(json.dumps({
        "window": {"width": 1000, "height": 700},
        "workspaces": [{"name": "W1", "current": True,
                        "splitter": {"type": "splitter", "children": children}}],
    }))
    return path


def _window(home: Path, monkeypatch):
    from ui import main_window as MW

    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", home / "session.json")
    with mock.patch("pathlib.Path.home", return_value=home):
        win = MW.MainWindow()
    win._reconnect_timer.stop()
    return win


def _destroy(win) -> None:
    for term in list(win._terminal_panes):
        win._close_terminal_pane(term)
    win.close()
    win.deleteLater()
    pump()


def _same_dir(a, b) -> bool:
    try:
        return a is not None and os.path.samefile(a, b)
    except OSError:
        return False


# --- happy -----------------------------------------------------------------


def test_happy_a_pane_on_a_dead_mount_does_not_hold_the_window(home, monkeypatch):
    dead = f"/axross-dead-{os.getpid()}"
    _session(home, [
        {"type": "pane", "local": True, "path": f"{dead}/projects", "active": True},
        {"type": "pane", "local": True, "path": str(home)},
    ])
    win = _window(home, monkeypatch)
    try:
        with DeadMount(dead) as mount, mock.patch("pathlib.Path.home", return_value=home):
            started = time.monotonic()
            assert win.restore_layout_on_start() is True
            win.show()
            pump(0.3)
            took = time.monotonic() - started
            assert mount.gui_calls == []
            assert took < GUI_HOLD_SECONDS
            assert len(win._panes) == 2
            stuck = win._panes[0]
            # the folder is asked in the background and the pane says so
            assert wait_until(lambda: mount.worker_calls, 5.0)
            assert stuck.is_loading
            # the other pane and the window work meanwhile
            assert wait_until(lambda: win._panes[1].current_path == str(home), 5.0)
    finally:
        _destroy(win)


def test_happy_a_terminal_on_a_dead_mount_does_not_hold_the_window(home, monkeypatch):
    dead = f"/axross-dead-{os.getpid()}"
    _session(home, [
        {"type": "pane", "local": True, "path": str(home), "active": True},
        {"type": "terminal", "local": True, "cwd": f"{dead}/build"},
    ])
    win = _window(home, monkeypatch)
    try:
        with DeadMount(dead) as mount, mock.patch("pathlib.Path.home", return_value=home):
            started = time.monotonic()
            assert win.restore_layout_on_start() is True
            took = time.monotonic() - started
            assert mount.gui_calls == []
            assert took < GUI_HOLD_SECONDS
            (term,) = win._terminal_panes
            # The shell itself finds the folder unusable (here: absent) and
            # starts at home.
            assert wait_until(lambda: _same_dir(term.working_directory(), home), 10.0)
    finally:
        _destroy(win)


# --- sad -------------------------------------------------------------------


def test_sad_a_pane_whose_folder_is_gone_comes_back_at_home(home, monkeypatch):
    _session(home, [{"type": "pane", "local": True, "path": str(home / "removed"),
                     "active": True}])
    win = _window(home, monkeypatch)
    try:
        with mock.patch("pathlib.Path.home", return_value=home):
            assert win.restore_layout_on_start() is True
            win.show()
            (pane,) = win._panes
            assert wait_until(lambda: not pane.is_loading and pane.current_path == str(home)
                              and pane._model.rowCount() >= 0, 10.0)
            assert pane.current_path == str(home)
    finally:
        _destroy(win)


def test_sad_a_terminal_whose_folder_is_gone_starts_at_home(home, monkeypatch):
    _session(home, [
        {"type": "pane", "local": True, "path": str(home), "active": True},
        {"type": "terminal", "local": True, "cwd": str(home / "removed")},
    ])
    win = _window(home, monkeypatch)
    try:
        with mock.patch("pathlib.Path.home", return_value=home):
            assert win.restore_layout_on_start() is True
            (term,) = win._terminal_panes
            assert wait_until(lambda: _same_dir(term.working_directory(), home), 10.0)
    finally:
        _destroy(win)


def test_sad_a_new_terminal_beside_a_pane_on_a_dead_mount_does_not_hold_the_window(
        home, monkeypatch):
    # Runtime twin of the start: Add Terminal Pane starts in the active
    # pane's folder, which was asked about in the GUI thread too.
    from ui.workspaces import START_TERMINAL

    win = _window(home, monkeypatch)
    dead = f"/axross-dead-{os.getpid()}"
    try:
        win.show()
        win._active_pane._current_path = f"{dead}/here"  # it was listed before the server went
        with DeadMount(dead) as mount, mock.patch("pathlib.Path.home", return_value=home):
            started = time.monotonic()
            ws = win.new_workspace(start=START_TERMINAL)
            assert time.monotonic() - started < GUI_HOLD_SECONDS
            assert mount.gui_calls == []
            assert ws is not None
    finally:
        _destroy(win)


# --- edge ------------------------------------------------------------------


def test_edge_a_restored_pane_in_an_existing_folder_lands_there(home, monkeypatch):
    target = home / "work"
    target.mkdir()
    (target / "file.txt").write_text("x")
    _session(home, [{"type": "pane", "local": True, "path": str(target), "active": True}])
    win = _window(home, monkeypatch)
    try:
        with mock.patch("pathlib.Path.home", return_value=home):
            assert win.restore_layout_on_start() is True
            (pane,) = win._panes
            assert wait_until(lambda: pane.current_path == str(target) and not pane.is_loading)
    finally:
        _destroy(win)


def test_edge_a_cancelled_restore_load_leaves_the_pane_usable(home, monkeypatch):
    dead = f"/axross-dead-{os.getpid()}"
    _session(home, [{"type": "pane", "local": True, "path": f"{dead}/x", "active": True}])
    win = _window(home, monkeypatch)
    try:
        with DeadMount(dead) as mount, mock.patch("pathlib.Path.home", return_value=home):
            assert win.restore_layout_on_start() is True
            (pane,) = win._panes
            assert wait_until(lambda: mount.worker_calls, 5.0)
            pane.cancel_navigation()
            pump(0.2)
            assert not pane.is_loading
            assert mount.gui_calls == []
    finally:
        _destroy(win)
