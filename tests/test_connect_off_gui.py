"""Restoring a session and (re)connecting a terminal connect off the GUI
thread.

Found by the second audit (feedback: no blocked windows): Restore Last
Session connected every remote pane in turn on the GUI thread, and a
terminal pane's connect / Restart / a restored terminal did the same
(with its keyring read) - the window frozen for each handshake, for a
dead host's whole timeout. ui.off_gui.connect_off_gui runs the connect
on a worker now; the unknown-host question is still asked on the GUI
thread, its answer reaches the connect.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QTimer  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from ui.off_gui import connect_off_gui  # noqa: E402

APP = QApplication.instance() or QApplication([])

# TICKS_NOTE: a timer that ticked at all ran during the wait - a GUI thread
# held by the call gets none (the timer stops before the loop runs again).
# How often it ticked depends on the host's load, so only "at all" counts.


class Manager:
    def __init__(self, fail=None, ask=False, delay=0.3) -> None:
        self.calls: list = []
        self.fail, self.ask, self.delay = fail, ask, delay

    def connect(self, profile, password="", key_passphrase="", on_unknown_host=None):
        self.calls.append((threading.current_thread().name, password, key_passphrase))
        time.sleep(self.delay)
        if self.ask:
            if not on_unknown_host(RuntimeError("new key")):
                raise OSError("host key rejected")
        if self.fail:
            raise self.fail
        return SimpleNamespace(name="session")


class Profile:
    name = "srv"

    def __init__(self) -> None:
        self.read_on: list[str] = []

    def get_password(self):
        self.read_on.append(threading.current_thread().name)
        return "from-keyring"


def _ticks(fn):
    ticks = []
    timer = QTimer()
    timer.setInterval(20)
    timer.timeout.connect(lambda: ticks.append(1))
    timer.start()
    try:
        return fn(), len(ticks)
    finally:
        timer.stop()


def test_happy_the_connect_runs_off_the_gui_thread_and_the_window_stays_live():
    manager = Manager()
    session, ticks = _ticks(lambda: connect_off_gui(manager, Profile(), password="pw",
                                                    key_passphrase="kp"))
    assert session.name == "session"
    assert manager.calls == [(manager.calls[0][0], "pw", "kp")]
    assert manager.calls[0][0] != "MainThread"
    assert ticks >= 1


def test_happy_the_host_key_question_is_asked_on_the_gui_thread():
    asked: list[str] = []

    def prompt(_error):
        asked.append(threading.current_thread().name)
        return True

    assert connect_off_gui(Manager(ask=True), Profile(), prompt=prompt).name == "session"
    assert asked == ["MainThread"]


def test_happy_the_keyring_is_read_off_the_gui_thread_too():
    profile, manager = Profile(), Manager()
    connect_off_gui(manager, profile, password_from_keyring=True)
    assert profile.read_on and "MainThread" not in profile.read_on
    assert manager.calls[0][1] == "from-keyring"


def test_sad_a_rejected_host_key_or_a_dead_host_raises_here():
    with pytest.raises(OSError, match="host key rejected"):
        connect_off_gui(Manager(ask=True), Profile(), prompt=lambda _e: False)
    with pytest.raises(TimeoutError):
        connect_off_gui(Manager(fail=TimeoutError("no route")), Profile())


def test_edge_the_status_line_names_the_host_while_it_takes():
    texts: list[str] = []
    connect_off_gui(Manager(delay=0.7), Profile(), status=texts.append)
    assert texts == ["Connecting to srv…", ""]
