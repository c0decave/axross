"""An SSH terminal opens its channel, pty and shell off the GUI thread.

Found by the second audit (feedback: no blocked windows): Start in the
terminal dock, Open Terminal Here on an SSH pane and a restored shell
pane opened the channel, asked for the pty and started the shell on the
GUI thread - three round trips, the window frozen for a slow server.
They run on a worker now (ui.off_gui).
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QTimer  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])

# TICKS_NOTE: a timer that ticked at all ran during the wait - a GUI thread
# held by the call gets none (the timer stops before the loop runs again).
# How often it ticked depends on the host's load, so only "at all" counts.


class Channel:
    def __init__(self, log) -> None:
        self.log, self.closed = log, False
        self.sent: list[bytes] = []

    def get_pty(self, **kw):
        self.log.append(("pty", threading.current_thread().name, kw))
        time.sleep(0.15)

    def invoke_shell(self):
        self.log.append(("shell", threading.current_thread().name, None))
        time.sleep(0.15)

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True


class Transport:
    def __init__(self) -> None:
        self.log: list = []

    def open_session(self):
        self.log.append(("open", threading.current_thread().name, None))
        time.sleep(0.15)
        return Channel(self.log)

    def is_active(self):
        return True


def test_happy_the_shell_starts_off_the_gui_thread_with_its_size():
    from ui import terminal_widget as TW

    backend_class = next(getattr(TW, n) for n in dir(TW)
                         if n.startswith("SSH") and hasattr(getattr(TW, n), "start"))
    transport = Transport()
    backend = backend_class(transport, rows=30, cols=100)
    ticks = []
    timer = QTimer()
    timer.setInterval(20)
    timer.timeout.connect(lambda: ticks.append(1))
    timer.start()
    try:
        backend.start()
    finally:
        timer.stop()
    assert [step for step, _t, _kw in transport.log] == ["open", "pty", "shell"]
    assert all(thread != "MainThread" for _s, thread, _kw in transport.log)
    assert transport.log[1][2] == {"term": "xterm", "width": 100, "height": 30}
    assert backend.is_active and len(ticks) >= 1


def _backend_class():
    from ui import terminal_widget as TW

    return TW.SSHTerminalSession


def test_sad_a_read_timer_during_the_start_does_not_end_the_session():
    """Found by the review: the dock's 50 ms read timer ran during the
    wait, saw no channel yet and closed the new session - the remote shell
    stayed open with nobody reading it."""
    transport = Transport()
    backend = _backend_class()(transport)
    seen: list[bool] = []
    timer = QTimer()
    timer.setInterval(20)
    timer.timeout.connect(lambda: (seen.append(backend.is_active), backend.read()))
    timer.start()
    try:
        backend.start()
    finally:
        timer.stop()
    assert seen and all(seen)  # active all along
    assert backend.is_active and backend._channel is not None


def test_sad_a_failing_pty_closes_the_channel_it_opened():
    closed: list[bool] = []

    class Broken(Channel):
        def get_pty(self, **kw):
            raise OSError("no pty")

        def close(self):
            closed.append(True)

    class T(Transport):
        def open_session(self):
            return Broken(self.log)

    backend = _backend_class()(T())
    with pytest.raises(OSError, match="no pty"):
        backend.start()
    assert closed == [True] and not backend.is_active


def test_edge_closed_while_starting_closes_the_arriving_channel():
    transport = Transport()
    backend = _backend_class()(transport)
    QTimer.singleShot(100, backend.close)
    backend.start()
    assert backend._channel is None and not backend.is_active
