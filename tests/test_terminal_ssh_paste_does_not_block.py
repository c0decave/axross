"""A paste into an SSH terminal whose remote side does not read never
blocks the window.

Review 2026-11-19 (terminal round 1): ``SSHTerminalSession.write`` was
``channel.sendall`` on the GUI thread. paramiko's ``sendall`` waits for
the channel's send window; with the remote program busy (``sleep 100``
and a large paste) or the connection gone quiet the window stays shut and
the whole window froze until the remote read again - for ever on a dead
link. The local shell got a non-blocking queue before
(tests/test_terminal_paste_does_not_block.py); the SSH shell now does the
same: what the channel does not take at once waits in a bounded queue and
goes out on the next write or output poll.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402

pytest.importorskip("PyQt6.QtWidgets")


class _Channel:
    """A paramiko Channel as far as the terminal uses it: a send window."""

    def __init__(self, window: int = 0) -> None:
        self.window = window
        self.sent = bytearray()
        self.closed = False

    def send_ready(self) -> bool:
        return self.closed or self.window > 0

    def send(self, data: bytes) -> int:
        n = min(len(data), self.window)
        self.sent += data[:n]
        self.window -= n
        return n

    def sendall(self, data: bytes) -> None:
        if len(data) > self.window:
            raise AssertionError("sendall would block until the remote reads")
        self.send(data)

    def recv_ready(self) -> bool:
        return False

    def recv(self, size: int) -> bytes:
        return b""

    def close(self) -> None:
        self.closed = True


def _session(channel: _Channel):
    from ui.terminal_widget import SSHTerminalSession

    session = SSHTerminalSession(transport=None)
    session._channel = channel
    session._running = True
    return session


def test_sad_a_paste_into_a_remote_that_does_not_read_returns_at_once():
    channel = _Channel(window=0)
    session = _session(channel)
    started = time.monotonic()
    session.write(b"x" * 200_000)
    assert time.monotonic() - started < 1.0
    assert channel.sent == b""


def test_happy_the_queued_rest_goes_out_once_the_remote_reads_again():
    channel = _Channel(window=1000)
    session = _session(channel)
    session.write(b"a" * 5000)
    assert bytes(channel.sent) == b"a" * 1000
    channel.window = 10**9
    session.read_ready()  # the next output poll
    assert bytes(channel.sent) == b"a" * 5000


def test_happy_order_is_kept_between_queued_and_new_input():
    channel = _Channel(window=0)
    session = _session(channel)
    session.write(b"first ")
    channel.window = 3
    session.write(b"second")
    channel.window = 10**9
    session.write(b"!")
    assert bytes(channel.sent) == b"first second!"


def test_edge_the_queue_is_bounded(monkeypatch, caplog):
    import ui.terminal_widget as tw

    monkeypatch.setattr(tw, "PTY_WRITE_QUEUE_CAP", 1024)
    channel = _Channel(window=0)
    session = _session(channel)
    session.write(b"y" * 5000)
    assert session.pending_input() == 1024
    assert "dropped" in caplog.text


def test_edge_a_closed_channel_drops_the_queue():
    channel = _Channel(window=0)
    session = _session(channel)
    session.write(b"z" * 100)
    session.close()
    assert session.pending_input() == 0
    session.write(b"more")  # no error, nothing queued
    assert session.pending_input() == 0
