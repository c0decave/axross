"""A paste into a busy Windows shell (ConPTY through pywinpty) never
blocks the window.

Review 2026-11-20 (terminal round 2): ``LocalTerminalSession.write`` on
Windows was ``PtyProcess.write`` on the GUI thread. pywinpty writes the
text into the console's input pipe and waits while the pipe is full - a
large paste while ``cmd`` runs a program that does not read froze the
window until it read again, for ever with one that never does. The POSIX
pty and the SSH channel got a bounded queue in round 1; the ConPTY now
has the same queue, drained by a writer thread of its own. Order is kept,
a UTF-8 character split between two writes arrives whole, a shell that
has gone ends the writer instead of raising in the window.
"""

from __future__ import annotations

import socket
import sys
import threading
import time
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ui import terminal_widget as TW  # noqa: E402


class _BusyPty:
    """pywinpty's PtyProcess as far as the terminal uses it; ``write``
    blocks until ``reading`` is set, as a full console input pipe does."""

    last: "_BusyPty | None" = None

    def __init__(self) -> None:
        self._ours, self._theirs = socket.socketpair()
        self.pid = 4242
        self.reading = threading.Event()
        self.written: list[str] = []
        self.calls_on: set[int] = set()
        self.closed = False
        self.raise_eof = False

    @classmethod
    def spawn(cls, argv, cwd=None, env=None, dimensions=(24, 80)):
        cls.last = cls()
        return cls.last

    def fileno(self) -> int:
        return self._ours.fileno()

    def read(self, size=1024) -> str:
        data = self._ours.recv(size)
        if not data:
            raise EOFError("Pty is closed")
        return data.decode("utf-8")

    def write(self, s: str) -> int:
        self.calls_on.add(threading.get_ident())
        if self.raise_eof:
            raise EOFError("Pty is closed")
        # Blocks while the shell does not read - up to 2 s here, so a
        # write on the GUI thread fails the test instead of hanging it.
        deadline = time.monotonic() + 2
        while not self.reading.wait(0.05):
            if self.closed:
                raise EOFError("Pty is closed")
            if time.monotonic() > deadline:
                break
        self.written.append(s)
        return len(s)

    def setwinsize(self, rows, cols) -> None:
        pass

    def close(self, force=False) -> None:
        self.closed = True
        self._ours.close()
        self._theirs.close()


@pytest.fixture
def session(monkeypatch):
    monkeypatch.setitem(sys.modules, "pty", None)
    fake = types.ModuleType("winpty")
    fake.PtyProcess = _BusyPty
    monkeypatch.setitem(sys.modules, "winpty", fake)
    monkeypatch.setenv("COMSPEC", "cmd.exe")
    s = TW.LocalTerminalSession()
    s.start()
    yield s
    s.close()


def _written(proc: _BusyPty, expected: str, timeout: float = 5.0) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        text = "".join(proc.written)
        if len(text) >= len(expected):
            return text
        time.sleep(0.01)
    return "".join(proc.written)


def test_sad_a_paste_into_a_shell_that_does_not_read_returns_at_once(session):
    proc = _BusyPty.last
    started = time.monotonic()
    session.write(b"x" * 200_000)
    session.write(b"y" * 200_000)
    assert time.monotonic() - started < 0.5
    assert threading.get_ident() not in proc.calls_on or not proc.written
    assert session.pending_input() > 0


def test_happy_the_queue_goes_out_in_order_once_the_shell_reads(session):
    proc = _BusyPty.last
    session.write(b"first ")
    session.write(b"second " * 20_000)
    session.write(b"!")
    proc.reading.set()
    expected = "first " + "second " * 20_000 + "!"
    assert _written(proc, expected) == expected
    assert threading.get_ident() not in proc.calls_on


def test_edge_a_character_split_between_two_writes_arrives_whole(session):
    proc = _BusyPty.last
    proc.reading.set()
    euro = "€".encode()
    session.write(b"a" + euro[:1])
    session.write(euro[1:] + b"b\r\n")
    assert _written(proc, "a€b\r\n") == "a€b\r\n"


def test_edge_the_queue_is_bounded(session, monkeypatch, caplog):
    monkeypatch.setattr(TW, "PTY_WRITE_QUEUE_CAP", 1024)
    monkeypatch.setattr(TW, "PTY_WRITE_CHUNK", 64)
    session.write(b"q" * 5000)
    assert session.pending_input() <= 1024
    assert "dropped" in caplog.text


def test_sad_a_shell_that_has_gone_ends_the_writer_without_an_error(session):
    proc = _BusyPty.last
    proc.raise_eof = True
    session.write(b"dir\r\n")  # never raises in the window
    deadline = time.monotonic() + 5
    while session.pending_input() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert session.pending_input() == 0
    session.write(b"more")  # still no error


def test_edge_close_drops_the_queue_and_frees_a_blocked_writer(session):
    proc = _BusyPty.last
    session.write(b"z" * 100_000)
    session.close()
    assert session.pending_input() == 0
    session.write(b"after close")
    assert session.pending_input() == 0
    assert proc.written == []
