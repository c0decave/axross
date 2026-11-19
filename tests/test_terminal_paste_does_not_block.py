"""A large paste into a busy local shell never blocks the window.

Reproduced 2026-11-19 (independent review): ``LocalTerminalSession.write``
was one blocking ``os.write`` on the pty master. With the shell busy (not
reading) a 200 KB paste filled the pty buffer and the GUI thread waited
until the shell read again - six seconds in the repro, for ever with a
program that never reads. Now the master is non-blocking: what does not
fit waits in a bounded queue, drained whenever the pty takes more (a
QSocketNotifier, and every output poll).
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("pty")
pytest.importorskip("PyQt6.QtWidgets")
from PyQt6.QtWidgets import QApplication  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def _wait_for(session, marker: bytes, app=None, timeout=10.0) -> bytes:
    seen = b""
    deadline = time.monotonic() + timeout
    while marker not in seen and time.monotonic() < deadline:
        if app is not None:
            app.processEvents()
        seen += session.read()
    assert marker in seen, seen[-300:]
    return seen


@pytest.fixture
def session(monkeypatch):
    from ui.terminal_widget import LocalTerminalSession

    monkeypatch.setenv("SHELL", "/bin/sh")
    s = LocalTerminalSession()
    s.start()
    yield s
    s.close()


def test_sad_a_paste_into_a_busy_shell_returns_at_once(session):
    session.write(b"stty raw -echo; echo REA''DY; sleep 30\n")
    _wait_for(session, b"READY")
    started = time.monotonic()
    session.write(b"x" * 200_000)
    assert time.monotonic() - started < 1.0


def test_happy_the_queued_rest_reaches_the_shell(app, session, tmp_path):
    out = tmp_path / "pasted"
    session.write(f"stty raw -echo; echo REA''DY; head -c 200000 > {out}; echo DO''NE\n".encode())
    _wait_for(session, b"READY", app)
    session.write(b"y" * 200_000)
    _wait_for(session, b"DONE", app, timeout=20.0)
    assert out.read_bytes() == b"y" * 200_000


def test_edge_the_queue_is_bounded(session, monkeypatch, caplog):
    """A paste beyond the cap is cut there (and says so) rather than
    taking memory without limit while the shell does not read."""
    import ui.terminal_widget as tw

    monkeypatch.setattr(tw, "PTY_WRITE_QUEUE_CAP", 64 * 1024)
    session.write(b"stty raw -echo; echo REA''DY; sleep 30\n")
    _wait_for(session, b"READY")
    with caplog.at_level("WARNING", logger="ui.terminal_widget"):
        session.write(b"z" * 2_000_000)
    assert session.pending_input() <= 64 * 1024
    assert "dropped" in caplog.text


def test_edge_close_with_input_still_queued_is_clean(session):
    session.write(b"stty raw -echo; echo REA''DY; sleep 30\n")
    _wait_for(session, b"READY")
    session.write(b"w" * 500_000)
    assert session.pending_input() > 0
    session.close()
    assert session.pending_input() == 0
    session.write(b"more")  # after close: nothing, no error
