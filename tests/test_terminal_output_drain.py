"""A terminal takes in everything its shell wrote at each poll, never waits
for output on the GUI thread, and draws the result once per poll.

Measured 2026-10-25 (scripts/ui_bench.py): ``cat`` of a 4 MiB file in a
terminal pane took 48.5 s and ``yes | head -200000`` 7.3 s - each 50 ms
poll read one 4 KiB piece and drew it (ui/terminal_pane.py ``_poll_output``,
ui/terminal_widget.py ``TerminalDock._poll_output``); and an idle shell
blocked the GUI thread 50 ms on every poll in ``select`` (the read's
timeout, ui/terminal_widget.py ``LocalTerminalSession.read``).
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtCore")
from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

# Module level, alive until the interpreter exits: a QApplication that only
# a fixture held was destroyed at the module's end with widget wrappers
# still alive - a segfault in sip's release_QApplication (seen once under
# load, core dump of 2026-10-25).
APP = QApplication.instance() or QApplication([])


@pytest.fixture(scope="module")
def app():
    return APP


def _pump(app, n=5):
    for _ in range(n):
        app.processEvents()


class FakeSession:
    """A shell that has *out* ready: read_ready hands it out piece by piece;
    the blocking read must not be used."""

    def __init__(self, out=()):
        self.out = list(out)
        self.written = b""
        self.sizes = []
        self.is_active = True
        self.ready_reads = 0
        self.blocking_reads = 0

    def start(self):
        pass

    def resize(self, rows, cols):
        self.sizes.append((rows, cols))

    def write(self, data):
        self.written += data

    def read(self, size=4096):
        # Not an exception: raised in a QTimer slot it aborts the process.
        self.blocking_reads += 1
        return self.out.pop(0) if self.out else b""

    def read_ready(self, size=4096):
        self.ready_reads += 1
        return self.out.pop(0) if self.out else b""

    def close(self):
        self.is_active = False


class OldStyleSession(FakeSession):
    """A session of the old protocol (an extension's, a test double): read()
    only, returning b"" when nothing is there."""

    read_ready = None

    def read(self, size=4096):
        return self.out.pop(0) if self.out else b""


_OPEN: list = []


@pytest.fixture(autouse=True)
def _shut_down_panes():
    """Every pane's poll timer stops, also when a test failed half-way."""
    yield
    while _OPEN:
        widget = _OPEN.pop()
        try:
            if hasattr(widget, "shutdown"):
                widget.shutdown()
            widget.close()
            widget.deleteLater()
        except RuntimeError:
            pass
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def _pane(app, monkeypatch, session):
    from ui import terminal_pane as TP

    monkeypatch.setattr(TP, "LocalTerminalSession", lambda cwd=None: session)
    pane = TP.TerminalPaneWidget()
    _OPEN.append(pane)
    pane.resize(700, 400)
    pane.show()
    _pump(app)
    return pane


def _count_renders(monkeypatch, terminal) -> list:
    calls = []
    original = terminal._render

    def counting(*args, **kwargs):
        calls.append(args)
        return original(*args, **kwargs)

    monkeypatch.setattr(terminal, "_render", counting)
    return calls


def _lines(text_edit):
    return [line.rstrip() for line in text_edit.toPlainText().split("\n")]


# -- happy ---------------------------------------------------------------------


def test_happy_one_poll_takes_everything_ready_and_draws_once(app, monkeypatch):
    chunks = [f"line {i}\r\n".encode() for i in range(40)]
    fake = FakeSession(chunks)
    pane = _pane(app, monkeypatch, fake)
    renders = _count_renders(monkeypatch, pane._terminal)
    pane._poll_output()
    assert fake.out == []  # nothing left for the next poll
    assert fake.blocking_reads == 0
    assert len(renders) == 1
    lines = _lines(pane._terminal)
    assert [f"line {i}" for i in range(40)] == [ln for ln in lines if ln.startswith("line")]
    assert pane._read_timer.interval() == 50  # drained: back to the idle interval
    pane.shutdown()


def test_happy_a_local_shell_is_read_without_waiting(monkeypatch):
    """read_ready asks select with a zero timeout; read() keeps its 50 ms."""
    from ui import terminal_widget as TW

    timeouts = []
    monkeypatch.setattr(TW.select, "select",
                        lambda r, w, x, timeout: (timeouts.append(timeout), ([], [], []))[1])
    session = TW.LocalTerminalSession()
    session._master_fd = 99
    session._running = True
    assert session.read_ready() == b""
    assert session.read() == b""
    assert timeouts == [0, 0.05]


def test_happy_the_dock_drains_its_tabs_and_draws_the_shown_one_once(app, monkeypatch):
    from ui.terminal_widget import TerminalDock

    dock = TerminalDock()
    _OPEN.append(dock)
    dock.resize(800, 400)
    dock.show()
    _pump(app)
    shown = FakeSession([f"a{i}\r\n".encode() for i in range(30)])
    hidden = FakeSession([f"b{i}\r\n".encode() for i in range(30)])
    dock._session_combo.addItem("two")
    dock._get_or_create_tab("Local Shell").session = shown
    dock._get_or_create_tab("two").session = hidden
    renders = _count_renders(monkeypatch, dock._terminal)
    activity = []
    dock.activity.connect(lambda: activity.append(1))
    dock._poll_output()
    assert shown.out == [] and hidden.out == []
    assert shown.blocking_reads == hidden.blocking_reads == 0
    assert len(renders) == 1
    assert len(activity) == 2  # one per tab with output, not one per piece
    assert "a29" in dock._terminal.toPlainText()
    assert "b0" not in dock._terminal.toPlainText()
    assert dock._tabs["two"].buffer.startswith("b0\r\nb1")
    dock._session_combo.setCurrentText("two")
    _pump(app)
    assert "b29" in dock._terminal.toPlainText()
    dock.shutdown()


# -- sad -----------------------------------------------------------------------


def test_sad_a_session_without_read_ready_is_read_with_read(app, monkeypatch):
    fake = OldStyleSession([b"old ", b"protocol\r\n"])
    pane = _pane(app, monkeypatch, fake)
    pane._poll_output()
    assert fake.out == []
    assert "old protocol" in pane._terminal.toPlainText()
    pane.shutdown()


def test_sad_a_session_that_ends_still_says_so(app, monkeypatch):
    fake = FakeSession([b"bye\r\n"])
    pane = _pane(app, monkeypatch, fake)
    pane._poll_output()
    fake.is_active = False
    pane._poll_output()
    assert "--- Session ended ---" in _lines(pane._terminal)
    assert not pane._read_timer.isActive()


def test_sad_the_cursor_report_still_goes_back_at_once(app, monkeypatch):
    fake = FakeSession(["café \x1b[6n".encode(), b"more\r\n"])
    pane = _pane(app, monkeypatch, fake)
    pane._poll_output()
    assert fake.written.endswith(b"R")
    assert "café" in pane._terminal.toPlainText()
    pane.shutdown()


# -- edge ----------------------------------------------------------------------


def test_edge_a_flood_leaves_the_rest_for_the_next_poll_which_comes_at_once(app, monkeypatch):
    from ui import terminal_widget as TW

    monkeypatch.setattr(TW, "OUTPUT_POLL_BUDGET_S", 0.0)  # every piece spends the budget
    fake = FakeSession([b"one\r\n", b"two\r\n", b"three\r\n"])
    pane = _pane(app, monkeypatch, fake)
    pane._poll_output()
    assert fake.out == [b"two\r\n", b"three\r\n"]
    assert pane._read_timer.interval() == 0  # more is waiting: poll again soon
    pane._poll_output()
    pane._poll_output()
    assert fake.out == []
    pane._poll_output()  # finds nothing
    assert pane._read_timer.interval() == 50
    assert [ln for ln in _lines(pane._terminal) if ln in ("one", "two", "three")] == [
        "one", "two", "three"]
    pane.shutdown()


def test_edge_a_character_split_between_two_pieces_of_one_poll_arrives_whole(app, monkeypatch):
    data = "日本".encode()
    fake = FakeSession([data[:2], data[2:4], data[4:] + b"\r\n"])
    pane = _pane(app, monkeypatch, fake)
    pane._poll_output()
    assert "日本" in _lines(pane._terminal)
    pane.shutdown()


def test_edge_drain_returns_what_it_took_and_nothing_when_nothing_is_ready():
    from ui.terminal_widget import drain_output

    got = []
    fake = FakeSession([b"ab", b"cde"])
    assert drain_output(fake, got.append) == (5, False)
    assert got == [b"ab", b"cde"]
    assert drain_output(fake, got.append) == (0, False)
    assert drain_output(FakeSession([b"x", b"y"]), got.append, budget_s=0.0) == (1, True)


def test_edge_the_drawn_document_equals_drawing_every_piece(app, monkeypatch):
    """Drawing once per poll shows what drawing after every piece showed."""
    from ui.terminal_widget import TerminalEmulator

    pieces = [f"row {i} {'x' * (i % 37)}\r\n".encode() for i in range(400)]
    pieces += [b"\x1b[2;3Hmid", b"\x1b[?1049h\x1b[Hfull", b"\x1b[?1049l$ "]
    fake = FakeSession(list(pieces))
    pane = _pane(app, monkeypatch, fake)
    pane._poll_output()
    reference = TerminalEmulator()
    _OPEN.append(reference)
    reference.resize(pane._terminal.size())
    reference.show()
    _pump(app)
    reference.attach_screen(type(reference.screen)(pane._terminal.screen.cols,
                                                   pane._terminal.screen.rows))
    for piece in pieces:
        reference.feed_bytes(piece)
    assert reference.toPlainText() == pane._terminal.toPlainText()
    assert (reference.textCursor().position()
            == pane._terminal.textCursor().position())
    pane.shutdown()


# -- e2e: a real shell in a real pty -----------------------------------------------


@pytest.mark.skipif(os.name != "posix", reason="needs a pty")
def test_e2e_a_real_shell_floods_and_every_line_arrives_in_large_polls(app, tmp_path):
    from ui.terminal_pane import TerminalPaneWidget

    pane = TerminalPaneWidget(cwd=str(tmp_path))
    _OPEN.append(pane)
    pane.resize(900, 600)
    pane.show()
    _pump(app)
    deadline = time.monotonic() + 20
    while not (pane._session and pane._session.is_active) and time.monotonic() < deadline:
        _pump(app)
    taken = []
    feed = pane._terminal.feed_bytes

    def counting(data, **kwargs):
        taken[-1] += len(data)
        return feed(data, **kwargs)

    pane._terminal.feed_bytes = counting
    poll = pane._poll_output

    def counted_poll():
        taken.append(0)
        poll()

    pane._read_timer.timeout.disconnect()
    pane._read_timer.timeout.connect(counted_poll)
    pane._session.write(b"seq 1 30000; echo DONE$((40+2))\n")
    deadline = time.monotonic() + 120
    while "DONE42" not in _lines(pane._terminal) and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.001)
    lines = _lines(pane._terminal)
    assert "DONE42" in lines
    numbers = [ln for ln in lines if ln.isdigit()]
    assert numbers[-1] == "30000"
    assert numbers == [str(n) for n in range(int(numbers[0]), 30001)]  # none lost, in order
    assert max(taken) > 4096  # the old poll took one 4 KiB piece
    pane.shutdown()
