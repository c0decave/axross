"""The Markdown window's responsiveness as its user sees it: a heartbeat on the GUI thread.

A QTimer ticks every few milliseconds on the GUI thread while something is done (a document opened and
laid out, an export, a zoom). Two things are measured between two ticks:

- the GUI thread's own CPU time (``turn``) - what the window itself spends in one event-loop turn;
- the wall-clock time (``gap``) - how long the window did not answer, whatever held it.

The second catches what the first cannot: a worker thread that holds Python's lock (the GIL) in one long
C call - a regular expression's search, which never lets it go - freezes the window although the GUI
thread spends no CPU time at all (review 23's N1: a line of 1,200 backticks in a big file, the window
frozen 12.6 s while the per-turn CPU meter read 0.08 s). Every stress test that measures turns measures
the gap too (tests/test_markdown_reader_bugs20.py's _Turns, bugs16/17/18's Turns, bugs22's within_turn):
over GAP the test fails.
"""

from __future__ import annotations

import time

#: The longest wall-clock gap between two heartbeats a stress test allows, in seconds, on the machine the
#: budgets were measured on (as much longer on a slower one: gap_budget). Above the 0.1 s a turn may take:
#: what else the machine does (a second pytest beside it: 0.32 s once) can delay a tick, never by seconds -
#: a lock held by a worker does, a wait for a child process does.
GAP = 0.5
#: Every heartbeat stopped since the last look: (gap, turn) - for the assertions after the measure.
STOPPED: list[tuple[float, float]] = []


#: What Qt took to lay out the calibration page on the machine the budgets were measured on (as
#: tests/test_markdown_reader_bugs22.py's CALIBRATION_SECONDS).
CALIBRATION_SECONDS = 0.014
_FACTOR: list[float] = []


def machine_factor() -> float:
    """How much slower than the calibration machine this one lays out a page - 1 to 3 (measured once: the
    least of five layouts of the same page, as bugs22's machine_factor)."""
    if not _FACTOR:
        from PyQt6.QtGui import QTextDocument

        text = "\n\n".join(f"Paragraph {n} with *some* `code`, **strong** words and [a link](x)." for n in range(600))
        took = []
        for _ in range(5):
            document = QTextDocument()
            began = time.thread_time()
            document.setMarkdown(text)
            document.setTextWidth(800)
            document.documentLayout().documentSize()
            took.append(time.thread_time() - began)
        _FACTOR.append(min(3.0, max(1.0, min(took) / CALIBRATION_SECONDS)))
    return _FACTOR[0]


def gap_budget() -> float:
    """GAP on this machine: as much longer as it lays out a page more slowly (machine_factor)."""
    return GAP * machine_factor()


class Heartbeat:
    """A heartbeat on the GUI thread (a QTimer of *interval* ms) from now to stop(): the longest turn
    (the GUI thread's CPU time between two ticks) and the longest gap (the wall-clock time between them -
    and from the last tick to stop())."""

    def __init__(self, interval: int = 5):
        from PyQt6.QtCore import QTimer

        self.cpu, self.wall = time.thread_time(), time.monotonic()
        self.turn = self.gap = 0.0
        self.turns: list[float] = []
        self.timer = QTimer()
        self.timer.setInterval(interval)
        self.timer.timeout.connect(self._beat)
        self.timer.start()

    def _beat(self) -> None:
        cpu, wall = time.thread_time(), time.monotonic()
        self.turns.append(cpu - self.cpu)
        self.turn = max(self.turn, cpu - self.cpu)
        self.gap = max(self.gap, wall - self.wall)
        self.cpu, self.wall = cpu, wall

    def stop(self) -> tuple[float, float]:
        """(the longest turn, the longest gap) - the heartbeat stopped."""
        if self.timer.isActive():
            self.timer.stop()
            self.gap = max(self.gap, time.monotonic() - self.wall)
            STOPPED.append((self.gap, self.turn))
        return self.turn, self.gap


#: While above 0, assert_responsive only records (a measure that is asked again when it fails: within_turn).
DEFERRED = [0]


def assert_responsive(gap: float, label=None) -> None:
    """*gap* (a heartbeat's longest) within gap_budget() - else the window froze, what held it aside. Not
    while a caller measures again before it judges (DEFERRED: bugs22's within_turn)."""
    if DEFERRED[0]:
        return
    budget = gap_budget()
    assert gap < budget, (label, f"the window did not answer for {gap:.3f} s (at most {budget:.3f} s)")


def gaps_since(mark: int) -> float:
    """The longest gap of the heartbeats stopped since STOPPED had *mark* entries."""
    return max((gap for gap, _turn in STOPPED[mark:]), default=0.0)
