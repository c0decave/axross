"""A small window above the main window that counts what the agent does."""

from __future__ import annotations

import time

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QGridLayout, QLabel, QPushButton, QVBoxLayout, QWidget

EXTENSION = {
    "name": "Agent Stats",
    "version": "1.0",
    "description": "A small window, on top and movable anywhere, with what the agent did: "
    "tasks, answers, tool calls, errors, declined calls, tokens and time - for all tabs and "
    "for the tab that ran last.",
    "author": "axross",
}

#: (key, label) of the numbers the window shows, in order.
FIELDS = (
    ("runs", "Tasks"),
    ("answers", "Answers"),
    ("tool_calls", "Tool calls"),
    ("errors", "Errors"),
    ("declined", "Declined"),
    ("prompt_tokens", "Tokens in"),
    ("completion_tokens", "Tokens out"),
    ("seconds", "Time (s)"),
)

WINDOW = None


class AgentStats:
    """The counts, from the agent's events (Qt-free)."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.total = dict.fromkeys((k for k, _label in FIELDS), 0)
        self.per_session: dict[str, dict] = {}
        self.last_session = ""
        self.running: set[str] = set()
        self._started: dict[str, float] = {}

    def add(self, session: str, event: dict) -> None:
        mine = self.per_session.setdefault(session, dict.fromkeys(self.total, 0))
        self.last_session = session
        kind = event.get("type")
        bumps: dict[str, float] = {}
        if kind == "run_started":
            bumps["runs"] = 1
            self.running.add(session)
            self._started[session] = time.monotonic()
        elif kind == "assistant":
            bumps["answers"] = 1
        elif kind == "tool_call":
            bumps["tool_calls"] = 1
        elif kind == "tool_result":
            outcome = event.get("outcome")
            if outcome in ("error", "unavailable"):
                bumps["errors"] = 1
            elif outcome == "declined":
                bumps["declined"] = 1
        elif kind == "usage":
            for key in ("prompt_tokens", "completion_tokens"):
                if isinstance(event.get(key), int):
                    bumps[key] = event[key]
        elif kind == "run_finished":
            self.running.discard(session)
            started = self._started.pop(session, None)
            seconds = event.get("seconds")
            if not isinstance(seconds, (int, float)):
                seconds = time.monotonic() - started if started else 0
            bumps["seconds"] = round(float(seconds), 1)
            if event.get("error"):
                bumps["errors"] = 1
        for key, value in bumps.items():
            mine[key] += value
            self.total[key] += value


class StatsWindow(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        # A normal window owned by the main window: it stays above it, has
        # the usual title bar buttons, and a tiling window manager floats it
        # at its own size (sway tiled the old parentless Tool window across
        # half the screen).
        super().__init__(parent, Qt.WindowType.Window)
        self.setWindowTitle("Agent Stats")
        self.setObjectName("axAgentStats")
        self.counts = AgentStats()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        self.state = QLabel("Idle")
        layout.addWidget(self.state)
        grid = QGridLayout()
        grid.addWidget(QLabel(""), 0, 0)
        grid.addWidget(QLabel("All"), 0, 1)
        grid.addWidget(QLabel("Last tab"), 0, 2)
        self._labels: dict[str, tuple[QLabel, QLabel]] = {}
        for row, (key, label) in enumerate(FIELDS, start=1):
            total, last = QLabel("0"), QLabel("0")
            for widget in (total, last):
                widget.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            grid.addWidget(QLabel(label), row, 0)
            grid.addWidget(total, row, 1)
            grid.addWidget(last, row, 2)
            self._labels[key] = (total, last)
        layout.addLayout(grid)
        reset = QPushButton("Reset")
        reset.clicked.connect(self.reset)
        layout.addWidget(reset)
        self.resize(self.sizeHint())

    def add(self, session: str, event: dict) -> None:
        self.counts.add(session, event)
        self.refresh()

    def reset(self) -> None:
        self.counts.reset()
        self.refresh()

    def refresh(self) -> None:
        last = self.counts.per_session.get(self.counts.last_session, {})
        for key, (total, mine) in self._labels.items():
            total.setText(_number(self.counts.total[key]))
            mine.setText(_number(last.get(key, 0)))
        running = len(self.counts.running)
        self.state.setText(
            f"Running: {running} tab{'s' if running != 1 else ''}" if running else "Idle"
        )

    def stats(self) -> dict:
        return dict(self.counts.total)


def _number(value) -> str:
    return f"{value:g}" if isinstance(value, float) else str(value)


def activate(api):
    global WINDOW
    WINDOW = StatsWindow(api.window)

    def toggle():
        if WINDOW.isVisible():
            WINDOW.hide()
        else:
            WINDOW.show()
            WINDOW.raise_()

    api.add_menu_action("Agent Stats", toggle)
    api.on_agent_event(WINDOW.add)


def deactivate(api):
    global WINDOW
    if WINDOW is not None:
        WINDOW.close()
        WINDOW.deleteLater()
        WINDOW = None
