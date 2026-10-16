"""Placeholder for a remote pane that came back from a saved session.

A restored layout never connects by itself: a file pane or a terminal of a
saved connection profile comes back as this placeholder, in its old place,
with a Reconnect button. Reconnect hands the profile to the main window,
which connects it exactly like opening the profile does.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

#: The two kinds of pane a placeholder can stand for.
KIND_PANE = "pane"
KIND_TERMINAL = "terminal"


class DisconnectedPanePlaceholder(QWidget):
    """Stands in for a remote file pane (``kind="pane"``) or a profile
    terminal (``kind="terminal"``) until the user reconnects it."""

    reconnect_requested = pyqtSignal()
    close_requested = pyqtSignal()

    def __init__(
        self,
        kind: str,
        profile_name: str,
        path: str = "",
        *,
        profile_known: bool = True,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        if kind not in (KIND_PANE, KIND_TERMINAL):
            raise ValueError(f"unknown placeholder kind: {kind!r}")
        self.kind = kind
        self.profile_name = profile_name
        self.path = path
        self.setMinimumWidth(220)
        self.setMinimumHeight(120)

        frame = QFrame(self)
        frame.setFrameShape(QFrame.Shape.Box)
        frame.setObjectName("axPaneBorder")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(frame)

        layout = QVBoxLayout(frame)
        header = QHBoxLayout()
        # Plain text: the profile name and the path come from session.json
        # and must never be read as rich text.
        self._title = QLabel(f"Not connected — {profile_name}")
        self._title.setTextFormat(Qt.TextFormat.PlainText)
        font = self._title.font()
        font.setBold(True)
        self._title.setFont(font)
        header.addWidget(self._title)
        header.addStretch()
        close_btn = QPushButton("✕")  # ✕
        close_btn.setFixedSize(22, 22)
        close_btn.setToolTip("Close this pane")
        close_btn.clicked.connect(self.close_requested.emit)
        header.addWidget(close_btn)
        layout.addLayout(header)

        what = "Terminal" if kind == KIND_TERMINAL else "Folder"
        detail = f"{what}: {path}" if path else what
        self._detail = QLabel(detail)
        self._detail.setTextFormat(Qt.TextFormat.PlainText)
        self._detail.setWordWrap(True)
        layout.addWidget(self._detail)

        self._note = QLabel("")
        self._note.setTextFormat(Qt.TextFormat.PlainText)
        self._note.setWordWrap(True)
        layout.addWidget(self._note)
        if not profile_known:
            self.set_note(f"The profile '{profile_name}' no longer exists.")

        self.reconnect_button = QPushButton("Reconnect")
        self.reconnect_button.setToolTip(f"Connect '{profile_name}' and open it here")
        self.reconnect_button.clicked.connect(self.reconnect_requested.emit)
        row = QHBoxLayout()
        row.addStretch()
        row.addWidget(self.reconnect_button)
        row.addStretch()
        layout.addStretch()
        layout.addLayout(row)
        layout.addStretch()

    def title_text(self) -> str:
        return self._title.text()

    def set_note(self, text: str) -> None:
        self._note.setText(text)

    def serialize(self) -> dict:
        """The session entry of the pane this placeholder stands for, so a
        layout saved before reconnecting still holds it."""
        if self.kind == KIND_TERMINAL:
            return {"type": "terminal", "profile": self.profile_name}
        return {"type": "pane", "profile": self.profile_name, "path": self.path or "/"}


__all__ = ["KIND_PANE", "KIND_TERMINAL", "DisconnectedPanePlaceholder"]
