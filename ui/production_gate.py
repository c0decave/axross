"""The production tarpit for the file pane's destructive entries.

A profile flagged ``production`` promises a short countdown before the
first destructive operation of a session (core.safety_tarpit), and the
profile's documentation says the GUI's right-click entries honour it. Only
the scripting verbs did: Delete, Rename, Move, Change Permissions and Move
to Trash in a pane went straight through.

:func:`confirm_production` is the GUI gate. It shows a countdown dialog
(Esc or Cancel stops the operation, the countdown running out lets it
proceed) the first time per connection session, and records the toll in
the same per-session state core.safety_tarpit keeps for scripts.
"""

from __future__ import annotations

import logging
import time

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QProgressBar,
    QVBoxLayout,
    QWidget,
)

from core.safety_tarpit import DEFAULT_COUNTDOWN_S, arm_fired, profile_label, should_arm
from ui.close_corner import add_close_corner

log = logging.getLogger(__name__)

#: Progress bar steps per second of countdown.
_TICKS_PER_S = 10


class ProductionCountdownDialog(QDialog):
    """"This is production" with a countdown: accepted when it runs out,
    rejected by Esc or Cancel."""

    def __init__(
        self, label: str, op_desc: str, seconds: float, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Production profile")
        self._seconds = max(0.0, float(seconds))
        self._deadline = 0.0
        layout = QVBoxLayout(self)
        text = QLabel(
            f"<b>{_escape(label)}</b> is marked as production.<br><br>"
            f"About to: {_escape(op_desc)}<br><br>"
            "Press Esc or Cancel to stop. The operation goes ahead when the "
            "countdown ends.",
            self,
        )
        text.setWordWrap(True)
        layout.addWidget(text)
        self._bar = QProgressBar(self)
        self._bar.setRange(0, max(1, int(self._seconds * _TICKS_PER_S)))
        self._bar.setTextVisible(False)
        layout.addWidget(self._bar)
        self._remaining = QLabel(self)
        layout.addWidget(self._remaining)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel, self)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self._timer = QTimer(self)
        self._timer.setInterval(int(1000 / _TICKS_PER_S))
        self._timer.timeout.connect(self._tick)
        add_close_corner(self)  # [x] rejects, like Esc and Cancel

    def exec(self) -> int:  # noqa: D102 - QDialog.exec with the countdown started
        self._deadline = time.monotonic() + self._seconds
        self._tick()
        self._timer.start()
        try:
            return super().exec()
        finally:
            self._timer.stop()

    def _tick(self) -> None:
        left = self._deadline - time.monotonic()
        if left <= 0:
            self._timer.stop()
            self.accept()
            return
        self._bar.setValue(int((self._seconds - left) * _TICKS_PER_S))
        self._remaining.setText(f"{left:.1f} s")


def _escape(text: str) -> str:
    from html import escape

    return escape(str(text))


def confirm_production(
    parent: QWidget | None,
    backend,
    op_desc: str,
    *,
    countdown_s: float = DEFAULT_COUNTDOWN_S,
) -> bool:
    """Whether a destructive *op_desc* on *backend* may go ahead.

    True at once for a backend without a production profile, with the
    tarpit disabled (``AXROSS_TARPIT_DISABLE=1``), or when the toll was
    already paid in this connection session; otherwise the countdown
    dialog decides.
    """
    profile = getattr(backend, "_axross_profile", None)
    if profile is None:
        return True
    session_id = str(getattr(backend, "_axross_profile_key", "") or f"pane:{id(backend)}")
    if not should_arm(profile, session_id):
        return True
    label = profile_label(profile)
    log.warning("production_gate ARMED (GUI) target=%s op=%r", label, op_desc)
    dialog = ProductionCountdownDialog(label, op_desc, countdown_s, parent)
    if dialog.exec() != QDialog.DialogCode.Accepted:
        log.info("production_gate: %r on %s stopped by the user", op_desc, label)
        return False
    arm_fired(profile, session_id)
    return True


__all__ = ["ProductionCountdownDialog", "confirm_production"]
