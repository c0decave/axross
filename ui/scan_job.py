"""Run a long walk / hashing job off the UI thread, with progress and cancel.

Dialogs that used to block on a synchronous walk (Duplicate Finder,
metadata index) use :class:`ScanJob` for the thread and
:class:`BusyStrip` for the one status line at the bottom: an
indeterminate bar, "Working… N indexed, M scanned — <path>" and a
Cancel button. Esc / Close / the window's X call :meth:`ScanJob.abandon`,
so a running scan never outlives its dialog.

The worker thread only writes to a plain dict; every widget is touched
from the UI thread by a polling timer.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

from PyQt6.QtCore import QObject, QTimer, pyqtSignal
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QProgressBar, QPushButton, QWidget

Work = Callable[[Callable[[], bool], Callable[[int, int, str], None]], Any]


def shorten(text: str, limit: int = 70) -> str:
    return text if len(text) <= limit else "…" + text[-(limit - 1) :]


class ScanJob(QObject):
    """One background job at a time.

    *work* receives ``(cancel, progress)``: ``cancel()`` is true once a stop
    was requested, ``progress(scanned, indexed, path)`` reports headway.
    ``finished(kind, value, cancelled)`` fires in the UI thread with kind
    ``"done"`` (value = the work's return value) or ``"error"`` (value =
    the exception); not at all after :meth:`abandon`.
    """

    started = pyqtSignal()
    progress = pyqtSignal(str)
    finished = pyqtSignal(str, object, bool)

    def __init__(
        self,
        parent: QObject | None = None,
        interval_ms: int = 150,
        formatter: Callable[[dict], str] | None = None,
    ) -> None:
        """*formatter* turns the progress state (``scanned``, ``indexed``,
        ``path``) into the status text; the default speaks of files."""
        super().__init__(parent)
        self._formatter = formatter
        self._cancel = threading.Event()
        self._state: dict = {}
        self._thread: threading.Thread | None = None
        self._timer = QTimer(self)
        self._timer.setInterval(interval_ms)
        self._timer.timeout.connect(self._poll)

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() or self._timer.isActive()

    @property
    def cancelling(self) -> bool:
        return self._cancel.is_set()

    def start(self, work: Work) -> bool:
        """Start *work*; ``False`` when a job is already running."""
        if self.running and not self._cancel.is_set():
            return False
        cancel = threading.Event()
        state: dict = {"scanned": 0, "indexed": 0, "path": "", "result": None}
        self._cancel, self._state = cancel, state

        def report(scanned: int, indexed: int, current: str) -> None:
            state["scanned"], state["indexed"], state["path"] = scanned, indexed, current

        def run() -> None:
            try:
                state["result"] = ("done", work(cancel.is_set, report))
            except Exception as exc:  # noqa: BLE001 — handed to the UI thread
                state["result"] = ("error", exc)

        self._thread = threading.Thread(target=run, name="scan-job", daemon=True)
        self.started.emit()
        self._thread.start()
        self._timer.start()
        return True

    def cancel(self) -> None:
        """Stop the job; ``finished`` still fires (cancelled=True)."""
        if self._thread is not None and self._thread.is_alive():
            self._cancel.set()

    def abandon(self) -> None:
        """Stop the job and drop its result (the owner is going away)."""
        self._cancel.set()
        self._timer.stop()

    def _poll(self) -> None:
        state = self._state
        result = state.get("result")
        if result is None:
            if self._cancel.is_set():
                self.progress.emit("Cancelling…")
            else:
                self.progress.emit(
                    self._formatter(state)
                    if self._formatter is not None
                    else f"Working… {state['indexed']} indexed, {state['scanned']} scanned"
                    f" — {shorten(state['path'])}"
                )
            return
        self._timer.stop()
        self.finished.emit(result[0], result[1], self._cancel.is_set())


class BusyStrip(QWidget):
    """The status line: bar + text + Cancel, hidden while no job runs."""

    def __init__(
        self, job: ScanJob, parent: QWidget | None = None, cancel_text: str = "Cancel scan"
    ) -> None:
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.bar = QProgressBar(self)
        self.bar.setRange(0, 0)  # indeterminate: the total is unknown
        self.bar.setTextVisible(False)
        self.bar.setFixedWidth(120)
        layout.addWidget(self.bar)
        self.label = QLabel("", self)
        self.label.setProperty("role", "muted")
        layout.addWidget(self.label, stretch=1)
        self.cancel_button = QPushButton(cancel_text, self)
        self.cancel_button.setToolTip("Stop what is running")
        self.cancel_button.clicked.connect(job.cancel)
        layout.addWidget(self.cancel_button)
        job.started.connect(self._on_started)
        job.progress.connect(self.label.setText)
        job.progress.connect(self._on_progress)
        job.finished.connect(self._on_finished)
        self._set_busy(False)

    def _set_busy(self, busy: bool) -> None:
        for w in (self.bar, self.label, self.cancel_button):
            w.setVisible(busy)

    def _on_started(self) -> None:
        self.label.setText("Working… scanning")
        self.cancel_button.setEnabled(True)
        self._set_busy(True)

    def _on_progress(self, text: str) -> None:
        if text.startswith("Cancelling"):
            self.cancel_button.setEnabled(False)

    def _on_finished(self, *_args) -> None:
        self._set_busy(False)


__all__ = ["BusyStrip", "ScanJob", "shorten"]
