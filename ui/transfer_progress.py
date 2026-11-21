"""A running copy or move, in sight while the Transfers dock is closed.

Copying a folder of many small files made its folders at the destination
at once and the files over minutes; with the Transfers dock closed nothing
said that the copy was still going, and it looked as if the files were
lost. :class:`TransferProgress` keeps, while copies or moves run:

* a permanent item in the window's status bar - "Preparing: 3,210 files
  queued…", then "Copying 1,210 of 10,000 files – 12 %"; a click opens the
  Transfers dock at the running transfer. When the last one ends it goes,
  and the summary the window shows anyway ("10,000 copied") stays;
* the destination pane's status line - "Copy in progress: 1,210 of 10,000"
  with a thin bar (ui.file_pane.FilePaneWidget.show_transfer_progress).

Updates come from a timer, about 4 a second, never from a signal per file:
a file's end only bumps a counter.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from PyQt6.QtCore import QObject, Qt, QTimer
from PyQt6.QtWidgets import QPushButton

from core.i18n import format_count, format_percent, tr, tr_n
from core.transfer_worker import TransferStatus

log = logging.getLogger(__name__)

#: How often the status bar item and the panes are brought up to date.
INTERVAL_MS = 250
#: The status bar item drawn as text (see TransferProgress.__init__).
STATUS_ITEM_CSS = ("QPushButton { border: none; background: transparent; padding: 0 6px; }\n"
                   "QPushButton:hover { text-decoration: underline; }")


@dataclass(eq=False)
class TransferOperation:
    """One copy or move of the window (F5 / F6 / a drop / Paste ...)."""

    target: object  # the destination pane
    move: bool
    walk: object = None  # core.transfer_manager.TransferWalk, while it walks
    walked: bool = False  # its jobs are known
    total: int = 0  # jobs (files, links, refused rows)
    ended: int = 0
    failed: int = 0
    bytes_total: int = 0
    bytes_done: int = 0
    active: set = field(default_factory=set)  # ids of its running jobs

    @property
    def finished(self) -> bool:
        return self.walked and self.ended >= self.total


def _plain(text: str) -> str:
    """*text* for a QPushButton: a "&" stays a "&"."""
    return text.replace("&", "&&")


class TransferProgress(QObject):
    """See the module docstring. *open_dock* shows the Transfers dock."""

    def __init__(self, window, manager, open_dock: Callable[[], None]) -> None:
        super().__init__(window)
        self._window = window
        self._manager = manager
        self._ops: list[TransferOperation] = []
        self._by_job: dict[str, TransferOperation] = {}
        #: Panes that show a running transfer now (to hide it again).
        self._showing: set = set()
        self.button = QPushButton()
        self.button.setObjectName("axTransferProgress")
        self.button.setFlat(True)
        # Text height, as the version item beside it, not a push button's:
        # QStatusBar takes the height of every permanent widget, a hidden
        # one too - a plain button made the bar 9 px taller for good, and
        # the panes lost that height (a split refused: "no room").
        self.button.setStyleSheet(STATUS_ITEM_CSS)
        self.button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.button.setToolTip(tr("Copies and moves are still running – click to see them in Transfers"))
        self.button.clicked.connect(lambda _checked=False: open_dock())
        self.button.hide()
        window.statusBar().insertPermanentWidget(0, self.button)
        self._timer = QTimer(self)
        self._timer.setInterval(INTERVAL_MS)
        self._timer.timeout.connect(self.refresh)
        manager.job_started.connect(self._on_started)
        manager.job_finished.connect(self._on_ended)
        manager.job_error.connect(self._on_ended)

    # -- the operations -------------------------------------------------------

    def begin(self, target, move: bool, walk=None) -> TransferOperation:
        """A copy or move into *target*'s pane was queued; *walk* is its
        background walk (TransferManager.transfer_files_in_background)."""
        op = TransferOperation(target=target, move=move, walk=walk)
        self._ops.append(op)
        if not self._timer.isActive():
            self._timer.start()
        QTimer.singleShot(0, self.refresh)  # shown now, not after the first tick
        return op

    def walked(self, op: TransferOperation, jobs) -> None:
        """The walk of *op* made *jobs* (they are registered, none has
        ended - the workers get them after this)."""
        op.walk = None
        op.walked = True
        op.total = len(jobs)
        for job in jobs:
            op.bytes_total += max(int(job.total_bytes or 0), 0)
            if hasattr(job, "error_context"):
                # A refused row (a folder that could not be read): it never
                # runs, and its error was signalled before this.
                op.ended += 1
                op.failed += 1
            else:
                # Its end is signalled after this, even when a worker has
                # already set its status (the signals are queued).
                self._by_job[job.job_id] = op
        self.refresh()

    def _on_started(self, job_id: str) -> None:
        op = self._by_job.get(job_id)
        if op is not None:
            op.active.add(job_id)

    def _on_ended(self, job_id: str, _error: str = "") -> None:
        op = self._by_job.pop(job_id, None)
        if op is None:
            return
        op.active.discard(job_id)
        op.ended += 1
        job = self._manager.get_job(job_id)
        if job is not None:
            op.bytes_done += max(int(job.total_bytes or 0), 0)
            if job.status is not TransferStatus.DONE:
                op.failed += 1
        if op.finished:
            QTimer.singleShot(0, self.refresh)  # gone at once, not a tick later

    # -- what is shown ----------------------------------------------------------

    def _percent(self, op: TransferOperation) -> int:
        done = op.bytes_done
        for job_id in op.active:
            job = self._manager.get_job(job_id)
            if job is not None:
                done += min(max(int(job.transferred_bytes or 0), 0),
                            max(int(job.total_bytes or 0), 0))
        if op.bytes_total > 0:
            value = done * 100 // op.bytes_total
        else:
            value = op.ended * 100 // op.total if op.total else 0
        return max(0, min(100 if op.finished else 99, int(value)))

    def text(self) -> str:
        """The status bar item's text now, "" when nothing runs."""
        ops = [op for op in self._ops if not op.finished]
        if not ops:
            return ""
        walking = [op for op in ops if not op.walked]
        if walking:
            from ui.transfer_dock import preparing_text

            state = self._manager.preparing() if hasattr(self._manager, "preparing") else None
            queued, total = state if state is not None else (0, None)
            return preparing_text(queued, total)
        done = sum(op.ended for op in ops)
        total = sum(op.total for op in ops)
        size = sum(op.bytes_total for op in ops)
        if size > 0:
            moved = 0
            for op in ops:
                moved += self._percent(op) * op.bytes_total
            percent = moved // size
        else:
            percent = done * 100 // total if total else 0
        fields = {"done": format_count(done), "count": format_count(total),
                  "percent": format_percent(percent)}
        if all(op.move for op in ops):
            return tr_n(total, "Moving {done} of {count} file – {percent}",
                        "Moving {done} of {count} files – {percent}", **fields)
        if not any(op.move for op in ops):
            return tr_n(total, "Copying {done} of {count} file – {percent}",
                        "Copying {done} of {count} files – {percent}", **fields)
        return tr_n(total, "Transferring {done} of {count} file – {percent}",
                    "Transferring {done} of {count} files – {percent}", **fields)

    def _pane_text(self, ops: list[TransferOperation]) -> tuple[str, int | None]:
        moving = all(op.move for op in ops)
        if any(not op.walked for op in ops):
            return (tr("Move in progress: preparing…") if moving
                    else tr("Copy in progress: preparing…")), None
        done = sum(op.ended for op in ops)
        total = sum(op.total for op in ops)
        size = sum(op.bytes_total for op in ops)
        percent = (sum(self._percent(op) * op.bytes_total for op in ops) // size if size
                   else (done * 100 // total if total else 0))
        fields = {"done": format_count(done), "count": format_count(total)}
        text = (tr("Move in progress: {done} of {count}") if moving
                else tr("Copy in progress: {done} of {count}")).format(**fields)
        return text, percent

    def refresh(self) -> None:
        """Bring the status bar item and the panes up to date; stop the
        timer once nothing runs."""
        self._ops = [op for op in self._ops if not op.finished]
        panes = getattr(self._window, "_panes", [])
        by_pane: dict = {}
        for op in self._ops:
            if op.target in panes:
                by_pane.setdefault(op.target, []).append(op)
        for pane in list(self._showing):
            if pane not in by_pane:
                self._showing.discard(pane)
                if pane in panes:
                    pane.show_transfer_progress("")
        for pane, ops in by_pane.items():
            text, percent = self._pane_text(ops)
            show = getattr(pane, "show_transfer_progress", None)
            if callable(show):
                show(text, percent)
                self._showing.add(pane)
        text = self.text()
        if text:
            if self.button.text() != _plain(text):
                self.button.setText(_plain(text))
            self.button.show()
        else:
            self.button.hide()
            self.button.setText("")
            self._timer.stop()

    def running(self) -> bool:
        """A tracked copy or move has not ended."""
        return any(not op.finished for op in self._ops)
