"""Transfer dock widget — shows transfer queue with progress."""

from __future__ import annotations

import logging

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QDockWidget,
    QHBoxLayout,
    QLabel,
    QMenu,
    QProgressBar,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from core.i18n import percent_sign, tr, tr_n
from core.transfer_manager import TransferManager
from core.transfer_worker import TransferJob, TransferStatus
from models.transfer_model import COL_PROGRESS, ProgressBarDelegate, TransferModel
from ui.dock_frame import framed
from ui.icon_provider import set_window_icon

log = logging.getLogger(__name__)

#: Rows the column fit measures (see TransferDock._setup_ui).
TABLE_FIT_ROWS = 100
#: The overall bar is recomputed at most this often while jobs change.
OVERALL_INTERVAL_MS = 250


class _OverallBar(QProgressBar):
    """The overall progress bar; a click on it shows the current transfer."""

    clicked = pyqtSignal()
    HINT = "Click to show the transfer running now"

    def __init__(self) -> None:
        super().__init__()
        self.HINT = tr(type(self).HINT)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setAccessibleName(tr("Overall progress (click: show current transfer)"))
        self.setToolTip(self.HINT)

    def setToolTip(self, text: str) -> None:  # noqa: N802 - Qt name
        super().setToolTip(f"{text}\n{self.HINT}" if text and text != self.HINT else self.HINT)

    def mouseReleaseEvent(self, event) -> None:  # noqa: N802 - Qt name
        if event.button() == Qt.MouseButton.LeftButton and self.rect().contains(
                event.position().toPoint()):
            self.clicked.emit()
        super().mouseReleaseEvent(event)


class TransferDock(QDockWidget):
    """Dockable panel showing file transfer progress."""

    # Fires on every transfer-state change (add / update / error /
    # finish). MainWindow uses this to highlight the dock's tab when
    # it's not the currently-raised tab, so background transfers
    # don't stay invisible to the user.
    activity = pyqtSignal()
    #: True when the queue became empty (the dock shows one short row: the
    #: window shrinks its area then), False when a job arrived.
    idle_changed = pyqtSignal(bool)

    def __init__(self, transfer_manager: TransferManager, parent: QWidget | None = None):
        super().__init__(tr("Transfers"), parent)
        set_window_icon(self, "download")
        self._manager = transfer_manager

        self.setAllowedAreas(
            Qt.DockWidgetArea.BottomDockWidgetArea | Qt.DockWidgetArea.TopDockWidgetArea
        )

        self._model = TransferModel()
        #: Jobs added since the queue was last idle: the overall bar is the
        #: progress of this batch, finished jobs included (it counted only
        #: the running and waiting ones, so it fell back whenever a job
        #: finished).
        self._batch: set[str] = set()
        #: Bytes of this batch's done jobs the manager has dropped from its
        #: list (core.transfer_manager.MAX_DONE_KEPT): still part of the bar.
        self._batch_dropped = 0
        #: (failed, cancelled) of the last batch once it ended: the bar
        #: keeps saying so until the next batch or Clear Finished.
        self._ended_badly = (0, 0)
        self._idle = False
        #: The window checks a copy for conflicts (note_preparing).
        self._preparing = False
        self._setup_ui()
        self._set_idle(True)
        # The model starts empty: nothing to retry, cancel or clear yet.
        self._sync_buttons([])

        # Connect manager signals
        # The overall bar walks every job; recompute it once per burst of
        # signals instead of once per signal (10 000 queued files spent
        # ~14 s of GUI time here).
        self._overall_timer = QTimer(self)
        self._overall_timer.setSingleShot(True)
        # 4 times a second: each pass walks every kept job and repaints the
        # bar (~16 ms with 2000 jobs); at 20 a second it was a third of the
        # GUI thread's time during a copy of many small files.
        self._overall_timer.setInterval(OVERALL_INTERVAL_MS)
        self._overall_timer.timeout.connect(self._update_overall)
        # A job's row is drawn anew once per burst as well: 2000 small files
        # sent 10 000 updates, each a dataChanged the column fitter measured
        # the row for (1.4 s of 2 s GUI time). Collected here, and the
        # rows of one burst go out together, at most every 50 ms.
        self._updated: set[str] = set()
        self._rows_timer = QTimer(self)
        self._rows_timer.setSingleShot(True)
        self._rows_timer.setInterval(50)
        self._rows_timer.timeout.connect(self._flush_updated_rows)
        self._manager.job_added.connect(self._on_job_added)
        self._manager.job_updated.connect(self._on_job_updated)
        self._manager.job_finished.connect(self._on_job_finished)
        self._manager.job_error.connect(self._on_job_error)
        trimmed = getattr(self._manager, "jobs_trimmed", None)
        if trimmed is not None:
            trimmed.connect(self._on_jobs_trimmed)
        for name in ("walk_started", "walk_finished"):
            signal = getattr(self._manager, name, None)
            if signal is not None:
                signal.connect(self._schedule_overall)
        started = getattr(self._manager, "walk_started", None)
        if started is not None:
            started.connect(lambda: self._btn_cancel.setEnabled(True))

    def _setup_ui(self) -> None:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        # Table
        self._table = QTableView()
        self._table.setModel(self._model)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(False)
        self._table.setAlternatingRowColors(True)

        # Progress bar delegate
        self._table.setItemDelegateForColumn(COL_PROGRESS, ProgressBarDelegate(self._table))
        # A right click on a job: Cancel, Retry, Open destination folder
        # (the tour and the handbook promised it; there was no menu).
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_job_menu)

        # Column sizing: File takes the free width, the others fit their
        # content; every divider stays draggable (ui.column_fit).
        from ui.column_fit import ColumnFitter

        # The fit measures the rows on screen and their neighbours up to this
        # many (Qt's default is 1000): a walk that queued 2000 jobs at once
        # had 7 x 1000 new cells measured in one pass, a 0.5 s freeze. The
        # rows of one queue look alike (a name, a size, a status), so a
        # hundred show the widths as well as a thousand.
        self._table.horizontalHeader().setResizeContentsPrecision(TABLE_FIT_ROWS)
        self._columns = ColumnFitter(self._table, fill=0, cache_widths=True, data_delay_ms=100)

        layout.addWidget(self._table, stretch=1)

        # Bottom bar
        bottom = QHBoxLayout()

        # A click on the overall bar shows the transfer running now. Not a
        # button of its own: the bottom row's width is what the dock scrolls
        # sideways for when it is narrower (the frame below), so it stays
        # short.
        self._overall_progress = _OverallBar()
        self._overall_progress.clicked.connect(self.show_current)
        self._overall_progress.setRange(0, 100)
        self._overall_progress.setValue(0)
        self._overall_progress.setTextVisible(True)
        bottom.addWidget(self._overall_progress, stretch=1)
        # With nothing queued the table and the bar ("0%") are hidden and
        # this line stands in their place: the file list gets the room.
        self._idle_label = QLabel(tr("No transfers yet. F5 copies the selection to the "
                                     "target pane, F6 moves it."))
        self._idle_label.setObjectName("axTransferIdle")
        # The theme's secondary text colour (QLabel[role="muted"]), not the
        # disabled one: that was 1.9:1 on white in Light Mode (UX review
        # round 7); every theme's muted colour reaches 4.5:1.
        self._idle_label.setProperty("role", "muted")
        bottom.addWidget(self._idle_label, stretch=1)

        self._btn_retry = QPushButton(tr("Retry Failed"))
        self._btn_retry.setObjectName("axTransferRetry")  # the tours point at it
        self._btn_retry.setToolTip(tr("Retry failed/cancelled transfers with resume"))
        self._btn_retry.clicked.connect(self._retry_failed)
        bottom.addWidget(self._btn_retry)

        self._btn_cancel = QPushButton(tr("Cancel All"))
        self._btn_cancel.clicked.connect(self._cancel_all)
        bottom.addWidget(self._btn_cancel)

        self._btn_clear = QPushButton(tr("Clear Finished"))
        self._btn_clear.clicked.connect(self._clear_finished)
        bottom.addWidget(self._btn_clear)

        layout.addLayout(bottom)

        # In a scroll area (ui.dock_frame), as the Terminal and the Log: with
        # a larger font the bottom row outgrew the room left of the right
        # dock column, and Qt laid the bottom area under that column.
        self.setWidget(framed(container, self))

    @property
    def idle(self) -> bool:
        """True while the queue holds no job (the dock is one short row)."""
        return self._idle

    def _set_idle(self, idle: bool) -> None:
        if idle == self._idle:
            return
        self._idle = idle
        self._table.setVisible(not idle)
        self._overall_progress.setVisible(not idle)
        self._idle_label.setVisible(idle)
        self.idle_changed.emit(idle)

    def _on_job_added(self, job: TransferJob) -> None:
        self._set_idle(False)
        # At once, not with the next overall pass: a job can be cancelled
        # the moment it shows.
        self._btn_cancel.setEnabled(True)
        self._batch.add(job.job_id)
        self._model.add_job(job)
        self._schedule_overall()
        self.activity.emit()

    def _on_jobs_trimmed(self, job_ids: list) -> None:
        for job_id in job_ids:
            if job_id in self._batch:
                self._batch.discard(job_id)
                row = self._model._job_index.get(job_id)
                job = self._model.get_job(row) if row is not None else None
                if job is not None:
                    self._batch_dropped += job.total_bytes
        self._model.remove_jobs(job_ids)
        self._schedule_overall()

    def _on_job_updated(self, job_id: str) -> None:
        self._updated.add(job_id)
        if not self._rows_timer.isActive():
            self._rows_timer.start()
        self._schedule_overall()

    def _flush_updated_rows(self) -> None:
        updated, self._updated = self._updated, set()
        self._model.update_jobs(updated)
        if updated:
            self.activity.emit()  # once per burst

    def _on_job_finished(self, job_id: str) -> None:
        self._btn_clear.setEnabled(True)  # at once; the overall pass refines
        self._on_job_updated(job_id)

    def _on_job_error(self, job_id: str, error: str) -> None:
        # A failed or cancelled job can be retried and cleared at once.
        self._btn_retry.setEnabled(True)
        self._btn_clear.setEnabled(True)
        self._on_job_updated(job_id)
        log.warning("Transfer error: %s: %s", job_id, error)
        self.activity.emit()

    def _schedule_overall(self) -> None:
        if not self._overall_timer.isActive():
            self._overall_timer.start()

    def _sync_buttons(self, jobs) -> None:
        """Each bottom button only while it has something to act on: Retry
        Failed with a failed or cancelled job to retry, Cancel All with one
        waiting or running, Clear Finished with one ended (UX review round
        6: all three were enabled over an empty list)."""
        running = (TransferStatus.ACTIVE, TransferStatus.PENDING)
        ended = (TransferStatus.DONE, TransferStatus.ERROR, TransferStatus.CANCELLED)
        self._btn_retry.setEnabled(any(self._can_retry(j) for j in jobs))
        # A folder walk still building jobs, or the window's conflict check
        # before a copy, counts: Cancel All stops them before a row shows.
        walking = bool(getattr(self._manager, "_walks", ())) or self._preparing
        self._btn_cancel.setEnabled(walking or any(j.status in running for j in jobs))
        self._btn_clear.setEnabled(any(j.status in ended for j in jobs))

    def note_preparing(self, preparing: bool) -> None:
        """The window is checking a copy or move for conflicts (*preparing*)
        or done with it: Cancel All follows."""
        self._preparing = preparing
        if preparing:
            self._btn_cancel.setEnabled(True)
        self._schedule_overall()

    def _update_overall(self) -> None:
        jobs = self._manager.all_jobs()
        self._sync_buttons(jobs)
        self._set_idle(not jobs)
        if not jobs:
            self._batch.clear()
            self._batch_dropped = 0
            self._ended_badly = (0, 0)
            self._show_ended_badly(False)
            self._overall_progress.setValue(0)
            self._overall_progress.setFormat("%p" + percent_sign())
            self._overall_progress.setToolTip("")
            return
        running = (TransferStatus.ACTIVE, TransferStatus.PENDING)
        if not any(j.status in running for j in jobs):
            # All jobs finished: "Done" - or, when some of the batch failed
            # or were cancelled, how many (it said "Done" when all failed).
            if self._batch:
                ended = [j for j in jobs if j.job_id in self._batch and not j.retried]
                self._ended_badly = (
                    sum(1 for j in ended if j.status == TransferStatus.ERROR),
                    sum(1 for j in ended if j.status == TransferStatus.CANCELLED),
                )
            self._batch.clear()
            self._batch_dropped = 0
            self._overall_progress.setValue(0)
            failed, cancelled = self._ended_badly
            if failed or cancelled:
                parts = []
                if failed:
                    parts.append(tr_n(failed, "{n} failed", "{n} failed"))
                if cancelled:
                    parts.append(tr_n(cancelled, "{n} cancelled", "{n} cancelled"))
                text = ", ".join(parts)
                self._overall_progress.setFormat(text)
                tip = tr("{what} in the last batch; Retry Failed tries them again").format(
                    what=text)
                if any(TransferManager.partial_kept(j) for j in jobs):
                    tip += "\n" + tr("Partly transferred files are kept for Retry Failed; "
                                     "Clear Finished deletes them.")
                self._overall_progress.setToolTip(tip)
                self._show_ended_badly(True)
            else:
                self._overall_progress.setFormat(tr("Done"))
                self._overall_progress.setToolTip("")
                self._show_ended_badly(False)
            return
        self._ended_badly = (0, 0)
        self._show_ended_badly(False)
        total = done = self._batch_dropped
        speed = 0.0
        for job in jobs:
            if job.status in running:
                total += job.total_bytes
                done += min(job.transferred_bytes, job.total_bytes)
                if job.status == TransferStatus.ACTIVE:
                    speed += max(job.speed, 0.0)
            elif job.job_id in self._batch:
                # Finished in this batch: all of it; failed or cancelled:
                # what it moved (the rest will not come).
                part = job.total_bytes if job.status == TransferStatus.DONE else min(
                    job.transferred_bytes, job.total_bytes)
                total += part
                done += part
        self._overall_progress.setValue(int(done * 100 / total) if total > 0 else 0)
        remaining = total - done
        if speed > 0 and remaining > 0:
            left = TransferModel._format_eta(remaining / speed)
            self._overall_progress.setFormat(tr("%p% · {left} left").format(left=left))
            self._overall_progress.setToolTip(
                tr("{done} of {total}, about {left} left at the current speed").format(
                    done=TransferModel._format_size(done),
                    total=TransferModel._format_size(total), left=left))
        else:
            self._overall_progress.setFormat("%p" + percent_sign())
            self._overall_progress.setToolTip("")

    def _show_ended_badly(self, bad: bool) -> None:
        """The overall bar's text in the theme's error colour (``danger``)
        while it reports failed or cancelled jobs."""
        bar = self._overall_progress
        if bool(bar.property("endedBadly")) == bad:
            return
        bar.setProperty("endedBadly", bad)
        if not bad:
            bar.setStyleSheet("")
            return
        from PyQt6.QtGui import QPalette

        dark = bar.palette().color(QPalette.ColorRole.Window).lightness() < 128
        bar.setStyleSheet(f"QProgressBar {{ color: {'#ff6b6b' if dark else '#c92a2a'}; }}")

    def show_current(self) -> bool:
        """Scroll to and select the running transfer (the first one when
        several run; else the next waiting one). False when none."""
        row_of = None
        for wanted in (TransferStatus.ACTIVE, TransferStatus.PENDING):
            for row in range(self._model.rowCount()):
                job = self._model.get_job(row)
                if job is not None and job.status == wanted:
                    row_of = row
                    break
            if row_of is not None:
                break
        if row_of is None:
            return False
        index = self._model.index(row_of, 0)
        self._table.selectRow(row_of)
        self._table.scrollTo(index, QAbstractItemView.ScrollHint.PositionAtCenter)
        return True

    def _cancel_all(self) -> None:
        self._manager.cancel_all()

    # -- the right-click menu of one job -----------------------------------------------

    def _job_at(self, pos) -> TransferJob | None:
        index = self._table.indexAt(pos)
        if not index.isValid():
            return None
        return self._model.get_job(index.row())

    @staticmethod
    def _can_retry(job: TransferJob) -> bool:
        return (
            job.status in (TransferStatus.ERROR, TransferStatus.CANCELLED)
            and bool(getattr(job, "retryable", True))
            and not getattr(job, "retried", False)
        )

    def build_job_menu(self, job: TransferJob | None) -> QMenu:
        """The menu of *job* (None: no job under the pointer, every entry
        disabled): Cancel a waiting or running job, Retry a failed or
        cancelled one, Open destination folder."""
        menu = QMenu(self)
        cancel = menu.addAction(tr("Cancel"))
        cancel.setObjectName("axTransferJobCancel")
        cancel.setEnabled(
            job is not None and job.status in (TransferStatus.PENDING, TransferStatus.ACTIVE)
        )
        cancel.triggered.connect(lambda _checked=False, j=job: self.cancel_job(j))
        retry = menu.addAction(tr("Retry"))
        retry.setObjectName("axTransferJobRetry")
        retry.setEnabled(job is not None and self._can_retry(job))
        retry.triggered.connect(lambda _checked=False, j=job: self.retry_job(j))
        menu.addSeparator()
        reveal = menu.addAction(tr("Open destination folder"))
        reveal.setObjectName("axTransferJobReveal")
        reveal.setEnabled(job is not None and bool(job.dest_path))
        reveal.triggered.connect(lambda _checked=False, j=job: self.open_destination(j))
        return menu

    def _show_job_menu(self, pos) -> None:
        job = self._job_at(pos)
        if job is not None:
            self._table.selectRow(self._table.indexAt(pos).row())
        menu = self.build_job_menu(job)
        try:
            menu.exec(self._table.viewport().mapToGlobal(pos))
        finally:
            menu.deleteLater()

    def cancel_job(self, job: TransferJob | None) -> None:
        if job is not None:
            self._manager.cancel_job(job.job_id)

    def retry_job(self, job: TransferJob | None) -> TransferJob | None:
        if job is None:
            return None
        return self._manager.retry_job(job.job_id)

    def open_destination(self, job: TransferJob | None) -> bool:
        """The destination folder of *job*: in the pane on its connection,
        the file selected (the main window's reveal); a local folder without
        such a window in the system's file manager. False when neither."""
        if job is None or not job.dest_path:
            return False
        backend = getattr(job, "dest_backend", None)
        reveal = getattr(self.parent(), "_reveal_found", None)
        if callable(reveal) and backend is not None:
            reveal(backend, job.dest_path)
            return True
        from core.local_fs import LocalFS

        if backend is None or isinstance(backend, LocalFS):
            import os

            from PyQt6.QtCore import QUrl

            from core.desktop_open import open_url

            return bool(open_url(QUrl.fromLocalFile(os.path.dirname(job.dest_path))))
        return False

    def _retry_failed(self) -> None:
        """Retry all failed/cancelled transfers with resume."""
        jobs = self._manager.all_jobs()
        retried = 0
        for job in jobs:
            if job.status in (TransferStatus.ERROR, TransferStatus.CANCELLED):
                new_job = self._manager.retry_job(job.job_id)
                if new_job:
                    retried += 1
        if retried:
            log.info("Retried %d failed transfers", retried)

    def _clear_finished(self) -> None:
        # The finished jobs of a batch still running stay part of its bar:
        # dropped from the list, the bar fell back to 0 % mid-batch.
        running = (TransferStatus.ACTIVE, TransferStatus.PENDING)
        jobs = self._manager.all_jobs()
        if any(j.status in running for j in jobs):
            for job in jobs:
                if job.status in running or job.job_id not in self._batch:
                    continue
                self._batch.discard(job.job_id)
                self._batch_dropped += job.total_bytes if job.status == TransferStatus.DONE \
                    else min(job.transferred_bytes, job.total_bytes)
        self._ended_badly = (0, 0)
        self._manager.clear_finished()
        self._model.clear_finished()
        self._update_overall()
