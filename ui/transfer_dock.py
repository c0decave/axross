"""Transfer dock widget — shows transfer queue with progress."""
from __future__ import annotations

import logging

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QDockWidget,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QProgressBar,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from core.transfer_manager import TransferManager
from core.transfer_worker import TransferJob, TransferStatus
from models.transfer_model import COL_PROGRESS, ProgressBarDelegate, TransferModel

log = logging.getLogger(__name__)


class TransferDock(QDockWidget):
    """Dockable panel showing file transfer progress."""

    # Fires on every transfer-state change (add / update / error /
    # finish). MainWindow uses this to highlight the dock's tab when
    # it's not the currently-raised tab, so background transfers
    # don't stay invisible to the user.
    activity = pyqtSignal()

    def __init__(self, transfer_manager: TransferManager, parent: QWidget | None = None):
        super().__init__("Transfers", parent)
        self._manager = transfer_manager

        self.setAllowedAreas(Qt.DockWidgetArea.BottomDockWidgetArea | Qt.DockWidgetArea.TopDockWidgetArea)

        self._model = TransferModel()
        self._setup_ui()

        # Connect manager signals
        self._manager.job_added.connect(self._on_job_added)
        self._manager.job_updated.connect(self._on_job_updated)
        self._manager.job_finished.connect(self._on_job_updated)
        self._manager.job_error.connect(self._on_job_error)

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

        # Column sizing
        header = self._table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col in range(1, self._model.columnCount()):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)

        layout.addWidget(self._table, stretch=1)

        # Bottom bar
        bottom = QHBoxLayout()

        self._overall_progress = QProgressBar()
        self._overall_progress.setRange(0, 100)
        self._overall_progress.setValue(0)
        self._overall_progress.setTextVisible(True)
        bottom.addWidget(self._overall_progress, stretch=1)

        self._btn_retry = QPushButton("Retry Failed")
        self._btn_retry.setToolTip("Retry failed/cancelled transfers with resume")
        self._btn_retry.clicked.connect(self._retry_failed)
        bottom.addWidget(self._btn_retry)

        self._btn_cancel = QPushButton("Cancel All")
        self._btn_cancel.clicked.connect(self._cancel_all)
        bottom.addWidget(self._btn_cancel)

        self._btn_clear = QPushButton("Clear Finished")
        self._btn_clear.clicked.connect(self._clear_finished)
        bottom.addWidget(self._btn_clear)

        layout.addLayout(bottom)

        self.setWidget(container)

    def _on_job_added(self, job: TransferJob) -> None:
        self._model.add_job(job)
        self._update_overall()
        self.activity.emit()

    def _on_job_updated(self, job_id: str) -> None:
        self._model.update_job(job_id)
        self._update_overall()
        self.activity.emit()

    def _on_job_error(self, job_id: str, error: str) -> None:
        self._model.update_job(job_id)
        self._update_overall()
        log.warning("Transfer error: %s: %s", job_id, error)
        self.activity.emit()

    def _update_overall(self) -> None:
        jobs = self._manager.all_jobs()
        if not jobs:
            self._overall_progress.setValue(0)
            self._overall_progress.setFormat("%p%")
            return

        active_or_pending = [
            j for j in jobs
            if j.status in (TransferStatus.ACTIVE, TransferStatus.PENDING)
        ]

        if not active_or_pending:
            # All jobs finished — show "Done" and reset to 0
            self._overall_progress.setValue(0)
            self._overall_progress.setFormat("Done")
            return

        total = sum(j.total_bytes for j in active_or_pending)
        done = sum(j.transferred_bytes for j in active_or_pending)

        self._overall_progress.setFormat("%p%")
        if total > 0:
            self._overall_progress.setValue(int((done / total) * 100))
        else:
            self._overall_progress.setValue(0)

    def _cancel_all(self) -> None:
        self._manager.cancel_all()

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
        self._manager.clear_finished()
        self._model.clear_finished()
        self._update_overall()
