"""Table model for the transfer queue."""
from __future__ import annotations

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PyQt6.QtWidgets import QStyle, QStyledItemDelegate, QStyleOptionProgressBar, QApplication

from core.transfer_worker import TransferDirection, TransferJob, TransferStatus

COLUMNS = ("File", "Direction", "Size", "Progress", "Speed", "ETA", "Status")
COL_FILE, COL_DIR, COL_SIZE, COL_PROGRESS, COL_SPEED, COL_ETA, COL_STATUS = range(7)


class TransferModel(QAbstractTableModel):
    """Model backing the transfer queue table view."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._jobs: list[TransferJob] = []
        self._job_index: dict[str, int] = {}

    def add_job(self, job: TransferJob) -> None:
        row = len(self._jobs)
        self.beginInsertRows(QModelIndex(), row, row)
        self._jobs.append(job)
        self._job_index[job.job_id] = row
        self.endInsertRows()

    def update_job(self, job_id: str) -> None:
        idx = self._job_index.get(job_id)
        if idx is not None:
            top_left = self.index(idx, 0)
            bottom_right = self.index(idx, len(COLUMNS) - 1)
            self.dataChanged.emit(top_left, bottom_right)

    def clear_finished(self) -> None:
        self.beginResetModel()
        self._jobs = [j for j in self._jobs if j.status == TransferStatus.ACTIVE or j.status == TransferStatus.PENDING]
        self._job_index = {j.job_id: i for i, j in enumerate(self._jobs)}
        self.endResetModel()

    def get_job(self, row: int) -> TransferJob | None:
        if 0 <= row < len(self._jobs):
            return self._jobs[row]
        return None

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self._jobs)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(COLUMNS)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or index.row() >= len(self._jobs):
            return None

        job = self._jobs[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            if col == COL_FILE:
                return job.filename
            if col == COL_DIR:
                if job.direction == TransferDirection.RELAY:
                    arrow = "\u21c4"  # ⇄ bidirectional arrow for relay
                elif job.direction == TransferDirection.UPLOAD:
                    arrow = "\u2191"
                else:
                    arrow = "\u2193"
                return f"{arrow}\u2700" if job.move else arrow  # ✀ scissors for move
            if col == COL_SIZE:
                return self._format_size(job.total_bytes)
            if col == COL_PROGRESS:
                if job.status == TransferStatus.DONE:
                    return "Done"
                return f"{job.progress_percent:.0f}%"
            if col == COL_SPEED:
                if job.status == TransferStatus.ACTIVE and job.speed > 0:
                    return f"{self._format_size(job.speed)}/s"
                return ""
            if col == COL_ETA:
                if job.status == TransferStatus.ACTIVE and job.eta_seconds > 0:
                    return self._format_eta(job.eta_seconds)
                return ""
            if col == COL_STATUS:
                return job.status.value

        if role == Qt.ItemDataRole.UserRole and col == COL_PROGRESS:
            return job.progress_percent

        if role == Qt.ItemDataRole.TextAlignmentRole:
            if col in (COL_SIZE, COL_SPEED, COL_ETA, COL_PROGRESS):
                return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
            if col == COL_DIR:
                return Qt.AlignmentFlag.AlignCenter

        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            if 0 <= section < len(COLUMNS):
                return COLUMNS[section]
        return None

    @staticmethod
    def _format_size(size: float) -> str:
        for unit in ("B", "KB", "MB", "GB"):
            if abs(size) < 1024:
                if unit == "B":
                    return f"{int(size)} {unit}"
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    @staticmethod
    def _format_eta(seconds: float) -> str:
        if seconds < 60:
            return f"{int(seconds)}s"
        if seconds < 3600:
            m, s = divmod(int(seconds), 60)
            return f"{m}m {s}s"
        h, remainder = divmod(int(seconds), 3600)
        m, s = divmod(remainder, 60)
        return f"{h}h {m}m"


class ProgressBarDelegate(QStyledItemDelegate):
    """Custom delegate to render progress bars in the table."""

    def paint(self, painter, option, index):
        if index.column() == COL_PROGRESS:
            progress = index.data(Qt.ItemDataRole.UserRole)
            if progress is not None:
                opt = QStyleOptionProgressBar()
                opt.rect = option.rect
                opt.minimum = 0
                opt.maximum = 100
                opt.progress = int(progress)
                opt.text = f"{int(progress)}%"
                opt.textVisible = True
                QApplication.style().drawControl(
                    QStyle.ControlElement.CE_ProgressBar, opt, painter
                )
                return
        super().paint(painter, option, index)
