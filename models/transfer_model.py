"""Table model for the transfer queue."""

from __future__ import annotations

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PyQt6.QtWidgets import QApplication, QStyle, QStyledItemDelegate, QStyleOptionProgressBar

from core.i18n import format_percent, tr
from core.transfer_worker import TransferDirection, TransferJob, TransferStatus

COLUMNS = ("File", "Direction", "Size", "Progress", "Speed", "ETA", "Status")
COL_FILE, COL_DIR, COL_SIZE, COL_PROGRESS, COL_SPEED, COL_ETA, COL_STATUS = range(7)

#: The Status cell's word for each state, translated where it is shown.
STATUS_WORDS = {
    TransferStatus.PENDING: "pending",
    TransferStatus.ACTIVE: "active",
    TransferStatus.DONE: "done",
    TransferStatus.ERROR: "error",
    TransferStatus.CANCELLED: "cancelled",
}


def status_text(job: TransferJob) -> str:
    """The Status cell: the translated state word, and for a failed or
    cancelled job the reason (``job.error_message``) behind it - the bare
    word "error" left the user guessing what went wrong."""
    if job.skipped:
        return tr("skipped")
    word = tr(STATUS_WORDS.get(job.status, job.status.value))
    reason = _sentence(job)
    return f"{word}: {reason.splitlines()[0]}" if reason else word


def _reason(job: TransferJob) -> str:
    """Why a failed or cancelled job ended, or "" - not the bare "Cancelled"
    the worker writes for a plain cancel, which repeats the state word."""
    if job.status not in (TransferStatus.ERROR, TransferStatus.CANCELLED):
        return ""
    reason = (job.error_message or "").strip()
    return "" if reason.casefold() == "cancelled" else reason


#: What a refused folder row was about (``job.error_context``, set by
#: core.transfer_manager): said in front of the error's own sentence.
REFUSAL_CONTEXTS = {
    "mkdir": "The folder could not be created, so its contents were not copied: {error}",
    "list": "The folder could not be read, so its contents were not copied: {error}",
}


def _both_local(job: TransferJob) -> bool:
    """Both ends of *job* on this machine (a local-to-local copy)."""
    from core.local_fs import LocalFS

    return (isinstance(getattr(job, "source_backend", None), LocalFS)
            and isinstance(getattr(job, "dest_backend", None), LocalFS))


def _named_as_destination(job: TransferJob, text: str) -> str:
    """*text* with the job's hidden temp file (``.name.part-<id>-<fp>``)
    named as the destination it was written for: the user never chose the
    temp name ("/usr/share/.todo.txt.part-c71d0b6a-58df0d1a is on a
    read-only file system" -> "/usr/share/todo.txt …", UX review round 6).
    The log keeps the raw text."""
    temp = getattr(job, "temp_path", "") or ""
    dest = getattr(job, "dest_path", "") or ""
    if not temp or not dest or temp == dest or not text:
        return text
    text = text.replace(temp, dest)
    temp_name = temp.replace("\\", "/").rsplit("/", 1)[-1]
    dest_name = dest.replace("\\", "/").rsplit("/", 1)[-1]
    if temp_name and dest_name:
        text = text.replace(temp_name, dest_name)
    return text


def _sentence(job: TransferJob) -> str:
    """:func:`_reason` as core.user_errors.describe() says it, in the
    interface language, when the job kept its exception ("[Errno 13]
    Permission denied: '/x'" -> "Permission denied for /x. ..."). A temp
    file's name is shown as the destination's (:func:`_named_as_destination`)."""
    reason = _named_as_destination(job, _reason(job))
    error = getattr(job, "error", None)
    if not reason or error is None or job.status != TransferStatus.ERROR:
        return reason
    from core.user_errors import describe

    sentence = _named_as_destination(job, describe(error) or reason)
    context = REFUSAL_CONTEXTS.get(getattr(job, "error_context", ""))
    return tr(context).format(error=sentence) if context else sentence


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

    def update_jobs(self, job_ids) -> None:
        """:meth:`update_job` for many: one dataChanged per run of adjacent
        rows (unknown ids are ignored)."""
        rows = sorted({self._job_index[j] for j in job_ids if j in self._job_index})
        last = len(COLUMNS) - 1
        start = previous = None
        for row in rows + [None]:
            if row is not None and previous is not None and row == previous + 1:
                previous = row
                continue
            if start is not None:
                self.dataChanged.emit(self.index(start, 0), self.index(previous, last))
            start = previous = row

    def clear_finished(self) -> None:
        self.beginResetModel()
        self._jobs = [
            j
            for j in self._jobs
            if j.status == TransferStatus.ACTIVE or j.status == TransferStatus.PENDING
        ]
        self._job_index = {j.job_id: i for i, j in enumerate(self._jobs)}
        self.endResetModel()

    def remove_jobs(self, job_ids) -> None:
        """Remove the rows of *job_ids* (unknown ids are ignored), one
        contiguous range at a time from the bottom: selection and scroll
        position stay where they were, unlike a reset."""
        rows = sorted({self._job_index[j] for j in job_ids if j in self._job_index})
        if not rows:
            return
        ranges: list[list[int]] = []
        for row in rows:
            if ranges and row == ranges[-1][1] + 1:
                ranges[-1][1] = row
            else:
                ranges.append([row, row])
        for first, last in reversed(ranges):
            self.beginRemoveRows(QModelIndex(), first, last)
            del self._jobs[first:last + 1]
            self.endRemoveRows()
        self._job_index = {j.job_id: i for i, j in enumerate(self._jobs)}

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
                elif _both_local(job):
                    # Neither up- nor download: one disk to another.
                    arrow = "\u2192"  # →
                elif job.direction == TransferDirection.UPLOAD:
                    arrow = "\u2191"
                else:
                    arrow = "\u2193"
                # Words, not a symbol: U+2700 scissors is in almost no font.
                return f"{arrow} {tr('move')}" if job.move else arrow
            if col == COL_SIZE:
                return self._format_size(job.total_bytes)
            if col == COL_PROGRESS:
                if job.skipped:
                    # "newer" kept the destination: nothing was written and
                    # a move kept its source, so this is no "Done".
                    return tr("Skipped")
                if job.status == TransferStatus.DONE:
                    return tr("Done")
                return format_percent(job.progress_percent)
            if col == COL_SPEED:
                if job.status == TransferStatus.ACTIVE and job.speed > 0:
                    return f"{self._format_size(job.speed)}/s"
                return ""
            if col == COL_ETA:
                if job.status == TransferStatus.ACTIVE and job.eta_seconds > 0:
                    return self._format_eta(job.eta_seconds)
                return ""
            if col == COL_STATUS:
                return status_text(job)

        if role == Qt.ItemDataRole.ToolTipRole and col == COL_STATUS:
            reason = _reason(job)
            if reason:
                word = tr(STATUS_WORDS.get(job.status, job.status.value))
                sentence = _sentence(job)
                # The whole sentence, in the interface language; the raw
                # text of the error ("[Errno 30] Read-only file system:
                # '…part-…'") is in the log (TransferDock._on_job_error).
                return f"{word}: {sentence}"
            return None

        if role == Qt.ItemDataRole.UserRole and col == COL_PROGRESS:
            # No bar for a skipped job: the delegate then draws "Skipped".
            return None if job.skipped else job.progress_percent

        if role == Qt.ItemDataRole.TextAlignmentRole:
            if col in (COL_SIZE, COL_SPEED, COL_ETA, COL_PROGRESS):
                return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
            if col == COL_DIR:
                return Qt.AlignmentFlag.AlignCenter

        return None

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            if 0 <= section < len(COLUMNS):
                return tr(COLUMNS[section])
        return None

    @staticmethod
    def _format_size(size: float) -> str:
        from core.i18n import format_decimal

        for unit in ("B", "KB", "MB", "GB"):
            if abs(size) < 1024:
                if unit == "B":
                    return f"{int(size)} {unit}"
                return f"{format_decimal(size)} {unit}"
            size /= 1024
        return f"{format_decimal(size)} TB"

    @staticmethod
    def _format_eta(seconds: float) -> str:
        """Time left, short: "7s", "3m 12s", "1h 5m" - in German "7 s",
        "3 min 12 s", "1 Std. 5 min" (the units read in the language;
        UX review round 9)."""
        if seconds < 60:
            return tr("{s}s").format(s=int(seconds))
        if seconds < 3600:
            m, s = divmod(int(seconds), 60)
            return tr("{m}m {s}s").format(m=m, s=s)
        h, remainder = divmod(int(seconds), 3600)
        m, s = divmod(remainder, 60)
        return tr("{h}h {m}m").format(h=h, m=m)


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
                opt.text = format_percent(int(progress))
                opt.textVisible = True
                QApplication.style().drawControl(QStyle.ControlElement.CE_ProgressBar, opt, painter)
                return
        super().paint(painter, option, index)
