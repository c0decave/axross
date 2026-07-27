"""Scheduled jobs — the window over :mod:`core.scheduler`.

A schedule the user cannot inspect is a schedule they stop trusting, so
every row carries when it last ran, whether it worked, and what it said.
That matters most for a job that has disabled itself after repeated
failure: it has to read as *disabled*, with the reason, rather than
quietly ceasing to happen.

Deciding what is due lives in core.scheduler and is pure; this file only
displays it and edits the store.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime

from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.scheduler import Job, JobStore, next_run_at

log = logging.getLogger(__name__)

COLUMNS = ("Name", "What", "Every", "Last run", "Status", "Next run", "Detail")

#: Offered intervals, in seconds. Deliberately no "every second" — see
#: core.scheduler on why a tiny interval is a loop, not a schedule.
INTERVAL_CHOICES = {
    "5 minutes": 300,
    "15 minutes": 900,
    "1 hour": 3600,
    "6 hours": 21600,
    "1 day": 86400,
}


def format_interval(seconds: int) -> str:
    """Human phrasing for an interval, largest whole unit first."""
    for unit_s, unit in ((86400, "day"), (3600, "h"), (60, "min")):
        if seconds >= unit_s:
            value = seconds // unit_s
            return f"every {value} {unit}" + ("s" if unit == "day" and value != 1 else "")
    return f"every {seconds} s"


def job_row(job: Job, *, now: datetime | None = None) -> dict[str, str]:
    """One job as display strings, keyed by column."""
    now = now or datetime.now()

    if job.running:
        status = "running"
    elif not job.enabled:
        status = "disabled"
    elif job.last_ok is None:
        status = "waiting"
    else:
        status = "ok" if job.last_ok else "failed"

    when = next_run_at(job, now=now)
    return {
        "Name": job.name,
        "What": f"{job.kind}: {job.target}",
        "Every": format_interval(job.interval_s),
        # "never" rather than a blank: an empty cell reads as a missing
        # value, not as "this has not happened yet".
        "Last run": job.last_run_at.strftime("%Y-%m-%d %H:%M") if job.last_run_at else "never",
        "Status": status,
        "Next run": when.strftime("%Y-%m-%d %H:%M") if when else "—",
        "Detail": job.last_detail or "",
    }


class SchedulerDialog(QDialog):
    """List, add and remove recurring jobs."""

    def __init__(self, store: JobStore, parent: QWidget | None = None):
        super().__init__(parent)
        self.store = store
        self._jobs: list[Job] = []

        self.setWindowTitle("Scheduled Jobs")
        self.resize(900, 420)
        self._build()
        self.reload()

    # -- construction ----------------------------------------------------

    def _build(self) -> None:
        layout = QVBoxLayout(self)

        self._table = QTableWidget(0, len(COLUMNS), self)
        self._table.setHorizontalHeaderLabels(list(COLUMNS))
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        layout.addWidget(self._table)

        form = QHBoxLayout()
        self._name_edit = QLineEdit(self)
        self._name_edit.setPlaceholderText("Job name")
        form.addWidget(self._name_edit)

        self._target_edit = QLineEdit(self)
        self._target_edit.setPlaceholderText("Script name, e.g. mirror.py")
        form.addWidget(self._target_edit)

        self._interval_box = QComboBox(self)
        self._interval_box.addItems(list(INTERVAL_CHOICES))
        self._interval_box.setCurrentText("1 hour")
        form.addWidget(self._interval_box)

        self._custom_spin = QSpinBox(self)
        self._custom_spin.setRange(0, 86400 * 7)
        self._custom_spin.setSuffix(" s (0 = use the list)")
        self._custom_spin.setSpecialValueText("")
        form.addWidget(self._custom_spin)

        add_btn = QPushButton("Add", self)
        add_btn.clicked.connect(self._on_add)
        form.addWidget(add_btn)
        layout.addLayout(form)

        actions = QHBoxLayout()
        self._toggle_btn = QPushButton("Enable / disable", self)
        self._toggle_btn.clicked.connect(self._on_toggle)
        actions.addWidget(self._toggle_btn)

        self._remove_btn = QPushButton("Remove", self)
        self._remove_btn.clicked.connect(self._on_remove)
        actions.addWidget(self._remove_btn)

        actions.addStretch(1)
        self._status = QLabel(self)
        self._status.setStyleSheet("color: #666;")
        actions.addWidget(self._status)
        layout.addLayout(actions)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    # -- data ------------------------------------------------------------

    def reload(self) -> None:
        self._jobs = self.store.load()
        self._populate()

    def _populate(self) -> None:
        rows = self.displayed_rows()
        self._table.setRowCount(len(rows))
        for row_idx, cells in enumerate(rows):
            for col_idx, column in enumerate(COLUMNS):
                self._table.setItem(row_idx, col_idx, QTableWidgetItem(cells[column]))
        if not rows:
            self._status.setText("No jobs scheduled.")
        else:
            active = sum(1 for j in self._jobs if j.enabled)
            self._status.setText(f"{len(rows)} job(s), {active} enabled")

    # -- introspection ---------------------------------------------------

    def displayed_rows(self) -> list[dict[str, str]]:
        return [job_row(job) for job in self._jobs]

    def displayed_names(self) -> list[str]:
        return [job.name for job in self._jobs]

    def status_text(self) -> str:
        return self._status.text()

    # -- mutations -------------------------------------------------------

    def add_job(self, *, name: str, kind: str, target: str, interval_s: int) -> Job:
        # Job.__post_init__ rejects a non-positive interval; letting it
        # raise here keeps the invalid job out of the store entirely.
        job = Job(
            job_id=uuid.uuid4().hex[:12],
            name=name,
            kind=kind,
            target=target,
            interval_s=interval_s,
        )
        self._jobs = [*self._jobs, job]
        self.store.save(self._jobs)
        self._populate()
        return job

    def remove_job(self, job_id: str) -> None:
        self._jobs = [j for j in self._jobs if j.job_id != job_id]
        self.store.save(self._jobs)
        self._populate()

    def set_enabled(self, job_id: str, enabled: bool) -> None:
        from dataclasses import replace

        self._jobs = [
            replace(j, enabled=enabled) if j.job_id == job_id else j for j in self._jobs
        ]
        self.store.save(self._jobs)
        self._populate()

    # -- handlers --------------------------------------------------------

    def _selected_job(self) -> Job | None:
        rows = {i.row() for i in self._table.selectedIndexes()}
        if not rows:
            return None
        index = sorted(rows)[0]
        return self._jobs[index] if index < len(self._jobs) else None

    def _on_add(self) -> None:
        name = self._name_edit.text().strip()
        target = self._target_edit.text().strip()
        if not name or not target:
            QMessageBox.information(self, "Add job", "A name and a target are required.")
            return
        interval = self._custom_spin.value() or INTERVAL_CHOICES[
            self._interval_box.currentText()
        ]
        try:
            self.add_job(name=name, kind="script", target=target, interval_s=interval)
        except ValueError as exc:
            QMessageBox.warning(self, "Add job", str(exc))
            return
        self._name_edit.clear()
        self._target_edit.clear()

    def _on_remove(self) -> None:
        job = self._selected_job()
        if job is None:
            return
        if QMessageBox.question(
            self,
            "Remove job",
            f"Remove {job.name!r} from the schedule?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) == QMessageBox.StandardButton.Yes:
            self.remove_job(job.job_id)

    def _on_toggle(self) -> None:
        job = self._selected_job()
        if job is not None:
            self.set_enabled(job.job_id, not job.enabled)


__all__ = ["COLUMNS", "INTERVAL_CHOICES", "SchedulerDialog", "format_interval", "job_row"]
