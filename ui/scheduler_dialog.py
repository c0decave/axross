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

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
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

from core.i18n import tr, tr_n
from core.scheduler import MIN_INTERVAL_S, Job, JobStore, next_run_at, reenabled, script_target
from ui.close_corner import add_close_corner
from ui.handbook import install_help_key
from ui.icon_provider import set_window_icon

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
    """Human phrasing for an interval, largest unit first, with every unit
    it has: 5400 s is "every 1 h 30 min" (it was rounded down to "every
    1 h", so two jobs that ran at different rates looked alike)."""
    seconds = max(0, int(seconds))
    parts = []
    for unit_s, unit in ((86400, "day"), (3600, "h"), (60, "min"), (1, "s")):
        value, seconds = divmod(seconds, unit_s)
        if value:
            parts.append(f"{value} {unit}" + ("s" if unit == "day" and value != 1 else ""))
    return "every " + (" ".join(parts) or "0 s")


def shown_cell(column: str, text: str, job: Job) -> str:
    """A :func:`job_row` cell as the table shows it: in the interface
    language (the row itself stays English, for the tests and the log)."""
    if column == "Every":
        seconds = max(0, int(job.interval_s))
        parts = []
        for unit_s, unit in ((86400, "day"), (3600, "h"), (60, "min"), (1, "s")):
            value, seconds = divmod(seconds, unit_s)
            if value:
                parts.append(tr_n(value, "{n} day", "{n} days") if unit == "day"
                             else f"{value} {unit}")
        return tr("every {interval}").format(interval=" ".join(parts) or "0 s")
    if column == "Status" or text == "never":
        return tr(text)
    return text


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

    def __init__(self, store: JobStore, parent: QWidget | None = None, *, run_now=None):
        super().__init__(parent)
        #: run_now(job) -> bool starts *job* at once (False: it is running).
        self._run_now = run_now
        set_window_icon(self, "clock")
        install_help_key(self, "scheduler")  # F1: its handbook section (a window of its own)
        self.store = store
        self._jobs: list[Job] = []

        self.setWindowTitle(tr("Scheduled Jobs"))
        self.resize(900, 420)
        self._build()
        self.reload()

    # -- construction ----------------------------------------------------

    def _build(self) -> None:
        layout = QVBoxLayout(self)
        add_close_corner(self)

        self._table = QTableWidget(0, len(COLUMNS), self)
        self._table.setHorizontalHeaderLabels([tr(c) for c in COLUMNS])
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        from ui.column_fit import ColumnFitter

        # The first column takes the free width; every divider stays draggable.
        self._columns = ColumnFitter(self._table, fill=0)
        layout.addWidget(self._table)

        form = QHBoxLayout()
        self._name_edit = QLineEdit(self)
        self._name_edit.setPlaceholderText(tr("Job name"))
        form.addWidget(self._name_edit)

        self._target_edit = QLineEdit(self)
        self._target_edit.setPlaceholderText(tr("Saved script name, e.g. mirror"))
        # The saved scripts to pick from (a job for a name no script has
        # was accepted and failed at every run).
        from PyQt6.QtWidgets import QCompleter

        self._script_completer = QCompleter(self._saved_scripts(), self)
        self._script_completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._target_edit.setCompleter(self._script_completer)
        form.addWidget(self._target_edit)

        self._interval_box = QComboBox(self)
        for label, seconds in INTERVAL_CHOICES.items():
            self._interval_box.addItem(tr(label), seconds)
        self._interval_box.setCurrentIndex(list(INTERVAL_CHOICES).index("1 hour"))
        form.addWidget(self._interval_box)

        self._custom_spin = QSpinBox(self)
        self._custom_spin.setRange(0, 86400 * 7)
        self._custom_spin.setSuffix(tr(" s (0 = use the list)"))
        self._custom_spin.setSpecialValueText("")
        # 0 (use the list) or at least five minutes, never in between: a
        # value is taken when typing ends, and one below the minimum snaps.
        self._custom_spin.setKeyboardTracking(False)
        self._custom_spin.setToolTip(
            tr("A custom interval of at least {seconds} s").format(seconds=MIN_INTERVAL_S))
        self._custom_last = 0
        self._custom_spin.valueChanged.connect(self._snap_custom_interval)
        form.addWidget(self._custom_spin)

        add_btn = QPushButton(tr("Add"), self)
        add_btn.clicked.connect(self._on_add)
        form.addWidget(add_btn)
        layout.addLayout(form)

        actions = QHBoxLayout()
        self._toggle_btn = QPushButton(tr("Enable / disable"), self)
        self._toggle_btn.clicked.connect(self._on_toggle)
        actions.addWidget(self._toggle_btn)

        self._remove_btn = QPushButton(tr("Remove"), self)
        self._remove_btn.clicked.connect(self._on_remove)
        actions.addWidget(self._remove_btn)

        self._run_btn = QPushButton(tr("Run Now"), self)
        self._run_btn.setToolTip(tr("Run the selected job now, without waiting for its time"))
        self._run_btn.clicked.connect(self._on_run_now)
        self._run_btn.setVisible(self._run_now is not None)
        actions.addWidget(self._run_btn)

        actions.addStretch(1)
        self._status = QLabel(self)
        self._status.setProperty("role", "muted")
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
                self._table.setItem(row_idx, col_idx, QTableWidgetItem(
                    shown_cell(column, cells[column], self._jobs[row_idx])))
        if not rows:
            self._status.setText(tr("No jobs scheduled."))
        else:
            active = sum(1 for j in self._jobs if j.enabled)
            self._status.setText(tr_n(len(rows), "{n} job, {active} enabled", "{n} jobs, {active} enabled",
                                     active=active))

    # -- introspection ---------------------------------------------------

    def displayed_rows(self) -> list[dict[str, str]]:
        return [job_row(job) for job in self._jobs]

    def displayed_names(self) -> list[str]:
        return [job.name for job in self._jobs]

    def status_text(self) -> str:
        return self._status.text()

    # -- mutations -------------------------------------------------------

    def _snap_custom_interval(self, value: int) -> None:
        """Below the minimum (but not 0): down to 0 (use the list) when
        stepping down from the minimum, else up to the minimum."""
        if 0 < value < MIN_INTERVAL_S:
            self._custom_spin.setValue(0 if self._custom_last == MIN_INTERVAL_S else MIN_INTERVAL_S)
            return
        self._custom_last = value

    def add_job(self, *, name: str, kind: str, target: str, interval_s: int) -> Job:
        # Job.__post_init__ rejects a non-positive interval; letting it
        # raise here keeps the invalid job out of the store entirely.
        if interval_s < MIN_INTERVAL_S:
            raise ValueError(tr("The shortest interval is {seconds} s (5 minutes).").format(
                seconds=MIN_INTERVAL_S))
        if kind == "script":
            target = script_target(target)  # ValueError for a name scripts refuse
        job = Job(
            job_id=uuid.uuid4().hex[:12],
            name=name,
            kind=kind,
            target=target,
            interval_s=interval_s,
        )
        self._change(lambda jobs: [*jobs, job])
        return job

    def remove_job(self, job_id: str) -> None:
        self._change(lambda jobs: [j for j in jobs if j.job_id != job_id])

    def set_enabled(self, job_id: str, enabled: bool) -> None:
        from dataclasses import replace

        def switch(j: Job) -> Job:
            if not enabled:
                return replace(j, enabled=False)
            # Switched on again: the failure count starts over (it kept 10,
            # and one more failure disabled the job at once).
            return j if j.enabled else reenabled(j)

        self._change(lambda jobs: [switch(j) if j.job_id == job_id else j for j in jobs])

    def _change(self, change) -> None:
        """Apply *change* to the jobs as the store holds them now, not to
        this dialog's copy: a run that finished while the dialog was open
        recorded its result in the store, and saving the copy would erase it."""
        self._jobs = self.store.update(change)
        self._populate()

    # -- handlers --------------------------------------------------------

    def _selected_job(self) -> Job | None:
        rows = {i.row() for i in self._table.selectedIndexes()}
        if not rows:
            return None
        index = sorted(rows)[0]
        return self._jobs[index] if index < len(self._jobs) else None

    @staticmethod
    def _saved_scripts() -> list[str]:
        from core import scripting

        try:
            return scripting.list_scripts()
        except OSError:
            return []

    def _on_add(self) -> None:
        name = self._name_edit.text().strip()
        target = self._target_edit.text().strip()
        if not name or not target:
            QMessageBox.information(self, tr("Add job"), tr("A name and a target are required."))
            return
        try:
            script = script_target(target)
        except ValueError as exc:
            QMessageBox.warning(self, tr("Add job"), str(exc))
            return
        scripts = self._saved_scripts()
        if script not in scripts:
            QMessageBox.warning(self, tr("Add job"), tr(
                "There is no saved script {name!r}. Save it in the Script Editor first, or "
                "choose one of: {scripts}").format(
                    name=script, scripts=", ".join(scripts) or tr("(no saved scripts)")))
            return
        interval = self._custom_spin.value() or int(self._interval_box.currentData())
        try:
            self.add_job(name=name, kind="script", target=target, interval_s=interval)
        except ValueError as exc:
            QMessageBox.warning(self, tr("Add job"), str(exc))
            return
        self._name_edit.clear()
        self._target_edit.clear()

    def _on_remove(self) -> None:
        job = self._selected_job()
        if job is None:
            return
        if QMessageBox.question(
            self,
            tr("Remove job"),
            tr("Remove {name!r} from the schedule?").format(name=job.name),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) == QMessageBox.StandardButton.Yes:
            self.remove_job(job.job_id)

    def _on_run_now(self) -> None:
        job = self._selected_job()
        if job is None or self._run_now is None:
            return
        if self._run_now(job):
            self._status.setText(tr("{name} started; its result shows here when it ends.").format(
                name=job.name))
        else:
            self._status.setText(tr("{name} is running already.").format(name=job.name))

    def _on_toggle(self) -> None:
        job = self._selected_job()
        if job is not None:
            self.set_enabled(job.job_id, not job.enabled)


__all__ = ["COLUMNS", "INTERVAL_CHOICES", "SchedulerDialog", "format_interval", "job_row"]
