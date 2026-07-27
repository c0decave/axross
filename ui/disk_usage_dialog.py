"""Disk usage across every open connection.

A view over :func:`core.dashboard.snapshot_with_backends`, which already
probes each backend's ``disk_usage()`` behind a bounded thread pool and
a per-call timeout. Nothing about the probing is reimplemented here.

The one thing this layer must not get wrong: ``disk_usage()`` returns
``(0, 0, 0)`` both for a backend that does not implement it (IMAP, LDAP,
most cloud object stores) and for a probe that timed out. Rendering
either as ``0 %`` would assert that a filesystem is empty when in truth
nothing was measured, so an unknown capacity is labelled as such and
gets no bar.

The snapshot itself runs on a worker thread. Its internal timeout is
per backend, so twenty stalled connections would still add up to twenty
timeouts of wall time on the GUI thread.
"""

from __future__ import annotations

import logging

from PyQt6.QtCore import QObject, Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.dashboard import DashboardSnapshot, HostRow
from ui.format_utils import human_bytes

log = logging.getLogger(__name__)

#: Rendered for every value that was not measured.
DASH = "—"

#: Column order of the table.
COLUMNS = ("Backend", "Protocol", "Total", "Used", "Free", "Usage")

_UNSUPPORTED = "not supported"


def usage_percent(row: HostRow) -> int | None:
    """Percentage of ``row``'s filesystem in use, or ``None``.

    ``None`` means "not measured" — an unimplemented ``disk_usage()`` or
    a timed-out probe, both of which surface as a zero total. It is
    explicitly not the same as 0 %.

    The result is clamped to 100: ext4 reserves blocks for root, so
    ``used + free < total`` is routine, and some backends report a
    ``used`` larger than ``total`` outright. Neither should render as
    143 %.
    """
    total = row.capacity_total
    if total <= 0:
        return None
    return max(0, min(100, round(row.capacity_used * 100 / total)))


def capacity_cells(row: HostRow) -> dict[str, str]:
    """Display strings for one row, keyed by column name."""
    percent = usage_percent(row)
    measured = percent is not None
    return {
        "Backend": row.label or DASH,
        "Protocol": row.protocol or DASH,
        "Total": human_bytes(row.capacity_total) if measured else DASH,
        "Used": human_bytes(row.capacity_used) if measured else DASH,
        "Free": human_bytes(row.capacity_free) if measured else DASH,
        "Usage": f"{percent}%" if measured else _UNSUPPORTED,
    }


def collect_backends(panes) -> list:
    """The distinct backends behind a list of file panes.

    Reads the public ``backend`` property, not the private attribute
    behind it — a cross-module reach into another widget's internals
    breaks silently the day it is renamed.

    Deduplicated by identity: two panes browsing the same host share one
    backend instance through the connection manager, and probing it
    twice would both double the wall time and list the same filesystem
    as two connections. Panes without a backend (still connecting, or a
    non-file pane) are skipped rather than raising.
    """
    seen: set[int] = set()
    backends: list = []
    for pane in panes:
        backend = getattr(pane, "backend", None)
        if backend is None or id(backend) in seen:
            continue
        seen.add(id(backend))
        backends.append(backend)
    return backends


def _default_snapshot(backends) -> DashboardSnapshot:
    from core.dashboard import snapshot_with_backends

    return snapshot_with_backends(backends)


class _SnapshotWorker(QObject):
    """Runs the capacity snapshot off the GUI thread."""

    done = pyqtSignal(object, str)  # snapshot | None, error text

    def __init__(self, backends, snapshot_fn) -> None:
        super().__init__()
        self._backends = backends
        self._snapshot_fn = snapshot_fn

    def run(self) -> None:
        try:
            self.done.emit(self._snapshot_fn(self._backends), "")
        except Exception as exc:  # noqa: BLE001 — a broken probe must not kill the dialog
            log.debug("disk usage snapshot failed: %s", exc)
            self.done.emit(None, str(exc))


class DiskUsageDialog(QDialog):
    """Capacity table over all open connections."""

    def __init__(self, backends, parent: QWidget | None = None, *, snapshot_fn=None):
        super().__init__(parent)
        self._backends = list(backends)
        self._snapshot_fn = snapshot_fn or _default_snapshot
        self._rows: list[HostRow] = []
        self._thread: QThread | None = None
        self._worker: _SnapshotWorker | None = None

        self.setWindowTitle("Disk Usage")
        self.resize(720, 380)
        self._build()
        self.refresh()

    # -- construction ----------------------------------------------------

    def _build(self) -> None:
        layout = QVBoxLayout(self)

        self._table = QTableWidget(0, len(COLUMNS), self)
        self._table.setHorizontalHeaderLabels(list(COLUMNS))
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self._table)

        bottom = QHBoxLayout()
        self._status = QLabel(self)
        self._status.setStyleSheet("color: #666;")
        bottom.addWidget(self._status, stretch=1)

        self._refresh_btn = QPushButton("Refresh", self)
        self._refresh_btn.clicked.connect(self.refresh)
        bottom.addWidget(self._refresh_btn)
        layout.addLayout(bottom)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    # -- data ------------------------------------------------------------

    def refresh(self) -> None:
        if self._thread is not None:
            return
        self._refresh_btn.setEnabled(False)
        self._status.setText("measuring…")

        self._thread = QThread(self)
        self._worker = _SnapshotWorker(self._backends, self._snapshot_fn)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.done.connect(self._on_snapshot)
        self._thread.start()

    def _on_snapshot(self, snap: DashboardSnapshot | None, error: str) -> None:
        self._rows = list(snap.rows) if snap is not None else []
        self._populate()
        if error:
            self._status.setText(f"Could not read capacity: {error}")
        elif not self._rows:
            self._status.setText("No open connections to measure.")
        else:
            unmeasured = sum(1 for r in self._rows if usage_percent(r) is None)
            text = f"{len(self._rows)} connection(s)"
            if unmeasured:
                text += f", {unmeasured} without capacity reporting"
            self._status.setText(text)
        self._refresh_btn.setEnabled(True)
        self._stop_thread()

    def _populate(self) -> None:
        self._table.setRowCount(len(self._rows))
        for row_idx, row in enumerate(self._rows):
            cells = capacity_cells(row)
            for col_idx, column in enumerate(COLUMNS):
                if column == "Usage":
                    self._table.setCellWidget(row_idx, col_idx, self._usage_widget(row))
                    continue
                item = QTableWidgetItem(cells[column])
                if column in ("Total", "Used", "Free"):
                    item.setTextAlignment(
                        Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
                    )
                self._table.setItem(row_idx, col_idx, item)

    def _usage_widget(self, row: HostRow) -> QWidget:
        percent = usage_percent(row)
        if percent is None:
            # No bar at all: a 0 %-filled bar reads as "empty disk",
            # which is precisely the claim we cannot make.
            label = QLabel(_UNSUPPORTED)
            label.setStyleSheet("color: #888;")
            return label
        bar = QProgressBar()
        bar.setRange(0, 100)
        bar.setValue(percent)
        bar.setFormat(f"{percent}%")
        bar.setTextVisible(True)
        return bar

    # -- introspection (used by tests and callers) -----------------------

    def displayed_labels(self) -> list[str]:
        return [row.label for row in self._rows]

    def displayed_cells(self) -> list[dict[str, str]]:
        return [capacity_cells(row) for row in self._rows]

    def status_text(self) -> str:
        return self._status.text()

    def wait_for_refresh(self, timeout_ms: int = 10000) -> None:
        """Block until a running snapshot has finished."""
        from PyQt6.QtCore import QCoreApplication, QDeadlineTimer, QEventLoop

        deadline = QDeadlineTimer(timeout_ms)
        while self._thread is not None and not deadline.hasExpired():
            # WaitForMoreEvents blocks until something actually happens
            # instead of spinning. A bare processEvents() loop pegs a
            # core for the whole wait, which on a slow remote walk is
            # seconds of a busy CPU doing nothing.
            QCoreApplication.processEvents(
                QEventLoop.ProcessEventsFlag.WaitForMoreEvents, 50
            )

    # -- lifecycle -------------------------------------------------------

    def _stop_thread(self) -> None:
        """Wind the worker down without dropping a live QThread.

        The snapshot itself cannot be interrupted — its budget lives in
        core.dashboard's per-backend timeout — so the reference is kept
        until the thread actually ends rather than being cleared while
        it runs, which Qt answers with an abort.
        """
        if self._thread is None:
            return
        self._thread.quit()
        if not self._thread.wait(5000):
            # A late `done` must not reach a dialog that is on its way
            # out: exec() returns, the last Python reference goes, and
            # the slot would fire on a deleted C++ object.
            if self._worker is not None:
                try:
                    self._worker.done.disconnect()
                except TypeError:  # already disconnected
                    pass
            log.warning("disk usage: snapshot still running; not discarding the thread")
            return
        self._thread = None
        self._worker = None

    def reject(self) -> None:  # noqa: D102 - Qt override
        self._stop_thread()
        super().reject()


__all__ = [
    "COLUMNS",
    "DiskUsageDialog",
    "capacity_cells",
    "collect_backends",
    "usage_percent",
]
