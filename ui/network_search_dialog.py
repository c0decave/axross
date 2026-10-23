"""Tools > Find on Network Hosts (SMB)…: your files on many SMB hosts.

The dialog over :mod:`core.remote_sweep`: targets (host names, addresses,
CIDR blocks, ranges), one login, a name pattern, "only my files" and the
number of hosts searched at once. Results stream into a table while the
hosts are searched; a host table shows each host's state. Nothing is
written on any host.

From a result: open its folder in a new pane, analyse the file with sift
(the Analysis dock), copy its UNC path, or export every result as CSV.
"""

from __future__ import annotations

import csv
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime

from PyQt6.QtCore import QObject, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import remote_sweep as RS
from core.i18n import tr
from core.net_helpers import TargetError, parse_targets
from ui.close_corner import add_close_corner

log = logging.getLogger(__name__)

#: More hosts than this and the run asks first.
ASK_ABOVE_HOSTS = 256
_HIT_COLUMNS = ("UNC", "Size", "Modified", "Owner")


@dataclass(frozen=True)
class Login:
    """The credential a result came from, for opening or analysing it."""

    username: str
    password: str = field(repr=False)
    domain: str
    port: int


class _Bridge(QObject):
    """Carries the sweep's callbacks from its thread to the dialog."""

    hit = pyqtSignal(object)
    status = pyqtSignal(str, str, str)
    finished = pyqtSignal(object, str)  # SweepResult or None, error text


class NetworkSearchDialog(QDialog):
    def __init__(self, parent=None, *, sweep_fn=None, open_hit=None, analyse_hit=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Find on Network Hosts (SMB)"))
        self.resize(1000, 640)
        self._sweep = sweep_fn or RS.sweep
        self._open_hit = open_hit
        self._analyse_hit = analyse_hit
        self._cancel: threading.Event | None = None
        self._thread: threading.Thread | None = None
        self._login: Login | None = None
        self._hits: list[RS.SweepHit] = []
        self._host_rows: dict[str, int] = {}
        self._bridge = _Bridge(self)
        self._bridge.hit.connect(self._on_hit)
        self._bridge.status.connect(self._on_status)
        self._bridge.finished.connect(self._on_finished)
        self._build()
        add_close_corner(self)

    # -- layout ----------------------------------------------------------------------------

    def _build(self) -> None:
        root = QVBoxLayout(self)
        form = QFormLayout()
        self.targets_edit = QPlainTextEdit()
        self.targets_edit.setPlaceholderText(
            tr("Host names, IP addresses, CIDR blocks (10.0.0.0/24) or ranges (10.0.0.5-20), "
               "separated by spaces, commas or lines; # starts a comment")
        )
        self.targets_edit.setMaximumHeight(80)
        targets_row = QHBoxLayout()
        targets_row.addWidget(self.targets_edit)
        load = QPushButton(tr("Load…"))
        load.setToolTip(tr("Read the targets from a text file"))
        load.clicked.connect(self._load_targets)
        targets_row.addWidget(load, 0, Qt.AlignmentFlag.AlignTop)
        form.addRow(tr("Targets:"), targets_row)
        self.user_edit = QLineEdit()
        self.domain_edit = QLineEdit()
        self.domain_edit.setPlaceholderText(tr("optional, e.g. CORP"))
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow(tr("Username:"), self.user_edit)
        form.addRow(tr("Domain:"), self.domain_edit)
        form.addRow(tr("Password:"), self.password_edit)
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText(tr("*.docx, report-*, … (empty: every file)"))
        form.addRow(tr("File name:"), self.name_edit)
        options = QHBoxLayout()
        self.owner_check = QCheckBox(tr("Only my files"))
        self.owner_check.setToolTip(tr("Files whose owner is the account you log on with"))
        self.special_check = QCheckBox(tr("Include admin shares (C$, ADMIN$)"))
        options.addWidget(self.owner_check)
        options.addWidget(self.special_check)
        options.addStretch(1)
        form.addRow("", options)
        limits = QHBoxLayout()
        self.parallel_spin = QSpinBox()
        self.parallel_spin.setRange(1, RS.MAX_PARALLEL)
        self.parallel_spin.setValue(RS.parallel_hosts())
        self.remember_parallel_check = QCheckBox(tr("Remember as default"))
        self.depth_spin = QSpinBox()
        self.depth_spin.setRange(1, 64)
        self.depth_spin.setValue(RS.SweepConfig.max_depth)
        limits.addWidget(QLabel(tr("Hosts at once:")))
        limits.addWidget(self.parallel_spin)
        limits.addWidget(self.remember_parallel_check)
        limits.addSpacing(16)
        limits.addWidget(QLabel(tr("Folder depth:")))
        limits.addWidget(self.depth_spin)
        limits.addStretch(1)
        form.addRow("", limits)
        root.addLayout(form)

        notice = QLabel(tr("Read only: nothing is written on any host. A refused logon stops the "
                           "whole run, so a mistyped password cannot lock the account on every host."))
        notice.setWordWrap(True)
        root.addWidget(notice)

        buttons = QHBoxLayout()
        self.start_button = QPushButton(tr("Start"))
        self.start_button.setDefault(True)
        self.start_button.clicked.connect(self.start)
        self.cancel_button = QPushButton(tr("Cancel"))
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel)
        self.export_button = QPushButton(tr("Export CSV…"))
        self.export_button.clicked.connect(self._export_clicked)
        close = QPushButton(tr("Close"))
        close.clicked.connect(self.close)
        for button in (self.start_button, self.cancel_button, self.export_button):
            buttons.addWidget(button)
        buttons.addStretch(1)
        buttons.addWidget(close)
        root.addLayout(buttons)

        self.error_label = QLabel("")
        self.error_label.setWordWrap(True)
        self.error_label.setStyleSheet("color: #d03030;")
        root.addWidget(self.error_label)
        self.summary_label = QLabel("")
        root.addWidget(self.summary_label)

        split = QSplitter(Qt.Orientation.Horizontal)
        self.hosts_table = QTableWidget(0, 3)
        self.hosts_table.setHorizontalHeaderLabels([tr("Host"), tr("State"), tr("Detail")])
        self.results_table = QTableWidget(0, len(_HIT_COLUMNS))
        self.results_table.setHorizontalHeaderLabels([tr(c) for c in _HIT_COLUMNS])
        for table in (self.hosts_table, self.results_table):
            table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            table.verticalHeader().setVisible(False)
            table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
            table.horizontalHeader().setStretchLastSection(True)
        self.results_table.setSortingEnabled(True)
        self.results_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.results_table.customContextMenuRequested.connect(self._results_menu)
        self.results_table.doubleClicked.connect(lambda _index: self.open_selected())
        self.results_table.setColumnWidth(0, 420)
        hosts_box = QWidget()
        hosts_layout = QVBoxLayout(hosts_box)
        hosts_layout.setContentsMargins(0, 0, 0, 0)
        hosts_layout.addWidget(self.hosts_table)
        split.addWidget(hosts_box)
        split.addWidget(self.results_table)
        split.setSizes([300, 700])
        root.addWidget(split, 1)

    # -- run -------------------------------------------------------------------------------

    def is_running(self) -> bool:
        return self._cancel is not None

    def start(self) -> None:
        if self.is_running():
            return
        self.error_label.setText("")
        try:
            hosts = parse_targets(self.targets_edit.toPlainText())
        except TargetError as exc:
            self.error_label.setText(str(exc))
            return
        if len(hosts) > ASK_ABOVE_HOSTS:
            answer = QMessageBox.question(
                self,
                tr("Find on Network Hosts"),
                tr("Search {n} hosts with the login {user}?").format(
                    n=len(hosts), user=self.user_edit.text() or tr("(anonymous)")),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        if self.remember_parallel_check.isChecked():
            try:
                RS.set_parallel_hosts(self.parallel_spin.value())
            except (OSError, ValueError) as exc:
                log.warning("Could not store the parallel host count: %s", exc)
        config = RS.SweepConfig(
            targets=self.targets_edit.toPlainText(),
            username=self.user_edit.text(),
            password=self.password_edit.text(),
            domain=self.domain_edit.text().strip(),
            parallel=self.parallel_spin.value(),
            name=self.name_edit.text().strip(),
            owner_only=self.owner_check.isChecked(),
            include_special=self.special_check.isChecked(),
            max_depth=self.depth_spin.value(),
        )
        self._login = Login(config.username, config.password, config.domain, config.port)
        self._reset_tables(hosts)
        self._cancel = threading.Event()
        cancel, bridge, sweep = self._cancel, self._bridge, self._sweep

        def work() -> None:
            try:
                result = sweep(config, on_hit=bridge.hit.emit, on_status=bridge.status.emit, cancel=cancel)
                bridge.finished.emit(result, "")
            except Exception as exc:  # noqa: BLE001 - shown to the user, never raised in a thread
                text = str(exc) or type(exc).__name__
                if config.password:
                    text = text.replace(config.password, "***")
                bridge.finished.emit(None, text)

        self.start_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.summary_label.setText(tr("Searching {n} hosts…").format(n=len(hosts)))
        self._thread = threading.Thread(target=work, name="axross-network-search", daemon=True)
        self._thread.start()

    def cancel(self) -> None:
        if self._cancel is not None:
            self._cancel.set()
            self.cancel_button.setEnabled(False)
            self.summary_label.setText(tr("Cancelling…"))

    def _reset_tables(self, hosts: list[str]) -> None:
        self._hits.clear()
        self.results_table.setSortingEnabled(False)
        self.results_table.setRowCount(0)
        self.results_table.setSortingEnabled(True)
        self.hosts_table.setRowCount(len(hosts))
        self._host_rows = {}
        for row, host in enumerate(hosts):
            self._host_rows[host] = row
            self.hosts_table.setItem(row, 0, QTableWidgetItem(host))
            self.hosts_table.setItem(row, 1, QTableWidgetItem(tr("waiting")))
            self.hosts_table.setItem(row, 2, QTableWidgetItem(""))

    def _on_hit(self, hit: RS.SweepHit) -> None:
        self._hits.append(hit)
        table = self.results_table
        table.setSortingEnabled(False)
        row = table.rowCount()
        table.insertRow(row)
        unc = QTableWidgetItem(hit.unc)
        unc.setData(Qt.ItemDataRole.UserRole, len(self._hits) - 1)
        size = QTableWidgetItem()
        size.setData(Qt.ItemDataRole.DisplayRole, hit.size)
        when = datetime.fromtimestamp(hit.mtime).strftime("%Y-%m-%d %H:%M") if hit.mtime else ""
        for col, item in enumerate((unc, size, QTableWidgetItem(when), QTableWidgetItem(hit.owner_sid))):
            table.setItem(row, col, item)
        table.setSortingEnabled(True)

    def _on_status(self, host: str, state: str, detail: str) -> None:
        row = self._host_rows.get(host)
        if row is None:
            return
        self.hosts_table.item(row, 1).setText(tr(state))
        if detail:
            self.hosts_table.item(row, 2).setText(detail)

    def _on_finished(self, result, error: str) -> None:
        self._thread = None
        self._cancel = None
        self.start_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        if result is None:
            self.error_label.setText(error)
            self.summary_label.setText("")
            return
        if result.aborted:
            self.error_label.setText(tr("Stopped: the login was refused ({reason}). No other host "
                                        "was tried with it.").format(reason=result.abort_reason))
        parts = [tr("{n} files").format(n=len(self._hits)),
                 tr("{n} hosts searched").format(n=result.hosts_searched)]
        if result.hosts_unreachable:
            parts.append(tr("{n} unreachable").format(n=result.hosts_unreachable))
        if result.hosts_failed:
            parts.append(tr("{n} failed").format(n=result.hosts_failed))
        if result.truncated:
            parts.append(tr("limit reached on some hosts"))
        prefix = tr("Cancelled") + " - " if result.cancelled else ""
        self.summary_label.setText(prefix + ", ".join(parts))

    # -- results ---------------------------------------------------------------------------

    def _selected_hits(self) -> list[RS.SweepHit]:
        rows = sorted({index.row() for index in self.results_table.selectedIndexes()})
        out = []
        for row in rows:
            item = self.results_table.item(row, 0)
            if item is not None:
                out.append(self._hits[item.data(Qt.ItemDataRole.UserRole)])
        return out

    def open_selected(self) -> None:
        if self._open_hit is not None and self._login is not None:
            for hit in self._selected_hits()[:1]:
                self._open_hit(hit, self._login)

    def analyse_selected(self) -> None:
        if self._analyse_hit is not None and self._login is not None:
            for hit in self._selected_hits():
                self._analyse_hit(hit, self._login)

    def copy_selected(self) -> None:
        QApplication.clipboard().setText("\n".join(hit.unc for hit in self._selected_hits()))

    def _results_menu(self, pos) -> None:
        if not self._selected_hits():
            return
        menu = QMenu(self)
        if self._open_hit is not None:
            menu.addAction(tr("Open Folder in a Pane"), self.open_selected)
        if self._analyse_hit is not None:
            menu.addAction(tr("Analyse with sift"), self.analyse_selected)
        menu.addAction(tr("Copy UNC Path"), self.copy_selected)
        menu.exec(self.results_table.viewport().mapToGlobal(pos))

    def export_csv(self, path: str) -> None:
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(list(_HIT_COLUMNS))
            for hit in self._hits:
                when = datetime.fromtimestamp(hit.mtime).isoformat(timespec="seconds") if hit.mtime else ""
                writer.writerow([hit.unc, hit.size, when, hit.owner_sid])

    def _export_clicked(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, tr("Export CSV"), "network-search.csv", "CSV (*.csv)")
        if path:
            try:
                self.export_csv(path)
            except OSError as exc:
                self.error_label.setText(str(exc))

    def _load_targets(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, tr("Load Targets"), "", tr("Text files (*.txt);;All files (*)"))
        if not path:
            return
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                self.targets_edit.setPlainText(fh.read(256 * 1024))
        except OSError as exc:
            self.error_label.setText(str(exc))

    # -- close -----------------------------------------------------------------------------

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt
        self._stop_and_forget()
        super().closeEvent(event)

    def reject(self) -> None:
        # Esc hides the dialog through reject(), which sends no close event:
        # the run must stop and the password go here as well.
        self._stop_and_forget()
        super().reject()

    def _stop_and_forget(self) -> None:
        self.cancel()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=5.0)
        self.password_edit.clear()
