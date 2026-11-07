"""The Bluetooth panel's *Presence…* dialog: when were which devices in range.

Over a chosen period (last hour ... everything) it lists every device the
presence log (core.bluetooth_presence) heard: in range now, last seen,
time in range, sessions, average signal. The selected device's sessions
are listed below it and drawn on a timeline, over a grey band of the
times anybody scanned (outside them, "absent" only means nobody looked).
*Keep scanning* keeps a scan running for a log over hours; the log goes to
CSV (the sessions) or JSON (devices, sessions and listening periods).
"""

from __future__ import annotations

import logging
import time

from PyQt6.QtCore import QRectF, QSize, Qt, QTimer
from PyQt6.QtGui import QColor, QPainter
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import bluetooth_presence as BP
from core.i18n import tr
from ui.off_gui import run_off_gui
from ui.close_corner import add_close_corner
from ui.icon_provider import set_window_icon

log = logging.getLogger(__name__)

#: (label, seconds back; None: everything kept)
PERIODS = (("Last hour", 3600), ("Last 24 hours", 86400), ("Last 7 days", 7 * 86400),
           ("Last 30 days", 30 * 86400), ("Everything", None))
DEVICE_COLUMNS = ("Name", "Address", "Vendor", "Now", "Last seen", "In range", "Sessions",
                  "Signal")
(DC_NAME, DC_ADDRESS, DC_VENDOR, DC_NOW, DC_LAST, DC_PRESENT, DC_SESSIONS,
 DC_SIGNAL) = range(len(DEVICE_COLUMNS))
SESSION_COLUMNS = ("Start", "End", "Duration", "Signal (min / avg / max)", "Connected")
#: The table follows the log at least this often while shown (ms).
REFRESH_MS = 5000


def when_text(t: float, now: float) -> str:
    """"10:15:02" today, "Mon 10:15" this week, else "2026-10-28 10:15"."""
    lt, ln = time.localtime(t), time.localtime(now)
    if lt.tm_yday == ln.tm_yday and lt.tm_year == ln.tm_year:
        return time.strftime("%H:%M:%S", lt)
    if now - t < 6 * 86400:
        return time.strftime("%a %H:%M", lt)
    return time.strftime("%Y-%m-%d %H:%M", lt)


def signal_text(rssi_min, rssi_avg, rssi_max) -> str:
    if rssi_avg is None:
        return ""
    return f"{rssi_min} / {rssi_avg:.0f} / {rssi_max} dBm"


class Timeline(QWidget):
    """One device's sessions over the period, on the listening periods."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumHeight(34)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.since = 0.0
        self.until = 1.0
        self.spans: list[tuple[float, float]] = []
        self.listening: list[tuple[float, float]] = []

    def sizeHint(self) -> QSize:  # noqa: N802 - Qt override
        return QSize(400, 34)

    def set_data(self, since: float, until: float, spans, listening) -> None:
        self.since, self.until = since, max(until, since + 1.0)
        self.spans = list(spans)
        self.listening = list(listening)
        self.update()

    def _x(self, t: float, width: float) -> float:
        return (min(max(t, self.since), self.until) - self.since) / (self.until - self.since) \
            * width

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt override
        painter = QPainter(self)
        width, height = float(self.width()), float(self.height())
        bar = QRectF(0, 4, width, height - 8)
        pal = self.palette()
        painter.fillRect(bar, pal.base())
        grey = QColor(pal.text().color())
        grey.setAlpha(40)
        for start, end in self.listening:
            x0, x1 = self._x(start, width), self._x(end, width)
            painter.fillRect(QRectF(x0, bar.top(), max(1.0, x1 - x0), bar.height()), grey)
        colour = QColor(22, 163, 74)
        for start, end in self.spans:
            x0, x1 = self._x(start, width), self._x(end, width)
            painter.fillRect(QRectF(x0, bar.top() + 3, max(2.0, x1 - x0), bar.height() - 6),
                             colour)
        painter.setPen(pal.mid().color())
        painter.drawRect(bar.adjusted(0, 0, -1, -1))
        painter.end()


class PresenceDialog(QDialog):
    def __init__(self, presence: BP.PresenceLog, *, adapter=None, ask_save=None,
                 parent: QWidget | None = None) -> None:
        """*adapter()*: the adapter path to monitor on (the panel's current
        one). *ask_save(title, name, filter)*: the file to export to, "" to
        cancel (a seam; QFileDialog without)."""
        super().__init__(parent)
        set_window_icon(self, "bluetooth")
        self.setWindowTitle(tr("Bluetooth Presence"))
        self.presence = presence
        self._adapter = adapter or (lambda: None)
        self._ask_save = ask_save
        self._summaries: list[BP.Summary] = []
        self._selected: str | None = None

        layout = QVBoxLayout(self)
        top = QHBoxLayout()
        self.monitor_check = QCheckBox(tr("Keep scanning"))
        self.monitor_check.setToolTip(tr("Keep a scan running so the log covers the whole time, "
                                         "also after the adapter was off. Devices are heard "
                                         "only while somebody scans."))
        self.monitor_check.setChecked(presence.monitoring is not None)
        self.monitor_check.toggled.connect(self._monitor_toggled)
        top.addWidget(self.monitor_check)
        self.period_combo = QComboBox()
        for label, seconds in PERIODS:
            self.period_combo.addItem(tr(label), seconds)
        self.period_combo.setCurrentIndex(1)
        self.period_combo.currentIndexChanged.connect(lambda _i: self.refresh())
        top.addWidget(self.period_combo)
        self.paired_check = QCheckBox(tr("Paired only"))
        self.paired_check.setToolTip(tr("Only your own (paired) devices. Unpaired phones and "
                                        "many BLE devices change their address every few "
                                        "minutes; each address is a device of its own."))
        self.paired_check.toggled.connect(lambda _on: self.refresh())
        top.addWidget(self.paired_check)
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText(tr("Filter by name, address or vendor…"))
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.textChanged.connect(lambda _t: self.refresh())
        top.addWidget(self.search_edit, 1)
        layout.addLayout(top)

        self.devices = QTableWidget(0, len(DEVICE_COLUMNS))
        self.devices.setHorizontalHeaderLabels([tr(c) for c in DEVICE_COLUMNS])
        self.sessions = QTableWidget(0, len(SESSION_COLUMNS))
        self.sessions.setHorizontalHeaderLabels([tr(c) for c in SESSION_COLUMNS])
        for table in (self.devices, self.sessions):
            table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
            table.verticalHeader().setVisible(False)
            table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
            table.horizontalHeader().setStretchLastSection(True)
        self.devices.itemSelectionChanged.connect(self._selection_changed)
        lower = QWidget()
        lower_layout = QVBoxLayout(lower)
        lower_layout.setContentsMargins(0, 0, 0, 0)
        self.timeline_label = QLabel("")
        self.timeline_label.setTextFormat(Qt.TextFormat.PlainText)
        lower_layout.addWidget(self.timeline_label)
        self.timeline = Timeline()
        self.timeline.setToolTip(tr("Green: in range. Grey: somebody was scanning - outside "
                                    "the grey nobody looked."))
        lower_layout.addWidget(self.timeline)
        lower_layout.addWidget(self.sessions, 1)
        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(self.devices)
        split.addWidget(lower)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        layout.addWidget(split, 1)

        self.info = QLabel("")
        self.info.setTextFormat(Qt.TextFormat.PlainText)
        self.info.setWordWrap(True)
        layout.addWidget(self.info)
        buttons = QHBoxLayout()
        self.csv_button = QPushButton(tr("Export CSV…"))
        self.csv_button.setToolTip(tr("The sessions of the devices listed, one per line."))
        self.csv_button.clicked.connect(lambda: self.export("csv"))
        self.json_button = QPushButton(tr("Export JSON…"))
        self.json_button.setToolTip(tr("The devices listed, their sessions and the times "
                                       "somebody was scanning."))
        self.json_button.clicked.connect(lambda: self.export("json"))
        self.clear_button = QPushButton(tr("Clear Log…"))
        self.clear_button.clicked.connect(self._clear_clicked)
        close = QPushButton(tr("Close"))
        close.clicked.connect(self.close)
        for button in (self.csv_button, self.json_button, self.clear_button):
            buttons.addWidget(button)
        buttons.addStretch(1)
        buttons.addWidget(close)
        layout.addLayout(buttons)

        presence.changed.connect(self.refresh)
        presence.monitoring_changed.connect(self._monitoring_changed)
        self._timer = QTimer(self)
        self._timer.setInterval(REFRESH_MS)
        self._timer.timeout.connect(self.refresh)
        self.resize(820, 560)
        self.refresh()
        add_close_corner(self)

    # -- what is shown -----------------------------------------------------------------------

    def period(self) -> tuple[float | None, float]:
        now = time.time()
        back = self.period_combo.currentData()
        return (now - back if back is not None else None), now

    def shown(self) -> list[BP.Summary]:
        since, until = self.period()
        needle = self.search_edit.text().strip().lower()
        out = []
        for sm in self.presence.summaries(since, until):
            if self.paired_check.isChecked() and not sm.paired:
                continue
            if needle and needle not in " ".join((sm.name, sm.address, sm.vendor,
                                                  sm.kind)).lower():
                continue
            out.append(sm)
        return out

    def refresh(self) -> None:
        now = time.time()
        self._summaries = self.shown()
        table = self.devices
        table.setUpdatesEnabled(False)
        try:
            table.setRowCount(len(self._summaries))
            for row, sm in enumerate(self._summaries):
                cells = (sm.name or tr("(no name)"), sm.address, sm.vendor,
                         "●" if sm.present_now else "", when_text(sm.last, now),
                         BP.duration_text(sm.present), str(sm.sessions),
                         f"{sm.rssi_avg:.0f} dBm" if sm.rssi_avg is not None else "")
                for col, text in enumerate(cells):
                    item = table.item(row, col)
                    if item is None:
                        item = QTableWidgetItem()
                        table.setItem(row, col, item)
                    if item.text() != text:
                        item.setText(text)
                table.item(row, DC_NAME).setData(Qt.ItemDataRole.UserRole, sm.address)
                table.item(row, DC_NOW).setToolTip(tr("In range now") if sm.present_now else "")
            rows = [r for r, sm in enumerate(self._summaries) if sm.address == self._selected]
            if rows:
                table.selectRow(rows[0])
            else:
                table.clearSelection()
        finally:
            table.setUpdatesEnabled(True)
        listening = self.presence.listening(*self.period())
        heard = sum(p.end - p.start for p in listening)
        self.info.setText(tr("{n} devices · somebody scanned for {time} of this period{monitor}")
                          .format(n=len(self._summaries), time=BP.duration_text(heard),
                                  monitor=tr(" · keeping a scan running")
                                  if self.presence.monitoring else "")
                          + (("\n" + tr("The log cannot be written: {error}").format(
                              error=self.presence.write_error))
                             if self.presence.write_error else ""))
        has = bool(self._summaries)
        self.csv_button.setEnabled(has)
        self.json_button.setEnabled(has)
        self._fill_sessions()

    def _selection_changed(self) -> None:
        rows = {i.row() for i in self.devices.selectedItems()}
        self._selected = self._summaries[min(rows)].address if rows and \
            min(rows) < len(self._summaries) else None
        self._fill_sessions()

    def _fill_sessions(self) -> None:
        since, until = self.period()
        sm = next((s for s in self._summaries if s.address == self._selected), None)
        sessions = [s for s in self.presence.sessions(since, until)
                    if sm is not None and s.address == sm.address]
        self.sessions.setRowCount(len(sessions))
        now = time.time()
        for row, s in enumerate(reversed(sessions)):
            cells = (when_text(s.start, now), when_text(s.end, now),
                     BP.duration_text(s.duration),
                     signal_text(s.rssi_min, s.rssi_avg, s.rssi_max),
                     tr("yes") if s.connected else "")
            for col, text in enumerate(cells):
                self.sessions.setItem(row, col, QTableWidgetItem(text))
        start = since if since is not None else min((s.start for s in sessions), default=until)
        self.timeline.set_data(start, until, sm.spans if sm is not None else [],
                               [(p.start, p.end) for p in self.presence.listening(since, until)])
        self.timeline_label.setText(tr("{name}: in range {time} in {n} sessions").format(
            name=sm.name or sm.address, time=BP.duration_text(sm.present), n=sm.sessions)
            if sm is not None else tr("Select a device to see when it was in range."))

    # -- actions -----------------------------------------------------------------------------

    def _monitor_toggled(self, on: bool) -> None:
        adapter = self._adapter() if on else None
        if on and adapter is None:
            self.monitor_check.setChecked(False)
            self.info.setText(tr("No Bluetooth adapter to scan with."))
            return
        self.presence.set_monitoring(adapter)

    def _monitoring_changed(self, on: bool) -> None:
        if self.monitor_check.isChecked() != on:
            self.monitor_check.blockSignals(True)
            self.monitor_check.setChecked(on)
            self.monitor_check.blockSignals(False)
        self.refresh()

    def _save_path(self, kind: str) -> str:
        name = time.strftime(f"bluetooth-presence-%Y%m%d-%H%M.{kind}")
        filt = "CSV (*.csv)" if kind == "csv" else "JSON (*.json)"
        title = tr("Export CSV") if kind == "csv" else tr("Export JSON")
        if self._ask_save is not None:
            return self._ask_save(title, name, filt) or ""
        path, _f = QFileDialog.getSaveFileName(self, title, name, filt)
        return path or ""

    def export(self, kind: str) -> bool:
        path = self._save_path(kind)
        if not path:
            return False
        since, until = self.period()
        wanted = {sm.address for sm in self._summaries}
        sessions = [s for s in self.presence.sessions(since, until) if s.address in wanted]
        listening = self.presence.listening(since, until)
        present = self.presence.present()
        try:
            if kind == "csv":
                count = run_off_gui(lambda: BP.export_csv(path, sessions))
            else:
                count = run_off_gui(lambda: BP.export_json(path, sessions, listening=listening,
                                                           since=since, until=until,
                                                           present=present))
        except OSError as exc:
            self.info.setText(tr("Export failed: {error}").format(error=exc))
            return False
        self.info.setText(tr("{n} sessions written to {path}.").format(n=count, path=path))
        return True

    def _clear_clicked(self) -> None:
        box = QMessageBox(QMessageBox.Icon.Warning, tr("Clear Log"),
                          tr("Forget every device's sessions and the scanning times? This "
                             "cannot be undone."), QMessageBox.StandardButton.Cancel, self)
        clear = box.addButton(tr("Clear Log"), QMessageBox.ButtonRole.DestructiveRole)
        box.exec()
        if box.clickedButton() is clear:
            self.presence.clear()
            self.refresh()

    def showEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().showEvent(event)
        self._timer.start()
        self.refresh()

    def hideEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().hideEvent(event)
        self._timer.stop()

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt override
        self._timer.stop()
        for signal, slot in ((self.presence.changed, self.refresh),
                             (self.presence.monitoring_changed, self._monitoring_changed)):
            try:
                signal.disconnect(slot)
            except (TypeError, RuntimeError):
                pass
        super().closeEvent(event)


__all__ = ["PERIODS", "PresenceDialog", "Timeline", "signal_text", "when_text"]
