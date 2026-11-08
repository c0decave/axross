"""The Bluetooth panel's *Streams…* dialog: the connections and channels
in an HCI capture, and their traffic over time.

Open a btsnoop capture (``btmon -w``, Android's ``btsnoop_hci.log``,
Bumble's snooper); core.bluetooth_stream splits it into links and L2CAP
channels and names each channel's protocol (ATT/GATT, SMP, SDP, RFCOMM,
AVDTP = A2DP audio, AVCTP = remote control, HID ...). The selected
stream's bytes per second are drawn below; *Follow* re-reads a capture
that is still being written. *Visualize* shows the traffic with the
media player's visualizations: each bar is one stream of the selected
link (or of all), its height the stream's rate, replayed in real time.
"""

from __future__ import annotations

import logging
import os
import time

from PyQt6.QtCore import QPoint, QRectF, QSize, Qt, QTimer
from PyQt6.QtGui import QColor, QPainter
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import bluetooth_stream as BS
from core.bluetooth_presence import duration_text
from core.i18n import tr
from ui.off_gui import run_off_gui
from ui.close_corner import add_close_corner
from ui.icon_provider import set_window_icon

log = logging.getLogger(__name__)

LINK_COLUMNS = ("Address", "Radio", "Role", "Start", "Duration")
STREAM_COLUMNS = ("Address", "Protocol", "Direction", "Frames", "Bytes", "Rate", "Operations")
(SC_ADDRESS, SC_PROTOCOL, SC_DIRECTION, SC_FRAMES, SC_BYTES, SC_RATE,
 SC_OPS) = range(len(STREAM_COLUMNS))
#: How often Follow re-reads the capture (ms).
FOLLOW_MS = 2000
#: A capture larger than this is not read (bytes).
MAX_CAPTURE = 256 * 1024 * 1024


def size_text(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return ""


def ops_text(att: dict) -> str:
    return ", ".join(f"{tr(k)} {v}" for k, v in sorted(att.items(), key=lambda kv: -kv[1]))


def load_capture(path: str) -> BS.StreamParser:
    """The capture at *path*, parsed (raises OSError / ValueError)."""
    size = os.path.getsize(path)
    if size > MAX_CAPTURE:
        raise ValueError(tr("The capture is larger than {size}.").format(
            size=size_text(MAX_CAPTURE)))
    return BS.parse_file(path)


class RateGraph(QWidget):
    """Bytes per second of one stream (and its other direction), as bars."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumHeight(80)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.series: list[tuple[list[float], QColor]] = []

    def sizeHint(self) -> QSize:  # noqa: N802 - Qt override
        return QSize(400, 90)

    def set_series(self, series) -> None:
        self.series = list(series)
        self.update()

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt override
        painter = QPainter(self)
        rect = QRectF(self.rect()).adjusted(1, 1, -1, -1)
        painter.fillRect(rect, self.palette().base())
        top = max((max(values, default=0.0) for values, _c in self.series), default=0.0)
        if top <= 0:
            painter.setPen(self.palette().placeholderText().color())
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, tr("No traffic to show."))
            return
        for n, (values, colour) in enumerate(self.series):
            if not values:
                continue
            width = rect.width() / len(values)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(colour)
            for i, value in enumerate(values):
                h = (rect.height() - 2) * value / top
                x = rect.left() + i * width + (width / 2 if n else 0)
                painter.drawRect(QRectF(x, rect.bottom() - h, max(1.0, width / 2), h))
        label = tr("{rate}/s at most").format(rate=size_text(top))
        box = painter.fontMetrics().boundingRect(label).adjusted(-4, -2, 4, 2)
        box.moveTopRight(rect.toRect().topRight() + QPoint(-2, 2))
        painter.fillRect(box, self.palette().base())
        painter.setPen(self.palette().text().color())
        painter.drawText(box, Qt.AlignmentFlag.AlignCenter, label)


class TrafficEngine:
    """What the media player's Visualizer asks an engine for, from streams:
    :meth:`current_bars` - one bar per stream, its rate over the last
    second of the replay against the busiest; :meth:`current_samples` - a
    tone per stream as loud as its rate (for the scopes and the VU meter).
    The capture is replayed in real time from :meth:`restart` on, looping."""

    WINDOW = 1.0
    RATE = 48000
    FRAMES = 1024

    def __init__(self, streams, clock=time.monotonic) -> None:
        self.streams = [s for s in streams if s.samples]
        self._clock = clock
        starts = [s.samples[0][0] for s in self.streams]
        ends = [s.samples[-1][0] for s in self.streams]
        self.begin = min(starts, default=0.0)
        self.length = max(1.0, max(ends, default=0.0) - self.begin + self.WINDOW)
        self.top = max((max(BS.rate_series(s, self.WINDOW), default=0.0)
                        for s in self.streams), default=0.0) or 1.0
        # per stream: the frame times and the running byte total, so a frame
        # of the visualizer (30 a second) is two binary searches, not a scan
        self._times = [[when for when, _size in s.samples] for s in self.streams]
        self._totals = []
        for s in self.streams:
            total, running = 0, [0]
            for _when, size in s.samples:
                total += size
                running.append(total)
            self._totals.append(running)
        self.restart()

    def restart(self) -> None:
        self._t0 = self._clock()

    def now(self) -> float:
        """The capture time the replay is at."""
        return self.begin + (self._clock() - self._t0) % self.length

    def levels(self) -> list[float]:
        from bisect import bisect_right

        t = self.now()
        out = []
        for times, totals in zip(self._times, self._totals):
            got = totals[bisect_right(times, t)] - totals[bisect_right(times, t - self.WINDOW)]
            out.append(min(1.0, got / self.WINDOW / self.top))
        return out

    def current_bars(self, n: int):
        levels = self.levels()
        if not levels:
            return [0.0] * n
        # spread the streams over the bars, each a block of bars
        return [levels[min(len(levels) - 1, i * len(levels) // n)] for i in range(n)]

    def current_samples(self):
        try:
            import numpy as np
        except ImportError:
            return None
        levels = self.levels()
        t = np.arange(self.FRAMES, dtype=np.float32) / self.RATE
        left = np.zeros(self.FRAMES, np.float32)
        right = np.zeros(self.FRAMES, np.float32)
        for i, (s, level) in enumerate(zip(self.streams, levels)):
            tone = level * np.sin(2 * np.pi * (220.0 * (i + 1)) * t).astype(np.float32)
            if s.direction == "out":
                left += tone
            else:
                right += tone
        scale = max(1, len(levels))
        return np.column_stack([left / scale, right / scale]).astype(np.float32)


def _media_player():
    """The media player extension's module (its Visualizer), or None."""
    try:
        from resources.extensions import media_player
    except Exception:  # noqa: BLE001 - no visualizer is no reason to fail
        log.info("the media player's visualizations are not available", exc_info=True)
        return None
    return media_player


class StreamsDialog(QDialog):
    def __init__(self, *, path: str | None = None, ask_open=None,
                 parent: QWidget | None = None) -> None:
        """*ask_open(title, filter)*: the capture to open, "" to cancel (a
        seam; QFileDialog without)."""
        super().__init__(parent)
        set_window_icon(self, "bluetooth")
        self.setWindowTitle(tr("Bluetooth Streams"))
        self._ask_open = ask_open
        self.path: str | None = None
        self.parsed: BS.StreamParser | None = None
        self._streams: list[BS.Stream] = []
        self._links: list[BS.Link] = []
        self._mtime = None
        self._reading = False
        self.visual_window = None
        self._left = False  # see _leave

        layout = QVBoxLayout(self)
        top = QHBoxLayout()
        self.open_button = QPushButton(tr("Open Capture…"))
        self.open_button.setToolTip(tr("A btsnoop file: btmon -w FILE, Android's "
                                       "btsnoop_hci.log, or another HCI capture."))
        self.open_button.clicked.connect(self._open_clicked)
        top.addWidget(self.open_button)
        self.follow_check = QCheckBox(tr("Follow"))
        self.follow_check.setToolTip(tr("Read the capture again every few seconds while it "
                                        "is being written."))
        self.follow_check.toggled.connect(self._follow_toggled)
        top.addWidget(self.follow_check)
        self.visual_button = QPushButton(tr("Visualize"))
        self.visual_button.setToolTip(tr("The traffic of the selected link (or of all) with "
                                         "the media player's visualizations: a bar per "
                                         "stream, as high as its rate."))
        self.visual_button.clicked.connect(self.visualize)
        top.addWidget(self.visual_button)
        top.addStretch(1)
        layout.addLayout(top)

        self.links = QTableWidget(0, len(LINK_COLUMNS))
        self.links.setHorizontalHeaderLabels([tr(c) for c in LINK_COLUMNS])
        self.table = QTableWidget(0, len(STREAM_COLUMNS))
        self.table.setHorizontalHeaderLabels([tr(c) for c in STREAM_COLUMNS])
        for table in (self.links, self.table):
            table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
            table.verticalHeader().setVisible(False)
            table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
            table.horizontalHeader().setStretchLastSection(True)
        self.links.itemSelectionChanged.connect(self._fill_streams)
        self.table.itemSelectionChanged.connect(self._fill_graph)
        self.graph = RateGraph()
        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(self.links)
        split.addWidget(self.table)
        split.setStretchFactor(0, 1)
        split.setStretchFactor(1, 3)
        layout.addWidget(split, 1)
        layout.addWidget(self.graph)
        self.info = QLabel(tr("Open a capture to see its connections and channels."))
        self.info.setTextFormat(Qt.TextFormat.PlainText)
        self.info.setWordWrap(True)
        layout.addWidget(self.info)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        close = QPushButton(tr("Close"))
        close.clicked.connect(self.close)
        buttons.addWidget(close)
        layout.addLayout(buttons)

        self._follow = QTimer(self)
        self._follow.setInterval(FOLLOW_MS)
        self._follow.timeout.connect(self._follow_tick)
        self.resize(860, 600)
        self.visual_button.setEnabled(False)
        if path:
            self.open_capture(path)
        add_close_corner(self)

    # -- the capture ---------------------------------------------------------------------

    def _open_clicked(self) -> None:
        title, filt = tr("Open Capture"), tr("HCI captures (*.btsnoop *.log *.cfa *.snoop);;"
                                             "All files (*)")
        if self._ask_open is not None:
            path = self._ask_open(title, filt) or ""
        else:
            path, _f = QFileDialog.getOpenFileName(self, title, "", filt)
        if path:
            self.open_capture(path)

    def open_capture(self, path: str) -> bool:
        self._reading = True
        try:
            parsed = run_off_gui(lambda: load_capture(path))
        except (OSError, ValueError) as exc:
            self.info.setText(tr("{path} cannot be read: {error}").format(path=path, error=exc))
            return False
        finally:
            self._reading = False
        self.path, self.parsed = path, parsed
        try:
            self._mtime = os.stat(path).st_mtime_ns
        except OSError:
            self._mtime = None
        self._fill_links()
        links = parsed.all_links()
        self.info.setText(tr("{packets} packets, {links} connections, {streams} streams"
                             "{errors}").format(
            packets=parsed.packets, links=len(links), streams=len(parsed.streams),
            errors=tr(" · {n} packets not understood").format(n=parsed.errors)
            if parsed.errors else ""))
        self.visual_button.setEnabled(bool(parsed.streams))
        return True

    def _follow_toggled(self, on: bool) -> None:
        if on:
            self._follow.start()
        else:
            self._follow.stop()

    def _follow_tick(self) -> None:
        # reading runs off the GUI thread with an event loop of its own, in which
        # this timer fires again: one reading at a time
        if not self.path or self._reading:
            return
        try:
            mtime = os.stat(self.path).st_mtime_ns
        except OSError:
            return
        if mtime != self._mtime:
            selected = self._selected_link()
            self.open_capture(self.path)
            if selected is not None:
                self._select_link(selected)

    # -- the tables ----------------------------------------------------------------------

    def _fill_links(self) -> None:
        links = self.parsed.all_links() if self.parsed else []
        self._links = links
        self.links.blockSignals(True)
        self.links.setRowCount(len(links) + 1)
        all_item = QTableWidgetItem(tr("(all connections)"))
        self.links.setItem(0, 0, all_item)
        for col in range(1, len(LINK_COLUMNS)):
            self.links.setItem(0, col, QTableWidgetItem(""))
        last = max((s.last or 0.0 for s in self.parsed.streams.values()), default=0.0) \
            if self.parsed else 0.0
        for row, link in enumerate(links, start=1):
            end = link.end if link.end is not None else max(last, link.start)
            cells = (link.address, tr(link.radio), tr(link.role) if link.role else "",
                     time.strftime("%H:%M:%S", time.localtime(link.start)),
                     duration_text(end - link.start) + ("" if link.end is not None
                                                        else " " + tr("(open)")))
            for col, text in enumerate(cells):
                self.links.setItem(row, col, QTableWidgetItem(text))
        self.links.blockSignals(False)
        self.links.resizeColumnsToContents()
        self.links.selectRow(0)
        self._fill_streams()

    def _selected_link(self):
        rows = {i.row() for i in self.links.selectedItems()}
        if not rows or min(rows) == 0:
            return None
        index = min(rows) - 1
        return self._links[index] if index < len(self._links) else None

    def _select_link(self, link) -> None:
        for row, other in enumerate(self._links, start=1):
            if (other.key, other.start) == (link.key, link.start):
                self.links.selectRow(row)
                return

    def shown_streams(self) -> list[BS.Stream]:
        if self.parsed is None:
            return []
        link = self._selected_link()
        streams = self.parsed.sorted_streams()
        if link is None:
            return streams
        end = link.end if link.end is not None else float("inf")
        return [s for s in streams if (s.controller, s.handle) == link.key
                and s.first is not None and link.start <= s.first <= end]

    def _fill_streams(self) -> None:
        self._streams = self.shown_streams()
        self.table.blockSignals(True)
        self.table.setRowCount(len(self._streams))
        for row, s in enumerate(self._streams):
            cells = (s.address, tr(s.protocol), tr("sent") if s.direction == "out"
                     else tr("received"), str(s.frames), size_text(s.bytes),
                     size_text(s.rate) + "/s", ops_text(s.att))
            for col, text in enumerate(cells):
                self.table.setItem(row, col, QTableWidgetItem(text))
        self.table.blockSignals(False)
        self.table.resizeColumnsToContents()
        if self._streams:
            self.table.selectRow(0)
        self._fill_graph()

    def selected_stream(self) -> BS.Stream | None:
        rows = {i.row() for i in self.table.selectedItems()}
        if not rows or min(rows) >= len(self._streams):
            return None
        return self._streams[min(rows)]

    def _fill_graph(self) -> None:
        stream = self.selected_stream()
        if stream is None or self.parsed is None:
            self.graph.set_series([])
            return
        other = self.parsed.streams.get((stream.controller, stream.handle, stream.cid,
                                         "in" if stream.direction == "out" else "out"))
        pair = [s for s in (stream, other) if s is not None and s.samples]
        since = min(s.samples[0][0] for s in pair)
        until = max(s.samples[-1][0] for s in pair)
        colours = {"out": QColor(0x2E, 0x86, 0xDE), "in": QColor(0x27, 0xAE, 0x60)}
        bucket = max(0.25, (until - since) / 80)  # finer only splits a burst into gaps
        self.graph.set_series([(BS.rate_series(s, bucket, since, until),
                                colours[s.direction]) for s in pair])
        self.graph.setToolTip(tr("Blue: sent. Green: received."))

    # -- the visualizer ------------------------------------------------------------------

    def visualize(self):
        """The media player's Visualizer on the shown streams, in a window."""
        mp = _media_player()
        streams = self.shown_streams()
        if mp is None or not streams:
            self.info.setText(tr("The media player's visualizations are not available."))
            return None
        engine = TrafficEngine(streams)
        window = QWidget(self, Qt.WindowType.Window)
        window.setWindowTitle(tr("Bluetooth Traffic"))
        set_window_icon(window, "bluetooth")
        window.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        box = QVBoxLayout(window)
        box.setContentsMargins(0, 0, 0, 0)
        visual = mp.Visualizer(engine)
        box.addWidget(visual)
        window.resize(640, 360)
        window.engine, window.visualizer = engine, visual
        window.show()
        visual.timer.start()
        self.visual_window = window
        return window

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt override
        self._leave()
        super().closeEvent(event)

    def done(self, result: int) -> None:  # noqa: D401 - Qt override
        # reject() (Escape, the corner's [x]) ends here without a closeEvent
        self._leave()
        super().done(result)

    def _leave(self) -> None:
        """Once however the dialog is left (closeEvent, or reject() from
        Escape and the corner's [x], which sends none): following the
        capture stops and the visualizer window closes."""
        if self._left:
            return
        self._left = True
        self._follow.stop()
        if self.visual_window is not None:
            try:
                self.visual_window.close()
            except RuntimeError:
                pass


__all__ = ["RateGraph", "StreamsDialog", "TrafficEngine", "load_capture", "ops_text",
           "size_text"]
