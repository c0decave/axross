"""A panel with every local and mounted drive: a table, a pie of the
selected drive and bars of all of them."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, replace

from PyQt6.QtCore import QRectF, Qt
from PyQt6.QtGui import QColor, QPainter
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.subprocess_env import clean_child_env

EXTENSION = {
    "name": "Drives Overview",
    "version": "1.0",
    "description": "A panel with every local and mounted drive - size, used, free - as a table, "
    "a pie of the selected drive and bars of all drives; double-click opens a drive.",
    "author": "axross",
}

#: Seconds a drive may take to answer before it counts as unknown.
TIMEOUT = 2.0
USED_COLOUR = "#d9534f"
FREE_COLOUR = "#5cb85c"
COLUMNS = ("Mount", "Device", "Type", "Size", "Used", "Free", "Use")
COL_MOUNT, COL_DEVICE, COL_TYPE, COL_SIZE, COL_USED, COL_FREE, COL_USE = range(len(COLUMNS))

NETWORK_FS = frozenset({
    "cifs", "smb3", "smbfs", "nfs", "nfs4", "afpfs", "webdav", "davfs", "fuse.sshfs", "sshfs",
    "fuse.rclone", "vboxsf", "9p", "virtiofs", "fuse.s3fs", "ceph", "glusterfs", "fuse.glusterfs",
})
MEMORY_FS = frozenset({"tmpfs", "ramfs", "devtmpfs"})
LOCAL_FS = frozenset({
    "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "jfs", "reiserfs", "ntfs", "ntfs3",
    "fuseblk", "vfat", "exfat", "msdos", "apfs", "hfs", "hfsplus", "iso9660", "udf", "bcachefs",
})
_REMOVABLE_ROOTS = ("/media/", "/run/media/", "/Volumes/")


@dataclass(frozen=True)
class Drive:
    mount: str
    device: str
    fstype: str
    kind: str  # local, network, removable, memory, system
    total: int | None = None
    used: int | None = None
    free: int | None = None
    error: str = ""

    @property
    def percent(self) -> float | None:
        if not self.total or self.used is None:
            return None
        return 100.0 * self.used / self.total


def _kind(device: str, mount: str, fstype: str) -> str:
    fstype = fstype.lower()
    if fstype in NETWORK_FS or device.startswith("//"):
        return "network"
    if fstype in MEMORY_FS:
        return "memory"
    if fstype in LOCAL_FS and (device.startswith("/dev/") or fstype in ("apfs", "hfs")):
        if mount.startswith(_REMOVABLE_ROOTS):
            return "removable"
        return "local"
    return "system"


def _unescape(field: str) -> str:
    """/proc/mounts escapes space, tab, newline and backslash as \\ooo."""
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), field)


def parse_proc_mounts(text: str) -> list[Drive]:
    """Drives of a /proc/self/mounts text; a device mounted twice (a bind
    mount) is listed once, at its first mount point."""
    drives: list[Drive] = []
    seen_devices: set[str] = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        device, mount, fstype = _unescape(fields[0]), _unescape(fields[1]), fields[2]
        if not mount.startswith("/"):
            continue
        kind = _kind(device, mount, fstype)
        if kind in ("local", "removable") and device in seen_devices:
            continue
        seen_devices.add(device)
        drives.append(Drive(mount, device, fstype, kind))
    return drives


_MOUNT_LINE = re.compile(r"^(?P<device>.+?) on (?P<mount>/.*?) \((?P<opts>[^)]*)\)\s*$")


def parse_mount_output(text: str) -> list[Drive]:
    """Drives of the macOS/BSD ``mount`` output ("dev on /path (type, opts)")."""
    drives = []
    for line in text.splitlines():
        match = _MOUNT_LINE.match(line.strip())
        if not match:
            continue
        opts = [o.strip() for o in match.group("opts").split(",")]
        fstype = opts[0] if opts else ""
        device, mount = match.group("device"), match.group("mount")
        kind = _kind(device, mount, fstype)
        if kind == "local" and "nobrowse" in opts:
            kind = "system"  # the APFS helper volumes under /System/Volumes
        drives.append(Drive(mount, device, fstype, kind))
    return drives


#: GetDriveTypeW: 2 removable, 3 fixed, 4 remote, 5 cdrom, 6 ramdisk.
_WIN_KINDS = {2: "removable", 3: "local", 4: "network", 5: "removable", 6: "memory"}


def windows_drives(roots: list[str], drive_type) -> list[Drive]:
    return [Drive(root, root, "", _WIN_KINDS.get(drive_type(root), "system")) for root in roots]


def list_drives() -> list[Drive]:
    """The drives of this machine, by platform."""
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/self/mounts", encoding="utf-8", errors="replace") as fh:
                return parse_proc_mounts(fh.read())
        except OSError:
            return [Drive("/", "", "", "local")]
    if sys.platform == "win32":
        import ctypes

        roots = list(os.listdrives()) if hasattr(os, "listdrives") else [
            f"{c}:\\" for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{c}:\\")]
        return windows_drives(roots, lambda root: ctypes.windll.kernel32.GetDriveTypeW(root))
    try:
        import psutil  # type: ignore[import-not-found] - optional, bundled in axross-full

        return [Drive(p.mountpoint, p.device, p.fstype, _kind(p.device, p.mountpoint, p.fstype))
                for p in psutil.disk_partitions(all=True)]
    except ImportError:
        pass
    mount = shutil.which("mount") or "/sbin/mount"
    try:
        out = subprocess.run([mount], capture_output=True, text=True, timeout=5,
                             env=clean_child_env()).stdout
    except (OSError, subprocess.SubprocessError):
        return [Drive("/", "", "", "local")]
    return parse_mount_output(out)


def _usage(path: str) -> tuple[int, int, int]:
    total, used, free = shutil.disk_usage(path)
    return total, used, free


def measure(drives: list[Drive], *, usage=_usage, timeout: float = TIMEOUT) -> list[Drive]:
    """Size, used and free of every drive, each probed on its own thread: a
    drive that does not answer within *timeout* (a dead network mount) is
    unknown with the reason, and the others are not held up."""
    results: dict[int, Drive] = {}

    def probe(index: int, drive: Drive) -> None:
        try:
            total, used, free = usage(drive.mount)
            results[index] = replace(drive, total=int(total), used=int(used), free=int(free))
        except Exception as exc:  # noqa: BLE001 - one drive, shown with its reason
            results[index] = replace(drive, error=str(exc) or type(exc).__name__)

    threads = []
    for index, drive in enumerate(drives):
        thread = threading.Thread(target=probe, args=(index, drive), daemon=True,
                                  name="axross-drive-probe")
        thread.start()
        threads.append(thread)
    deadline = time.monotonic() + timeout
    for thread in threads:
        thread.join(max(0.0, deadline - time.monotonic()))
    return [results.get(i, replace(d, error=f"timed out after {timeout:g} s"))
            for i, d in enumerate(drives)]


def human(n: int | None) -> str:
    if n is None:
        return "?"
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if value < 1024 or unit == "PiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} PiB"


def pie_spans(values: list[int]) -> list[tuple[int, int]]:
    """``(start, span)`` per value in Qt's 1/16 degree, clockwise from 12
    o'clock; the spans add up to the full circle."""
    total = sum(v for v in values if v > 0)
    if total <= 0:
        return []
    spans = []
    start = 90 * 16
    used = 0
    for i, value in enumerate(values):
        span = 5760 - used if i == len(values) - 1 else int(round(5760 * value / total))
        used += span
        spans.append((start, -span))
        start -= span
    return spans


def bar_lengths(sizes: list[tuple[int | None, int | None]], width: int) -> list[tuple[int, int]]:
    """``(bar, used part)`` in pixels per ``(total, used)``, the largest
    drive *width* long; an unknown drive gets no bar."""
    largest = max((t for t, _u in sizes if t), default=0)
    out = []
    for total, used in sizes:
        if not total or not largest or used is None:
            out.append((0, 0))
            continue
        bar = int(round(width * total / largest))
        out.append((bar, int(round(bar * used / total))))
    return out


class _Number(QTableWidgetItem):
    """A cell that sorts by its number, not its text."""

    def __init__(self, text: str, value: float | None):
        super().__init__(text)
        self.value = -1.0 if value is None else float(value)

    def __lt__(self, other):  # noqa: D105
        if isinstance(other, _Number):
            return self.value < other.value
        return super().__lt__(other)


class PieChart(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.drive: Drive | None = None
        self.setMinimumSize(180, 180)

    def set_drive(self, drive: Drive | None) -> None:
        self.drive = drive
        self.update()

    def paintEvent(self, _event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), self.palette().base())
        drive = self.drive
        if drive is None or not drive.total or drive.used is None:
            text = "Select a drive" if drive is None else f"{drive.mount}: size unknown"
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, text)
            return
        side = min(self.width(), self.height() - 40) - 20
        box = QRectF((self.width() - side) / 2, 10, side, side)
        free = drive.free if drive.free is not None else drive.total - drive.used
        for (start, span), colour in zip(pie_spans([drive.used, free]), (USED_COLOUR, FREE_COLOUR)):
            painter.setBrush(QColor(colour))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawPie(box, start, span)
        painter.setPen(self.palette().text().color())
        painter.drawText(
            QRectF(0, box.bottom() + 4, self.width(), 30), Qt.AlignmentFlag.AlignCenter,
            f"{drive.mount}: {human(drive.used)} used of {human(drive.total)} "
            f"({drive.percent:.0f} %), {human(free)} free",
        )


class BarChart(QWidget):
    ROW = 22

    def __init__(self) -> None:
        super().__init__()
        self.drives: list[Drive] = []
        self.setMinimumHeight(60)

    def set_drives(self, drives: list[Drive]) -> None:
        self.drives = drives
        self.setMinimumHeight(max(60, self.ROW * len(drives) + 10))
        self.update()

    def label_width(self) -> int:
        return min(220, max((self.fontMetrics().horizontalAdvance(d.mount) for d in self.drives),
                            default=0) + 12)

    def lengths(self) -> list[tuple[int, int]]:
        width = max(10, self.width() - self.label_width() - 90)
        return bar_lengths([(d.total, d.used) for d in self.drives], width)

    def paintEvent(self, _event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.fillRect(self.rect(), self.palette().base())
        label = self.label_width()
        text = self.palette().text().color()
        for row, (drive, (bar, used)) in enumerate(zip(self.drives, self.lengths())):
            y = 5 + row * self.ROW
            painter.setPen(text)
            painter.drawText(QRectF(4, y, label - 8, self.ROW - 4),
                             Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                             self.fontMetrics().elidedText(drive.mount, Qt.TextElideMode.ElideMiddle,
                                                           label - 8))
            if bar:
                painter.fillRect(QRectF(label, y + 3, used, self.ROW - 8), QColor(USED_COLOUR))
                painter.fillRect(QRectF(label + used, y + 3, bar - used, self.ROW - 8), QColor(FREE_COLOUR))
            note = f"{drive.percent:.0f} %" if drive.percent is not None else "unknown"
            painter.drawText(QRectF(label + bar + 6, y, 80, self.ROW - 4),
                             Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, note)


class DrivesPanel(QWidget):
    """The panel: Refresh, the system-mount switch, the table, the pie of the
    selected drive and the bars of every drive shown."""

    def __init__(self, *, refresh, open_folder) -> None:
        super().__init__()
        self._open_folder = open_folder
        self._drives: list[Drive] = []
        layout = QVBoxLayout(self)
        top = QHBoxLayout()
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(refresh)
        self.show_system = QCheckBox("Show system and memory mounts")
        self.show_system.toggled.connect(lambda _on: self._fill())
        self.status = QLabel("")
        top.addWidget(self.refresh_button)
        top.addWidget(self.show_system)
        top.addStretch(1)
        top.addWidget(self.status)
        layout.addLayout(top)
        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(list(COLUMNS))
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSortIndicator(COL_MOUNT, Qt.SortOrder.AscendingOrder)
        self.table.setSortingEnabled(True)
        self.table.itemSelectionChanged.connect(self._selected)
        self.table.doubleClicked.connect(self._open)
        charts = QSplitter(Qt.Orientation.Horizontal)
        self.pie = PieChart()
        self.bars = BarChart()
        charts.addWidget(self.pie)
        charts.addWidget(self.bars)
        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(self.table)
        split.addWidget(charts)
        layout.addWidget(split, 1)

    def visible_drives(self) -> list[Drive]:
        if self.show_system.isChecked():
            return list(self._drives)
        return [d for d in self._drives if d.kind in ("local", "network", "removable")]

    def set_drives(self, drives: list[Drive]) -> None:
        self._drives = list(drives)
        self._fill()

    def _fill(self) -> None:
        drives = self.visible_drives()
        table = self.table
        table.setSortingEnabled(False)
        table.setRowCount(len(drives))
        for row, drive in enumerate(drives):
            use = (f"{drive.percent:.0f} %" if drive.percent is not None
                   else (drive.error or "unknown"))
            cells = (
                QTableWidgetItem(drive.mount), QTableWidgetItem(drive.device),
                QTableWidgetItem(f"{drive.fstype} ({drive.kind})" if drive.fstype else drive.kind),
                _Number(human(drive.total), drive.total), _Number(human(drive.used), drive.used),
                _Number(human(drive.free), drive.free), _Number(use, drive.percent),
            )
            cells[0].setData(Qt.ItemDataRole.UserRole, drive)
            if drive.error:
                cells[COL_USE].setToolTip(drive.error)
            for col, item in enumerate(cells):
                table.setItem(row, col, item)
        table.setSortingEnabled(True)
        table.resizeColumnsToContents()
        self.bars.set_drives(drives)
        self.pie.set_drive(None)
        known = sum(d.total or 0 for d in drives)
        self.status.setText(f"{len(drives)} drives, {human(known)} in all")

    def _drive_at(self, row: int) -> Drive | None:
        item = self.table.item(row, COL_MOUNT)
        return item.data(Qt.ItemDataRole.UserRole) if item is not None else None

    def _selected(self) -> None:
        rows = {index.row() for index in self.table.selectedIndexes()}
        self.pie.set_drive(self._drive_at(min(rows)) if rows else None)

    def _open(self, index) -> None:
        drive = self._drive_at(index.row())
        if drive is not None:
            self._open_folder(drive.mount)


def activate(api):
    state = {"busy": False}

    def refresh() -> None:
        if state["busy"]:
            return
        state["busy"] = True
        panel.status.setText("Measuring…")

        def done(drives):
            state["busy"] = False
            panel.set_drives(drives)

        def failed(exc):
            state["busy"] = False
            panel.status.setText(f"Cannot list the drives: {exc}")

        api.run_in_background(lambda: measure(list_drives()), on_done=done, on_error=failed)

    def open_folder(path: str) -> None:
        ctx = api.current()
        if ctx is None or ctx.pane is None:
            api.notify("No file pane to open the drive in.")
            return
        if not ctx.is_local:
            api.notify("The active pane is a remote connection; activate a local pane first.")
            return
        ctx.pane.navigate_async(path)

    panel = DrivesPanel(refresh=refresh, open_folder=open_folder)
    api.add_dock("Drives Overview", panel)
    refresh()
