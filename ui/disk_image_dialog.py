"""Disk Image…: what an image holds, and loop-mounting one of its volumes.

The pane's context menu opens it on a disk image (core.disk_image reads the
container, partition table and file systems in the background). A local
raw image - or a fixed VDI, whose partitions sit at a known offset - can
mount a partition through core.loop_mount: read-only unless "Allow writing"
is ticked and confirmed. The mounted folder opens in a new pane; the mounts
made here are listed with an Unmount button.
"""

from __future__ import annotations

import html
import logging
import threading

from PyQt6.QtCore import QObject, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from core import disk_image as DI
from core import loop_mount as LM
from core.i18n import tr
from ui.close_corner import add_close_corner
from ui.scan_job import ScanJob

log = logging.getLogger(__name__)

COLUMNS = ("#", "Start", "Size", "Type", "Name", "File system", "Label")


def _is_local(backend) -> bool:
    from core.local_fs import LocalFS

    return isinstance(backend, LocalFS)


class _PasswordBridge(QObject):
    """Asks for the sudo password in the UI thread on behalf of the mount
    worker, which waits for the answer. Lives in the UI thread; after
    :meth:`abandon` (the dialog closes) every question is answered None at
    once and none opens."""

    request = pyqtSignal(str, bool)  # title, retry (the last answer was wrong)

    def __init__(self, ask, parent=None) -> None:
        super().__init__(parent)
        self._ask = ask
        self._lock = threading.Lock()
        self._event = threading.Event()
        self._answer: str | None = None
        self._abandoned = False
        self.request.connect(self._on_request)

    def ask_from_worker(self, title: str, retry: bool = False) -> str | None:
        if threading.current_thread() is threading.main_thread():
            # Called in the UI thread itself: waiting would block the reply.
            return None if self._abandoned else self._ask(title, retry)
        with self._lock:  # one question at a time
            self._event.clear()
            self._answer = None
            if self._abandoned:  # checked after clear(): abandon() cannot be lost
                return None
            try:
                self.request.emit(title, retry)  # queued: the receiver is in the UI thread
            except RuntimeError:  # the dialog is gone
                return None
            self._event.wait(LM.COMMAND_TIMEOUT)
            return None if self._abandoned else self._answer

    def _on_request(self, title: str, retry: bool) -> None:
        answer = None
        if not self._abandoned:
            try:
                answer = self._ask(title, retry)
            except Exception:  # noqa: BLE001 - the worker must not wait forever
                log.warning("Password prompt failed", exc_info=True)
        self._answer = answer
        self._event.set()

    def abandon(self) -> None:
        self._abandoned = True
        self._event.set()


class DiskImageDialog(QDialog):
    def __init__(self, backend, path: str, parent=None, *, open_folder=None,
                 mount=LM.mount_partition, unmount=LM.unmount) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Disk Image"))
        self.resize(820, 460)
        self._backend = backend
        self._path = path
        self._open_folder = open_folder
        self._mount = mount
        self._unmount = unmount
        self.info: DI.ImageInfo | None = None
        self._local = _is_local(backend)

        self.summary = QLabel(tr("Reading {name}…").format(name=path))
        self.summary.setWordWrap(True)
        self.summary.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels([tr(c) for c in COLUMNS])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemSelectionChanged.connect(self._update_buttons)
        self.table.doubleClicked.connect(lambda _i: self.mount_selected())
        self.note = QLabel("")
        self.note.setWordWrap(True)

        self.writable = QCheckBox(tr("Allow writing (mount read-write)"))
        self.writable.toggled.connect(lambda _on: self._update_buttons())
        self.writable.setToolTip(tr("Off: the volume is mounted read-only and nothing in the "
                                    "image can change."))
        self.mount_button = QPushButton(tr("Mount"))
        self.mount_button.clicked.connect(self.mount_selected)
        self.mounts = QListWidget()
        self.mounts.setMaximumHeight(90)
        self.open_button = QPushButton(tr("Open in Pane"))
        self.open_button.clicked.connect(self.open_selected_mount)
        self.unmount_button = QPushButton(tr("Unmount"))
        self.unmount_button.clicked.connect(self.unmount_selected)
        self.mounts.itemSelectionChanged.connect(self._update_buttons)
        close = QPushButton(tr("Close"))
        close.clicked.connect(self.close)

        layout = QVBoxLayout(self)
        layout.addWidget(self.summary)
        layout.addWidget(self.table, 1)
        layout.addWidget(self.note)
        row = QHBoxLayout()
        row.addWidget(self.writable)
        row.addStretch(1)
        row.addWidget(self.mount_button)
        layout.addLayout(row)
        layout.addWidget(QLabel(tr("Mounted by axross:")))
        layout.addWidget(self.mounts)
        row = QHBoxLayout()
        row.addStretch(1)
        row.addWidget(self.open_button)
        row.addWidget(self.unmount_button)
        row.addWidget(close)
        layout.addLayout(row)
        add_close_corner(self)

        self._job = ScanJob(self)
        self._job.finished.connect(self._job_done)
        self._mount_job = ScanJob(self)
        self._mount_job.finished.connect(self._mount_done)
        # Unmount waits for polkit / sudo like a mount: never on this thread.
        self._unmount_job = ScanJob(self)
        self._unmount_job.finished.connect(self._unmount_done)
        self._password_bridge = _PasswordBridge(self._password_dialog, self)
        self._refresh_mounts()
        self._update_buttons()

    # -- reading -----------------------------------------------------------------------

    def start(self) -> None:
        backend, path = self._backend, self._path
        self._job.start(lambda cancel, progress: DI.inspect_backend(backend, path))

    def idle(self) -> bool:
        return not (self._job.running or self._mount_job.running or self._unmount_job.running)

    def _job_done(self, kind: str, value, _cancelled: bool) -> None:
        if kind == "error":
            self.summary.setText(tr("Cannot read {name}: {error}").format(name=self._path,
                                                                          error=value))
            return
        self.show_info(value)

    def show_info(self, info: DI.ImageInfo) -> None:
        self.info = info
        # Rich text: the name and the image's own labels are escaped.
        self.summary.setText(f"<b>{html.escape(self._path)}</b><br>{html.escape(info.summary())}")
        self.table.setRowCount(len(info.partitions))
        for row, p in enumerate(info.partitions):
            cells = (
                str(p.number) if p.number else tr("whole"),
                DI.human_size(p.start), DI.human_size(p.size),
                p.type_name or "", p.name, p.filesystem or "?", p.label,
            )
            for col, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if col == 0:
                    item.setData(Qt.ItemDataRole.UserRole, row)
                if p.beyond_end:
                    item.setToolTip(tr("This partition runs past the end of the image."))
                self.table.setItem(row, col, item)
        self.table.resizeColumnsToContents()
        # resizeColumnsToContents shrank the stretched last column to its
        # text; switching the stretch off and on lays it out again.
        header = self.table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setStretchLastSection(True)
        notes = list(info.warnings)
        if info.note:
            notes.append(info.note)
        if not info.partitions and info.kind == "unknown":
            notes.append(tr("No disk image, partition table or file system was found."))
        if not self._local:
            notes.append(tr("Mounting needs the image on this computer: copy it to a local "
                            "folder first."))
        self.note.setText("\n".join(notes))
        mountable = [r for r, p in enumerate(info.partitions) if p.mountable]
        if mountable:
            self.table.selectRow(mountable[0])
        self._update_buttons()

    # -- mounting ----------------------------------------------------------------------

    def selected_partition(self) -> DI.Partition | None:
        rows = {i.row() for i in self.table.selectedIndexes()}
        if self.info is None or len(rows) != 1:
            return None
        return self.info.partitions[rows.pop()]

    def _update_buttons(self) -> None:
        part = self.selected_partition()
        can_mount = self._local and part is not None and part.mountable and not self._mount_job.running
        self.mount_button.setEnabled(can_mount)
        self.mount_button.setText(tr("Mount Read-Write…") if self.writable.isChecked()
                                  else tr("Mount Read-Only"))
        has_mount = self.mounts.currentItem() is not None
        self.open_button.setEnabled(has_mount and self._open_folder is not None)
        self.unmount_button.setEnabled(has_mount and not self._unmount_job.running)

    def mount_selected(self) -> bool:
        """Mount the selected volume in the background; False when nothing
        started (nothing mountable, writing not confirmed)."""
        part = self.selected_partition()
        if not (self._local and part is not None and part.mountable) or self._mount_job.running:
            return False
        writable = self.writable.isChecked()
        if writable:
            reply = QMessageBox.warning(
                self, tr("Mount Read-Write"),
                tr("Mount partition {n} with WRITE access? Changes go straight into the image "
                   "file and cannot be undone - for evidence, keep read-only.").format(
                    n=part.number or tr("whole")),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return False
        image, mount = self._path, self._mount
        # Asked from the worker, through the UI thread, only when sudo needs
        # it: a remembered password or a valid sudo ticket asks nothing.
        password = self._sudo_password_callback(tr("Mount"))
        self.note.setText(tr("Mounting… (the system may ask for your password)"))
        # cancel: the dialog closed - no further method, no polkit prompt.
        self._mount_job.start(lambda cancel, progress: mount(
            image, offset=part.start, size=part.size, writable=writable, password=password,
            cancelled=cancel))
        self._update_buttons()
        return True

    def _mount_done(self, kind: str, value, _cancelled: bool) -> None:
        if kind == "error":
            self.note.setText(str(value))
            QMessageBox.warning(self, tr("Mount"), str(value))
        else:
            self.note.setText(tr("Mounted at {path}{ro}").format(
                path=value.mountpoint, ro=tr(" (read-only)") if value.read_only else ""))
            self._refresh_mounts(select=value)
            if self._open_folder is not None:
                self._open_folder(value.mountpoint)
        self._update_buttons()

    def _refresh_mounts(self, select=None) -> None:
        self.mounts.clear()
        for m in LM.active_mounts():
            item = QListWidgetItem(f"{m.mountpoint}  ←  {m.image}"
                                   f"  [{'ro' if m.read_only else 'rw'}, {m.method}]")
            item.setData(Qt.ItemDataRole.UserRole, m)
            self.mounts.addItem(item)
            if m == select:
                self.mounts.setCurrentItem(item)
        self._update_buttons()

    def _selected_mount(self) -> LM.Mount | None:
        item = self.mounts.currentItem()
        return item.data(Qt.ItemDataRole.UserRole) if item is not None else None

    def open_selected_mount(self) -> None:
        m = self._selected_mount()
        if m is not None and self._open_folder is not None:
            self._open_folder(m.mountpoint)

    def unmount_selected(self) -> bool:
        """Unmount the selected mount in the background (polkit or sudo may
        ask meanwhile); False when nothing started."""
        m = self._selected_mount()
        if m is None or self._unmount_job.running:
            return False
        unmount = self._unmount
        password = self._sudo_password_callback(tr("Unmount"))
        self.note.setText(tr("Unmounting {path}…").format(path=m.mountpoint))
        def work(cancel, progress):
            unmount(m, password=password, cancelled=cancel)
            return m  # whatever unmount returns: the slot gets the Mount

        self._unmount_job.start(work)
        self._update_buttons()
        return True

    def _unmount_done(self, kind: str, value, _cancelled: bool) -> None:
        if kind == "error":
            self.note.setText(str(value))
            QMessageBox.warning(self, tr("Unmount"), str(value))
        else:
            self.note.setText(tr("Unmounted {path}").format(path=value.mountpoint))
        self._refresh_mounts()
        self._update_buttons()

    def _sudo_password_callback(self, title: str):
        """What core.loop_mount calls for the sudo password: ``()`` the first
        time, ``(retry=True)`` after sudo refused the last answer."""
        def password(retry: bool = False) -> str | None:
            return self._password_from_worker(title, retry)
        return password

    def _password_from_worker(self, title: str, retry: bool = False) -> str | None:
        """The sudo password for a background job: asked in the UI thread
        while the job waits; None when cancelled or the dialog closed."""
        return self._password_bridge.ask_from_worker(title, retry)

    def _password_dialog(self, title: str, retry: bool = False) -> str | None:
        label = tr("Password for sudo:")
        if retry:
            label = tr("Wrong password - try again.") + "\n" + label
        text, ok = QInputDialog.getText(self, title, label, QLineEdit.EchoMode.Password)
        return text if ok and text else None

    def closeEvent(self, event) -> None:
        # The jobs first: a worker woken by the abandoned password question
        # must already find itself cancelled.
        self._job.abandon()
        self._mount_job.abandon()
        self._unmount_job.abandon()
        self._password_bridge.abandon()
        super().closeEvent(event)
