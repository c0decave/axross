"""File / directory properties sheet.

Everything shown here already lived on :class:`models.file_item.FileItem`
— owner, group, mode, sizes, the three timestamps, the symlink target.
The app simply never had a window for it: ``Alt+Enter`` opened the chmod
editor alone, so "properties" looked missing. That binding now opens
this dialog, and the chmod editor is its second tab.

Two rules drive the layout:

**Absent metadata is information.** A field the backend cannot supply
renders as an em dash instead of vanishing. Which attributes a protocol
carries is exactly what a user comparing S3 against SFTP wants to see;
a row that disappears reads as "this file has no owner" rather than
"this protocol has no concept of one".

**A dialog must never hang on a network walk.** Directory sizes need a
recursive listing, which is one round trip per directory. Backends that
advertise a cheap walk (``has_cheap_recursive_walk``, set by LocalFS)
compute it automatically on a worker thread; everything else opens
instantly with a Calculate button. The default is the safe direction:
an unmarked backend is treated as expensive.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import TYPE_CHECKING

from PyQt6.QtCore import QObject, Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ui.format_utils import format_size, human_bytes
from ui.permissions_dialog import PermissionsWidget

if TYPE_CHECKING:
    from core.backend import FileBackend
    from models.file_item import FileItem

log = logging.getLogger(__name__)

#: Rendered for every value the backend could not supply.
DASH = "—"


def _format_time(value: datetime | None) -> str:
    return DASH if value is None else value.strftime("%Y-%m-%d %H:%M:%S")


class _SizeWorker(QObject):
    """Recursive size walk, off the GUI thread."""

    done = pyqtSignal(int)

    def __init__(self, backend: FileBackend, path: str) -> None:
        super().__init__()
        self._backend = backend
        self._path = path
        self._cancelled = False

    def cancel(self) -> None:
        """Ask the walk to stop at the next directory boundary.

        ``QThread.quit()`` only ends an event loop; it cannot interrupt
        a slot that is already running. Without this the dialog could
        only wait for a remote walk it no longer needs.
        """
        self._cancelled = True

    def run(self) -> None:
        self.done.emit(self._walk(self._path))

    def _walk(self, path: str, depth: int = 0) -> int:
        if self._cancelled:
            return 0
        # Depth cap mirrors the pane's own recursive walk: a symlink
        # loop on a backend that does not report is_link must not
        # recurse until the stack dies.
        if depth > 64:
            return 0
        total = 0
        try:
            entries = self._backend.list_dir(path)
        except OSError as exc:
            # An unreadable subtree is normal (permissions, vanished
            # directory). Report what we could read rather than nothing.
            log.debug("properties: skipping %s: %s", path, exc)
            return 0
        for item in entries:
            child = self._backend.join(path, item.name)
            if item.is_dir and not item.is_link:
                total += self._walk(child, depth + 1)
            else:
                total += item.size
        return total


class PropertiesDialog(QDialog):
    """Tabbed properties sheet for one file or directory."""

    def __init__(
        self,
        backend: FileBackend,
        file_path: str,
        item: FileItem,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self._backend = backend
        self._file_path = file_path
        self._item = item
        self._size_override: int | None = None
        self._thread: QThread | None = None
        self._worker: _SizeWorker | None = None

        self.setWindowTitle(f"Properties: {item.name}")
        self.setMinimumWidth(420)
        self._build()

        if item.is_dir and getattr(backend, "has_cheap_recursive_walk", False):
            self._start_size_walk()

    # -- construction ----------------------------------------------------

    def _build(self) -> None:
        layout = QVBoxLayout(self)
        self._tabs = QTabWidget(self)
        layout.addWidget(self._tabs)

        self._tabs.addTab(self._build_general(), "General")

        self._permissions = PermissionsWidget(
            self._backend, self._file_path, self._item, self
        )
        self._tabs.addTab(self._permissions, "Permissions")

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _build_general(self) -> QWidget:
        page = QWidget(self)
        form = QFormLayout(page)
        self._value_labels: dict[str, QLabel] = {}

        for key in self._field_order():
            label = QLabel(self._compute_field(key), page)
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
            label.setWordWrap(True)
            form.addRow(f"{key}:", label)
            self._value_labels[key] = label

        # Only meaningful for directories on an expensive backend; for
        # anything else it stays hidden so the row does not suggest an
        # action that would do nothing.
        self._calc_btn = QPushButton("Calculate", page)
        self._calc_btn.setToolTip("Walk the directory and total up its contents")
        self._calc_btn.clicked.connect(self._start_size_walk)
        self._calc_btn.setVisible(
            self._item.is_dir
            and not getattr(self._backend, "has_cheap_recursive_walk", False)
        )
        form.addRow("", self._calc_btn)
        return page

    def _field_order(self) -> list[str]:
        keys = ["Path", "Type"]
        if self._item.is_link:
            keys.append("Link target")
        keys += ["Size", "Owner", "Group", "Permissions", "Modified", "Accessed", "Created"]
        keys.append("Backend")
        return keys

    # -- field values ----------------------------------------------------

    def _compute_field(self, key: str) -> str:
        item = self._item
        if key == "Path":
            return self._file_path
        if key == "Type":
            if item.is_link:
                return "Symlink"
            return "Directory" if item.is_dir else "File"
        if key == "Link target":
            return item.link_target or DASH
        if key == "Size":
            if self._size_override is not None:
                return format_size(self._size_override)
            if item.is_dir:
                # Not known until something walks the tree.
                return DASH
            return format_size(item.size)
        if key == "Owner":
            return item.owner or DASH
        if key == "Group":
            return item.group or DASH
        if key == "Permissions":
            # A mode of 0 means the protocol reported none, not "no
            # rights for anyone" — rendering --------- would be a lie.
            if not item.permissions:
                return DASH
            return f"{item.permissions_str}  ({item.permissions & 0o7777:04o})"
        if key == "Modified":
            return _format_time(item.modified)
        if key == "Accessed":
            return _format_time(item.accessed)
        if key == "Created":
            return _format_time(item.created)
        if key == "Backend":
            return getattr(self._backend, "name", None) or DASH
        return DASH

    def general_fields(self) -> dict[str, str]:
        """The General tab as a mapping, in display order."""
        return {key: self._compute_field(key) for key in self._field_order()}

    # -- directory size --------------------------------------------------

    def _start_size_walk(self) -> None:
        if self._thread is not None:  # already running
            return
        self._calc_btn.setEnabled(False)
        self._value_labels["Size"].setText("calculating…")

        self._thread = QThread(self)
        self._worker = _SizeWorker(self._backend, self._file_path)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.done.connect(self._on_size_ready)
        self._thread.start()

    def _on_size_ready(self, total: int) -> None:
        self._size_override = total
        self._value_labels["Size"].setText(format_size(total))
        self._calc_btn.setEnabled(True)
        self._stop_thread()

    def _stop_thread(self) -> None:
        """Wind the worker down, and only forget it once it is really gone.

        Clearing ``self._thread`` while the walk is still running drops
        the last reference to a live QThread, which Qt punishes with
        "QThread: Destroyed while thread is still running" and an abort.
        On a large remote tree that is a realistic close-the-window
        crash, so the reference is kept and the thread is left to finish
        against a cancelled worker.
        """
        if self._thread is None:
            return
        if self._worker is not None:
            self._worker.cancel()
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
            log.warning(
                "properties: size walk for %s still running; leaving it to "
                "finish against a cancelled worker",
                self._file_path,
            )
            return
        self._thread = None
        self._worker = None

    def wait_for_size(self, timeout_ms: int = 5000) -> None:
        """Block until a running size walk has finished. For tests and
        for callers that need the total synchronously."""
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

    def _on_accept(self) -> None:
        error = self._permissions.apply()
        if error is None:
            self.accept()
            return
        QMessageBox.critical(self, "Permission Error", f"Failed to change permissions:\n{error}")

    def reject(self) -> None:  # noqa: D102 - Qt override
        self._stop_thread()
        super().reject()

    def accept(self) -> None:  # noqa: D102 - Qt override
        self._stop_thread()
        super().accept()


__all__ = ["PropertiesDialog", "format_size", "human_bytes", "DASH"]
