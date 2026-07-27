"""Permissions editor (chmod) — reusable widget plus a standalone dialog.

The editor lives in :class:`PermissionsWidget` rather than inline in the
dialog because two callers need it: the standalone
:class:`PermissionsDialog` (Alt+Enter's original behaviour) and the
Permissions tab of :class:`ui.properties_dialog.PropertiesDialog`.
Duplicating a control that writes file modes is exactly how two copies
drift until one of them grants a bit the other does not.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QLabel,
    QLineEdit,
    QMessageBox,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from core.backend import FileBackend
    from models.file_item import FileItem

log = logging.getLogger(__name__)

# Owner r/w/x, group r/w/x, others r/w/x — the order the checkbox grid
# is built in, so index i in ``_checks`` maps to ``_MODE_BITS[i]``.
_MODE_BITS = (0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001)


class PermissionsWidget(QWidget):
    """Checkbox grid + octal field + preview for one file's mode.

    ``apply()`` writes the selection through ``backend.chmod`` and
    returns whether the write succeeded. It is a no-op (returning
    ``True``) when the user did not actually change anything.
    """

    #: Emitted whenever the selected mode changes, with the new mode.
    mode_changed = pyqtSignal(int)

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
        self._original_mode = item.permissions
        self._build()

    # -- construction ----------------------------------------------------

    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        info = QFormLayout()
        info.addRow("File:", QLabel(self._item.name))
        info.addRow("Type:", QLabel(self._item.type_char))
        info.addRow("Owner:", QLabel(f"{self._item.owner}:{self._item.group}"))
        info.addRow("Current:", QLabel(self._item.mode_str))
        layout.addLayout(info)

        perm_group = QGroupBox("Permissions")
        grid = QGridLayout(perm_group)

        for col, header in enumerate(("Read", "Write", "Execute")):
            grid.addWidget(QLabel(header), 0, col + 1, alignment=Qt.AlignmentFlag.AlignCenter)

        self._checks: list[QCheckBox] = []
        for row_idx, row_name in enumerate(("Owner", "Group", "Others")):
            grid.addWidget(QLabel(row_name), row_idx + 1, 0)
            for col_idx in range(3):
                cb = QCheckBox()
                cb.setChecked(bool(self._original_mode & _MODE_BITS[row_idx * 3 + col_idx]))
                cb.toggled.connect(self._update_octal)
                grid.addWidget(
                    cb, row_idx + 1, col_idx + 1, alignment=Qt.AlignmentFlag.AlignCenter
                )
                self._checks.append(cb)

        layout.addWidget(perm_group)

        octal_layout = QFormLayout()
        self._octal_edit = QLineEdit(f"{self._original_mode & 0o777:03o}")
        self._octal_edit.setMaxLength(4)
        self._octal_edit.setFixedWidth(80)
        self._octal_edit.textChanged.connect(self._on_octal_changed)
        octal_layout.addRow("Octal:", self._octal_edit)
        layout.addLayout(octal_layout)

        self._preview = QLabel()
        layout.addWidget(self._preview)
        self._update_preview()

    # -- state -----------------------------------------------------------

    def selected_mode(self) -> int:
        """The mode the checkboxes currently describe (low 9 bits)."""
        mode = 0
        for cb, bit in zip(self._checks, _MODE_BITS):
            if cb.isChecked():
                mode |= bit
        return mode

    def is_modified(self) -> bool:
        """Whether the selection differs from the mode we opened with.

        Compares only the permission bits: a setuid/setgid/sticky file
        whose rwx bits are untouched counts as unmodified, so pressing
        OK cannot silently strip those high bits via a chmod that the
        user never asked for.
        """
        return self.selected_mode() != self._original_mode & 0o777

    # -- signal handlers -------------------------------------------------

    def _update_octal(self) -> None:
        mode = self.selected_mode()
        self._octal_edit.blockSignals(True)
        self._octal_edit.setText(f"{mode:03o}")
        self._octal_edit.blockSignals(False)
        self._update_preview()
        self.mode_changed.emit(mode)

    def _on_octal_changed(self, text: str) -> None:
        try:
            mode = int(text, 8)
        except ValueError:
            return
        if mode > 0o777:
            return

        for cb, bit in zip(self._checks, _MODE_BITS):
            cb.blockSignals(True)
            cb.setChecked(bool(mode & bit))
            cb.blockSignals(False)
        self._update_preview()
        self.mode_changed.emit(mode)

    def _update_preview(self) -> None:
        mode = self.selected_mode()
        perm_str = "".join(
            c if mode & b else "-" for c, b in zip("rwxrwxrwx", _MODE_BITS)
        )
        self._preview.setText(f"Preview: {self._item.type_char}{perm_str}  (0{mode:03o})")

    # -- action ----------------------------------------------------------

    def apply(self) -> str | None:
        """Write the selected mode.

        Returns ``None`` on success or when there was nothing to write,
        and the error text when chmod failed.

        Deliberately does NOT pop up a message box: this widget is
        embedded in a tab as well as in a dialog, and a reusable control
        that opens its own modal decides for every host how failure is
        presented — besides being untestable without a click.
        Presentation is the caller's job.
        """
        if not self.is_modified():
            return None

        new_mode = self.selected_mode()
        try:
            self._backend.chmod(self._file_path, new_mode)
        except OSError as exc:
            log.error("chmod failed for %s: %s", self._file_path, exc)
            return str(exc)
        log.info("Changed permissions of %s to %03o", self._file_path, new_mode)
        return None


class PermissionsDialog(QDialog):
    """Standalone chmod dialog around :class:`PermissionsWidget`."""

    def __init__(
        self,
        backend: FileBackend,
        file_path: str,
        item: FileItem,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self.setWindowTitle(f"Permissions: {item.name}")
        self.setMinimumWidth(350)

        layout = QVBoxLayout(self)
        self._widget = PermissionsWidget(backend, file_path, item, self)
        layout.addWidget(self._widget)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._apply)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _apply(self) -> None:
        error = self._widget.apply()
        if error is None:
            self.accept()
            return
        QMessageBox.critical(self, "Permission Error", f"Failed to change permissions:\n{error}")


__all__ = ["PermissionsDialog", "PermissionsWidget"]
