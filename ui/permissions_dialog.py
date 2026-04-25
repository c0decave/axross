"""Permissions dialog for viewing/editing file permissions (chmod)."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt
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


class PermissionsDialog(QDialog):
    """Dialog for viewing and editing file/directory permissions."""

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

        self.setWindowTitle(f"Permissions: {item.name}")
        self.setMinimumWidth(350)
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)

        # File info
        info = QFormLayout()
        info.addRow("File:", QLabel(self._item.name))
        info.addRow("Type:", QLabel(self._item.type_char))
        info.addRow("Owner:", QLabel(f"{self._item.owner}:{self._item.group}"))
        info.addRow("Current:", QLabel(self._item.mode_str))
        layout.addLayout(info)

        # Permission checkboxes
        perm_group = QGroupBox("Permissions")
        grid = QGridLayout(perm_group)

        headers = ["Read", "Write", "Execute"]
        rows = ["Owner", "Group", "Others"]
        for col, h in enumerate(headers):
            grid.addWidget(QLabel(h), 0, col + 1, alignment=Qt.AlignmentFlag.AlignCenter)

        self._checks: list[QCheckBox] = []
        bits = [
            0o400, 0o200, 0o100,  # Owner: r, w, x
            0o040, 0o020, 0o010,  # Group: r, w, x
            0o004, 0o002, 0o001,  # Others: r, w, x
        ]

        for row_idx, row_name in enumerate(rows):
            grid.addWidget(QLabel(row_name), row_idx + 1, 0)
            for col_idx in range(3):
                cb = QCheckBox()
                bit = bits[row_idx * 3 + col_idx]
                cb.setChecked(bool(self._original_mode & bit))
                cb.toggled.connect(self._update_octal)
                grid.addWidget(cb, row_idx + 1, col_idx + 1, alignment=Qt.AlignmentFlag.AlignCenter)
                self._checks.append(cb)

        layout.addWidget(perm_group)

        # Octal display
        octal_layout = QFormLayout()
        self._octal_edit = QLineEdit(f"{self._original_mode & 0o777:03o}")
        self._octal_edit.setMaxLength(4)
        self._octal_edit.setFixedWidth(80)
        self._octal_edit.textChanged.connect(self._on_octal_changed)
        octal_layout.addRow("Octal:", self._octal_edit)
        layout.addLayout(octal_layout)

        # Preview
        self._preview = QLabel()
        self._update_preview()
        layout.addWidget(self._preview)

        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._apply)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _get_mode_from_checks(self) -> int:
        bits = [0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001]
        mode = 0
        for cb, bit in zip(self._checks, bits):
            if cb.isChecked():
                mode |= bit
        return mode

    def _update_octal(self) -> None:
        mode = self._get_mode_from_checks()
        self._octal_edit.blockSignals(True)
        self._octal_edit.setText(f"{mode:03o}")
        self._octal_edit.blockSignals(False)
        self._update_preview()

    def _on_octal_changed(self, text: str) -> None:
        try:
            mode = int(text, 8)
            if mode > 0o777:
                return
        except ValueError:
            return

        bits = [0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001]
        for cb, bit in zip(self._checks, bits):
            cb.blockSignals(True)
            cb.setChecked(bool(mode & bit))
            cb.blockSignals(False)
        self._update_preview()

    def _update_preview(self) -> None:
        mode = self._get_mode_from_checks()
        chars = "rwxrwxrwx"
        bits = [0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001]
        perm_str = "".join(c if mode & b else "-" for c, b in zip(chars, bits))
        self._preview.setText(f"Preview: {self._item.type_char}{perm_str}  (0{mode:03o})")

    def _apply(self) -> None:
        new_mode = self._get_mode_from_checks()
        if new_mode == self._original_mode & 0o777:
            self.accept()
            return

        try:
            self._backend.chmod(self._file_path, new_mode)
            log.info("Changed permissions of %s to %03o", self._file_path, new_mode)
            self.accept()
        except OSError as e:
            log.error("chmod failed for %s: %s", self._file_path, e)
            QMessageBox.critical(self, "Permission Error", f"Failed to change permissions:\n{e}")
