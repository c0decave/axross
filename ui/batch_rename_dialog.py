"""Batch rename dialog — rename multiple files using pattern/regex."""
from __future__ import annotations

import logging
import re
import uuid
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from core.backend import FileBackend
    from models.file_item import FileItem

log = logging.getLogger(__name__)


class BatchRenameDialog(QDialog):
    """Dialog for renaming multiple files using find/replace or regex patterns."""

    def __init__(
        self,
        backend: FileBackend,
        base_path: str,
        items: list[FileItem],
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self._backend = backend
        self._base_path = base_path
        self._items = items

        self.setWindowTitle(f"Batch Rename — {len(items)} files")
        self.setMinimumWidth(600)
        self.setMinimumHeight(400)
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)

        # Pattern input
        pattern_group = QGroupBox("Rename Pattern")
        form = QFormLayout(pattern_group)

        self._mode = QComboBox()
        self._mode.addItems(["Find & Replace", "Regex"])
        self._mode.currentIndexChanged.connect(self._update_preview)
        form.addRow("Mode:", self._mode)

        self._find_edit = QLineEdit()
        self._find_edit.setPlaceholderText("Search pattern")
        self._find_edit.textChanged.connect(self._update_preview)
        form.addRow("Find:", self._find_edit)

        self._replace_edit = QLineEdit()
        self._replace_edit.setPlaceholderText("Replacement")
        self._replace_edit.textChanged.connect(self._update_preview)
        form.addRow("Replace:", self._replace_edit)

        options = QHBoxLayout()
        self._case_sensitive = QCheckBox("Case sensitive")
        self._case_sensitive.setChecked(True)
        self._case_sensitive.toggled.connect(self._update_preview)
        options.addWidget(self._case_sensitive)

        self._replace_all = QCheckBox("Replace all occurrences")
        self._replace_all.setChecked(True)
        self._replace_all.toggled.connect(self._update_preview)
        options.addWidget(self._replace_all)
        options.addStretch()
        form.addRow("", options)

        layout.addWidget(pattern_group)

        # Preview table
        preview_group = QGroupBox("Preview")
        preview_layout = QVBoxLayout(preview_group)

        self._table = QTableWidget(len(self._items), 2)
        self._table.setHorizontalHeaderLabels(["Current Name", "New Name"])
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)

        for row, item in enumerate(self._items):
            self._table.setItem(row, 0, QTableWidgetItem(item.name))
            self._table.setItem(row, 1, QTableWidgetItem(item.name))

        self._table.resizeColumnsToContents()
        preview_layout.addWidget(self._table)

        self._status = QLabel(f"{len(self._items)} files selected, 0 will be renamed")
        preview_layout.addWidget(self._status)

        layout.addWidget(preview_group, stretch=1)

        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._apply)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _compute_new_names(self) -> list[tuple[str, str]]:
        """Return list of (old_name, new_name) pairs."""
        find = self._find_edit.text()
        replace = self._replace_edit.text()
        if not find:
            return [(item.name, item.name) for item in self._items]

        results = []
        is_regex = self._mode.currentIndex() == 1
        flags = 0 if self._case_sensitive.isChecked() else re.IGNORECASE
        count = 0 if self._replace_all.isChecked() else 1

        for item in self._items:
            try:
                if is_regex:
                    new_name = re.sub(find, replace, item.name, count=count, flags=flags)
                else:
                    if self._case_sensitive.isChecked():
                        if self._replace_all.isChecked():
                            new_name = item.name.replace(find, replace)
                        else:
                            new_name = item.name.replace(find, replace, 1)
                    else:
                        # Case-insensitive find & replace
                        pattern = re.escape(find)
                        new_name = re.sub(pattern, replace, item.name, count=count, flags=flags)
            except re.error:
                new_name = item.name
            results.append((item.name, new_name))
        return results

    def _update_preview(self) -> None:
        pairs = self._compute_new_names()
        changed = 0
        for row, (old, new) in enumerate(pairs):
            item = QTableWidgetItem(new)
            if new != old:
                item.setForeground(Qt.GlobalColor.blue)
                changed += 1
            self._table.setItem(row, 1, item)
        self._status.setText(f"{len(self._items)} files selected, {changed} will be renamed")

    def _apply(self) -> None:
        pairs = self._compute_new_names()
        to_rename = [(old, new) for old, new in pairs if old != new]

        if not to_rename:
            self.accept()
            return

        # Check for conflicts (duplicate new names)
        new_names = [new for _, new in to_rename]
        if len(new_names) != len(set(new_names)):
            QMessageBox.warning(self, "Conflict", "Some new names are duplicates. Fix the pattern.")
            return

        selected_old_names = {old for old, _ in to_rename}
        for old_name, new_name in to_rename:
            new_path = self._backend.join(self._base_path, new_name)
            if new_name not in selected_old_names and self._backend.exists(new_path):
                QMessageBox.warning(
                    self,
                    "Conflict",
                    f"Target '{new_name}' already exists and is not part of the rename set.",
                )
                return

        errors = []
        renamed = 0
        staged: list[tuple[str, str, str]] = []
        for old_name, new_name in to_rename:
            old_path = self._backend.join(self._base_path, old_name)
            temp_name = f".{old_name}.rename-{uuid.uuid4().hex[:8]}"
            temp_path = self._backend.join(self._base_path, temp_name)
            try:
                self._backend.rename(old_path, temp_path)
                staged.append((old_name, new_name, temp_path))
            except OSError as e:
                log.error("Batch rename staging failed: %s -> %s: %s", old_name, new_name, e)
                errors.append(f"{old_name}: {e}")

        for old_name, new_name, temp_path in staged:
            new_path = self._backend.join(self._base_path, new_name)
            try:
                self._backend.rename(temp_path, new_path)
                renamed += 1
                log.info("Batch rename: %s -> %s", old_name, new_name)
            except OSError as e:
                log.error("Batch rename finalize failed: %s -> %s: %s", old_name, new_name, e)
                errors.append(f"{old_name}: {e}")
                try:
                    self._backend.rename(temp_path, self._backend.join(self._base_path, old_name))
                except OSError:
                    pass

        if errors:
            QMessageBox.warning(
                self, "Rename Errors",
                f"Renamed {renamed}, failed {len(errors)}:\n" + "\n".join(errors[:10]),
            )
        self.accept()
