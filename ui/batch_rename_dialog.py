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

from core.path_policy import hidden_sibling_name
from core.server_ops import rename_target_taken
from ui.close_corner import add_close_corner
from ui.icon_provider import set_window_icon
from core.i18n import tr

if TYPE_CHECKING:
    from core.backend import FileBackend
    from models.file_item import FileItem

log = logging.getLogger(__name__)


def _validate_leaf_name(name: str) -> None:
    from core.path_policy import safe_leaf

    safe_leaf(name)


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
        set_window_icon(self, "edit")
        self._backend = backend
        self._base_path = base_path
        self._items = items

        self.setWindowTitle(tr("Batch Rename — {n} files").format(n=len(items)))
        self.setMinimumWidth(600)
        self.setMinimumHeight(400)
        self._setup_ui()
        add_close_corner(self)

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)

        # Pattern input
        pattern_group = QGroupBox(tr("Rename Pattern"))
        form = QFormLayout(pattern_group)

        self._mode = QComboBox()
        self._mode.addItems([tr("Find & Replace"), tr("Regex")])
        self._mode.currentIndexChanged.connect(self._update_preview)
        form.addRow(tr("Mode:"), self._mode)

        self._find_edit = QLineEdit()
        self._find_edit.setPlaceholderText(tr("Search pattern"))
        self._find_edit.textChanged.connect(self._update_preview)
        form.addRow(tr("Find:"), self._find_edit)

        self._replace_edit = QLineEdit()
        self._replace_edit.setPlaceholderText(tr("Replacement"))
        self._replace_edit.textChanged.connect(self._update_preview)
        form.addRow(tr("Replace:"), self._replace_edit)

        options = QHBoxLayout()
        self._case_sensitive = QCheckBox(tr("Case sensitive"))
        self._case_sensitive.setChecked(True)
        self._case_sensitive.toggled.connect(self._update_preview)
        options.addWidget(self._case_sensitive)

        self._replace_all = QCheckBox(tr("Replace all occurrences"))
        self._replace_all.setChecked(True)
        self._replace_all.toggled.connect(self._update_preview)
        options.addWidget(self._replace_all)
        options.addStretch()
        form.addRow("", options)

        layout.addWidget(pattern_group)

        # Preview table
        preview_group = QGroupBox(tr("Preview"))
        preview_layout = QVBoxLayout(preview_group)

        self._table = QTableWidget(len(self._items), 2)
        self._table.setHorizontalHeaderLabels([tr("Current Name"), tr("New Name")])
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)

        for row, item in enumerate(self._items):
            self._table.setItem(row, 0, QTableWidgetItem(item.name))
            self._table.setItem(row, 1, QTableWidgetItem(item.name))

        self._table.resizeColumnsToContents()
        preview_layout.addWidget(self._table)

        self._status = QLabel(tr("{n} files selected, 0 will be renamed").format(n=len(self._items)))
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

    def _unique_temp_path(self, old_name: str) -> str:
        for _ in range(32):
            temp_name = hidden_sibling_name(old_name, f".rename-{uuid.uuid4().hex[:12]}")
            temp_path = self._backend.join(self._base_path, temp_name)
            if not self._backend.exists(temp_path):
                return temp_path
        raise OSError(f"Could not allocate a unique temp name for {old_name!r}")

    def _recovery_path(self, old_name: str) -> str:
        """Return a free visible ``name (n).ext`` path next to *old_name*."""
        stem, dot, ext = old_name.rpartition(".")
        if not stem:  # no extension, or a dot file such as ".bashrc"
            stem, dot, ext = old_name, "", ""
        for n in range(1, 1000):
            candidate = f"{stem} ({n}){dot}{ext}"
            path = self._backend.join(self._base_path, candidate)
            if not self._backend.exists(path):
                return path
        raise OSError(f"No free recovery name for {old_name!r}")

    def _roll_back(self, old_name: str, temp_path: str) -> str:
        """Move a staged entry back out of its hidden temporary name.

        The original name is preferred. When another entry of the same
        batch has taken it already (a chain such as ``a -> b, b -> c``),
        the entry goes to a visible ``name (n)`` path instead. Returns a
        note for the error report when the entry did not get its
        original name back, so the user can find it.
        """
        rollback_path = self._backend.join(self._base_path, old_name)
        try:
            if not self._backend.exists(rollback_path):
                self._backend.rename(temp_path, rollback_path)
                return ""
            log.error("Batch rename rollback target already exists: %s", rollback_path)
            recovery_path = self._recovery_path(old_name)
            self._backend.rename(temp_path, recovery_path)
        except OSError as exc:
            log.error("Batch rename rollback failed for %s: %s", temp_path, exc)
            return tr("left as {path}").format(path=temp_path)
        return tr("kept as {path}").format(path=recovery_path)

    def _update_preview(self) -> None:
        pairs = self._compute_new_names()
        changed = 0
        for row, (old, new) in enumerate(pairs):
            item = QTableWidgetItem(new)
            if new != old:
                item.setForeground(Qt.GlobalColor.blue)
                changed += 1
            self._table.setItem(row, 1, item)
        self._status.setText(tr("{n} files selected, {changed} will be renamed").format(n=len(self._items), changed=changed))

    def _apply(self) -> None:
        pairs = self._compute_new_names()
        to_rename = [(old, new) for old, new in pairs if old != new]

        if not to_rename:
            self.accept()
            return

        # Check for conflicts (duplicate new names)
        new_names = [new for _, new in to_rename]
        if len(new_names) != len(set(new_names)):
            QMessageBox.warning(self, tr("Conflict"), tr("Some new names are duplicates. Fix the pattern."))
            return

        selected_old_names = {old for old, _ in to_rename}
        for old_name, new_name in to_rename:
            try:
                _validate_leaf_name(old_name)
                _validate_leaf_name(new_name)
            except ValueError as exc:
                QMessageBox.warning(
                    self,
                    tr("Invalid Name"),
                    tr("Refusing unsafe rename '{old_name}' -> '{new_name}':\n{exc}").format(old_name=old_name, new_name=new_name, exc=exc),
                )
                return

        # The server's part on a worker (ui.off_gui): five or so round trips
        # a file held the window - a thousand remote files for minutes. The
        # dialog says how far it is; clicks wait until it is done, so the
        # batch is never left half staged under its temporary names.
        from PyQt6.QtCore import QTimer

        from ui.off_gui import run_off_gui

        progress = {"done": 0, "total": len(to_rename), "phase": "Checking"}
        ticker = QTimer(self)
        ticker.setInterval(150)
        ticker.timeout.connect(lambda: self._status.setText(
            tr("{phase} {done} of {total}…").format(
                phase=tr(progress["phase"]), done=progress["done"], total=progress["total"])))
        ticker.start()
        try:
            outcome = run_off_gui(lambda: self._rename_all(to_rename, selected_old_names, progress))
        finally:
            ticker.stop()
        if outcome[0] == "conflict":
            QMessageBox.warning(
                self,
                tr("Conflict"),
                tr("Target '{name}' already exists and is not part of the rename set.").format(
                    name=outcome[1]),
            )
            self._update_preview()
            return
        _kind, renamed, errors = outcome
        if errors:
            QMessageBox.warning(
                self,
                tr("Rename Errors"),
                tr("Renamed {renamed}, failed {n}:\n").format(renamed=renamed, n=len(errors)) + "\n".join(errors[:10]),
            )
        self.accept()

    def _rename_all(self, to_rename, selected_old_names, progress) -> tuple:
        """On a worker: ("conflict", name) before anything moved when a new
        name is taken by an entry outside the set; else ("done", renamed,
        errors) - each entry staged under a hidden temporary name first,
        then given its new one (a chain a -> b, b -> c works)."""
        for old_name, new_name in to_rename:
            new_path = self._backend.join(self._base_path, new_name)
            old_path = self._backend.join(self._base_path, old_name)
            # Case-aware: on a case-insensitive backend "Report.txt" for
            # "report.txt" finds the file itself, not another one.
            if new_name not in selected_old_names and rename_target_taken(
                self._backend, old_path, new_path
            ):
                return ("conflict", new_name)

        errors = []
        renamed = 0
        staged: list[tuple[str, str, str]] = []
        progress["phase"] = "Preparing"
        for done, (old_name, new_name) in enumerate(to_rename, 1):
            old_path = self._backend.join(self._base_path, old_name)
            try:
                temp_path = self._unique_temp_path(old_name)
                self._backend.rename(old_path, temp_path)
                staged.append((old_name, new_name, temp_path))
            except OSError as e:
                log.error("Batch rename staging failed: %s -> %s: %s", old_name, new_name, e)
                errors.append(f"{old_name}: {e}")
            progress["done"] = done
        # Renaming counts each entry once more; one that failed staging is
        # done already.
        progress["phase"], progress["done"] = "Renaming", len(to_rename) - len(staged)

        for old_name, new_name, temp_path in staged:
            new_path = self._backend.join(self._base_path, new_name)
            try:
                if self._backend.exists(new_path):
                    raise OSError(f"target already exists: {new_name}")
                self._backend.rename(temp_path, new_path)
                renamed += 1
                log.info("Batch rename: %s -> %s", old_name, new_name)
            except OSError as e:
                log.error("Batch rename finalize failed: %s -> %s: %s", old_name, new_name, e)
                errors.append(f"{old_name}: {e}")
                note = self._roll_back(old_name, temp_path)
                if note:
                    errors[-1] += f" ({note})"
            progress["done"] += 1
        return ("done", renamed, errors)
