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

from ui.close_corner import add_close_corner

if TYPE_CHECKING:
    from core.backend import FileBackend
    from models.file_item import FileItem

log = logging.getLogger(__name__)

# Owner r/w/x, group r/w/x, others r/w/x — the order the checkbox grid
# is built in, so index i in ``_checks`` maps to ``_MODE_BITS[i]``.
_MODE_BITS = (0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001)

# setuid, setgid and sticky, shown on the owner/group/others execute
# position like ``ls -l`` does: lower case when the execute bit is set too.
_SPECIAL_MARKS = ((0o4000, 0o100, "s", "S"), (0o2000, 0o010, "s", "S"), (0o1000, 0o001, "t", "T"))

_OCTAL_DIGITS = frozenset("01234567")

#: Shown instead of an editor for a symbolic link.
LINK_NOTE = (
    "This is a symbolic link. Its own permissions cannot be changed, and a "
    "change made here would be applied to the file it points to. Open the "
    "target to change that file's permissions."
)


def _format_octal(mode: int) -> str:
    """Three digits, or four when a setuid/setgid/sticky bit is set."""
    return f"{mode:04o}" if mode & 0o7000 else f"{mode:03o}"


class PermissionsWidget(QWidget):
    """Checkbox grid + octal field + preview for one file's mode.

    ``apply()`` writes the selection through ``backend.chmod`` and
    returns whether the write succeeded. It is a no-op (returning
    ``True``) when the user did not actually change anything.

    The octal field takes three digits (the rwx bits; the file's own
    setuid/setgid/sticky bits are kept) or four (the full mode, as
    chmod(1) reads it, so ``0755`` clears a setuid bit). Text that is not
    such a mode marks the field invalid: ``is_valid()`` turns false,
    ``validity_changed`` fires, and ``apply()`` refuses to write.

    A symbolic link gets a read-only view: chmod follows the link, so an
    edit here would land on the target, whose mode is not what is shown.
    """

    #: Emitted whenever the selected mode changes, with the new mode.
    mode_changed = pyqtSignal(int)
    #: Emitted when the octal field turns valid (True) or invalid (False).
    validity_changed = pyqtSignal(bool)

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
        # The setuid/setgid/sticky bits the next write carries: the
        # file's own until the user types a four-digit mode.
        self._special = self._original_mode & 0o7000
        self._valid = True
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

        self._link_note = QLabel(LINK_NOTE)
        self._link_note.setWordWrap(True)
        self._link_note.setVisible(self._item.is_link)
        layout.addWidget(self._link_note)

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
        self._octal_edit = QLineEdit(_format_octal(self._original_mode & 0o7777))
        self._octal_edit.setMaxLength(4)
        self._octal_edit.setFixedWidth(80)
        self._octal_edit.textChanged.connect(self._on_octal_changed)
        octal_layout.addRow("Octal:", self._octal_edit)
        layout.addLayout(octal_layout)

        self._preview = QLabel()
        layout.addWidget(self._preview)
        self._update_preview()

        if self._item.is_link:
            perm_group.setEnabled(False)
            for cb in self._checks:
                cb.setEnabled(False)
            self._octal_edit.setEnabled(False)

    # -- state -----------------------------------------------------------

    def selected_mode(self) -> int:
        """The mode the checkboxes currently describe (low 9 bits)."""
        mode = 0
        for cb, bit in zip(self._checks, _MODE_BITS):
            if cb.isChecked():
                mode |= bit
        return mode

    def full_mode(self) -> int:
        """The mode a write would set: the rwx bits plus setuid/setgid/sticky."""
        return self.selected_mode() | self._special

    def is_valid(self) -> bool:
        """Whether the octal field holds a mode (three or four octal digits)."""
        return self._valid

    def is_modified(self) -> bool:
        """Whether the selection differs from the mode we opened with.

        Compares the full mode including setuid/setgid/sticky: those are
        carried over from the file unless a four-digit mode was typed, so
        a file whose rwx bits are untouched counts as unmodified and
        pressing OK cannot strip a high bit via a chmod the user never
        asked for.
        """
        return self.full_mode() != self._original_mode & 0o7777

    # -- signal handlers -------------------------------------------------

    def _set_valid(self, valid: bool) -> None:
        if valid == self._valid:
            return
        self._valid = valid
        self._octal_edit.setStyleSheet("" if valid else "QLineEdit { border: 1px solid red; }")
        self._octal_edit.setToolTip(
            "" if valid else "Enter three or four octal digits (0-7), e.g. 644 or 1777."
        )
        self.validity_changed.emit(valid)

    def _update_octal(self) -> None:
        mode = self.full_mode()
        self._octal_edit.blockSignals(True)
        self._octal_edit.setText(_format_octal(mode))
        self._octal_edit.blockSignals(False)
        self._set_valid(True)
        self._update_preview()
        self.mode_changed.emit(mode)

    def _on_octal_changed(self, text: str) -> None:
        text = text.strip()
        # Every keystroke lands here, so a partial entry ("17" on the way
        # to "1777") is applied for a moment; the complete value wins,
        # because it is the last call. Four digits are the full mode.
        if not text or len(text) > 4 or not set(text) <= _OCTAL_DIGITS:
            self._set_valid(False)
            return
        mode = int(text, 8)
        if len(text) == 4:
            self._special = mode & 0o7000
        else:
            self._special = self._original_mode & 0o7000

        for cb, bit in zip(self._checks, _MODE_BITS):
            cb.blockSignals(True)
            cb.setChecked(bool(mode & bit))
            cb.blockSignals(False)
        self._set_valid(True)
        self._update_preview()
        self.mode_changed.emit(self.full_mode())

    def _update_preview(self) -> None:
        mode = self.full_mode()
        chars = [c if mode & b else "-" for c, b in zip("rwxrwxrwx", _MODE_BITS)]
        for (special, exec_bit, with_x, without_x), pos in zip(_SPECIAL_MARKS, (2, 5, 8)):
            if mode & special:
                chars[pos] = with_x if mode & exec_bit else without_x
        perm_str = "".join(chars)
        self._preview.setText(f"Preview: {self._item.type_char}{perm_str}  ({mode:04o})")

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
        if self._item.is_link:
            if not self.is_modified():
                return None
            # chmod follows the link: it would rewrite the target's mode.
            return "Refusing to change permissions through a symbolic link."
        if not self._valid:
            return f"Not an octal mode: {self._octal_edit.text()!r}"
        if not self.is_modified():
            return None

        new_mode = self.full_mode()
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
        ok = buttons.button(QDialogButtonBox.StandardButton.Ok)
        self._widget.validity_changed.connect(ok.setEnabled)
        layout.addWidget(buttons)
        add_close_corner(self)

    def _apply(self) -> None:
        error = self._widget.apply()
        if error is None:
            self.accept()
            return
        QMessageBox.critical(self, "Permission Error", f"Failed to change permissions:\n{error}")


__all__ = ["PermissionsDialog", "PermissionsWidget"]
