"""Right-click > Pack > Pack with Options…: archive name, format, level and,
for 7z, a password (AES-256) with optional encrypted file names."""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QStandardItemModel
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)

from core import packer as PK
from core.i18n import tr
from ui.close_corner import add_close_corner


class PackDialog(QDialog):
    def __init__(
        self, names: list[str], default_name: str, *, single_file: bool, parent=None
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Pack"))
        self.setMinimumWidth(460)
        self._single_file = single_file
        what = names[0] if len(names) == 1 else tr("{n} items").format(n=len(names))
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(tr("Pack {what}").format(what=what)))
        form = QFormLayout()
        layout.addLayout(form)

        self.name_edit = QLineEdit(default_name)
        form.addRow(tr("Archive name:"), self.name_edit)
        self.format_combo = QComboBox()
        for fmt in PK.FORMATS.values():
            self.format_combo.addItem(fmt.label, fmt.fmt_id)
        self._disable_unusable_formats()
        form.addRow(tr("Format:"), self.format_combo)
        self.level_combo = QComboBox()
        self.level_combo.addItems(list(PK.LEVELS))
        self.level_combo.setCurrentText("normal")
        form.addRow(tr("Compression:"), self.level_combo)
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.repeat_edit = QLineEdit()
        self.repeat_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow(tr("Password (7z):"), self.password_edit)
        form.addRow(tr("Repeat password:"), self.repeat_edit)
        self.names_box = QCheckBox(tr("Encrypt file names too"))
        self.names_box.setChecked(True)
        form.addRow("", self.names_box)
        self.target_label = QLabel()
        self.target_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        form.addRow(tr("Writes:"), self.target_label)
        self.hint = QLabel()
        self.hint.setWordWrap(True)
        layout.addWidget(self.hint)

        self._buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self._buttons.accepted.connect(self.accept)
        self._buttons.rejected.connect(self.reject)
        layout.addWidget(self._buttons)

        for signal in (
            self.format_combo.currentIndexChanged,
            self.name_edit.textChanged,
            self.password_edit.textChanged,
            self.repeat_edit.textChanged,
        ):
            signal.connect(self._update)
        self._update()
        add_close_corner(self)

    # -- formats ----------------------------------------------------------------
    def _disable_unusable_formats(self) -> None:
        model = self.format_combo.model()
        assert isinstance(model, QStandardItemModel)
        first_usable = -1
        for row, fmt in enumerate(PK.FORMATS.values()):
            ok, reason = fmt.available()
            if fmt.single and not self._single_file:
                ok, reason = False, tr("compresses exactly one file - select a single file")
            item = model.item(row)
            if not ok:
                item.setEnabled(False)
                item.setToolTip(reason)
            elif first_usable < 0:
                first_usable = row
        self.format_combo.setCurrentIndex(max(first_usable, 0))

    def _index_of(self, fmt_id: str) -> int:
        return self.format_combo.findData(fmt_id)

    def format_enabled(self, fmt_id: str) -> bool:
        return self.format_combo.model().item(self._index_of(fmt_id)).isEnabled()

    def format_tooltip(self, fmt_id: str) -> str:
        return self.format_combo.model().item(self._index_of(fmt_id)).toolTip()

    def set_format(self, fmt_id: str) -> None:
        self.format_combo.setCurrentIndex(self._index_of(fmt_id))

    def current_format(self) -> PK.Format:
        return PK.FORMATS[self.format_combo.currentData()]

    # -- state ------------------------------------------------------------------
    def ok_button(self) -> QPushButton:
        return self._buttons.button(QDialogButtonBox.StandardButton.Ok)

    def _update(self) -> None:
        fmt = self.current_format()
        encrypts = fmt.encrypts
        for widget in (self.password_edit, self.repeat_edit):
            widget.setEnabled(encrypts)
            if not encrypts and widget.text():
                widget.blockSignals(True)
                widget.clear()
                widget.blockSignals(False)
        pw, repeat = self.password_edit.text(), self.repeat_edit.text()
        self.names_box.setEnabled(encrypts and bool(pw))
        name = self.name_edit.text().strip()
        stem = name[: -len(fmt.suffix)] if name.lower().endswith(fmt.suffix) else name
        self.target_label.setText(f"{stem}{fmt.suffix}" if stem else "")
        problem = ""
        if not stem or "/" in stem or "\\" in stem or stem in (".", ".."):
            problem = tr("Enter a file name without a folder.")
        elif encrypts and pw != repeat:
            problem = tr("The passwords differ.")
        elif not self.format_enabled(fmt.fmt_id):
            problem = self.format_tooltip(fmt.fmt_id)
        if problem:
            self.hint.setText(problem)
        elif encrypts and pw:
            self.hint.setText(tr("AES-256. Without the password the archive cannot be opened."))
        elif encrypts:
            self.hint.setText(tr("No password: the 7z is not encrypted."))
        else:
            self.hint.setText(tr("For a password, choose 7z."))
        self.ok_button().setEnabled(not problem)

    def result_values(self) -> tuple[str, PK.PackOptions]:
        fmt = self.current_format()
        options = PK.PackOptions(
            fmt=fmt.fmt_id,
            level=self.level_combo.currentText(),
            password=self.password_edit.text() if fmt.encrypts else "",
            encrypt_names=self.names_box.isChecked(),
        )
        return self.name_edit.text().strip(), options


__all__ = ["PackDialog"]
