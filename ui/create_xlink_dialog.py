"""Create-XLink dialog — small form over :func:`core.xlink.create_xlink`.

Asks for a filename (without the ``.axlink`` suffix — the library
appends it) and a target URL. The URL field shows the allowed
schemes inline so the user knows which protocols round-trip; the
library still validates server-side before writing the file.
"""
from __future__ import annotations

from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
)

from core import xlink as XL


class CreateXlinkDialog(QDialog):
    """Single-shot form: name + target_url. Validation happens on
    Accept; Reject leaves no on-disk side effect."""

    def __init__(self, default_name: str = "", parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Create XLink")
        self.resize(560, 220)
        self._build_ui(default_name)

    def _build_ui(self, default_name: str) -> None:
        root = QVBoxLayout(self)

        form = QFormLayout()
        self._name_edit = QLineEdit(default_name)
        self._name_edit.setPlaceholderText("link name (no .axlink suffix needed)")
        form.addRow("Name:", self._name_edit)

        self._scheme_box = QComboBox()
        # Sorted alphabetically so the user can scan quickly. The
        # selected entry is just a hint that pre-fills the URL field.
        for scheme in sorted(XL.ALLOWED_TARGET_SCHEMES):
            self._scheme_box.addItem(scheme)
        self._scheme_box.activated.connect(self._on_scheme_picked)
        form.addRow("Scheme:", self._scheme_box)

        self._url_edit = QLineEdit()
        self._url_edit.setPlaceholderText(
            "e.g. sftp://host/path  or  s3://bucket/key  or  ax-cas://sha256:abc"
        )
        form.addRow("Target URL:", self._url_edit)

        self._display_edit = QLineEdit()
        self._display_edit.setPlaceholderText("optional human-readable label")
        form.addRow("Display name:", self._display_edit)
        root.addLayout(form)

        # Allowed-schemes hint so the user can read what's permitted
        # without diving into the library docs.
        hint = QLabel(
            "Allowed schemes: " + ", ".join(sorted(XL.ALLOWED_TARGET_SCHEMES))
        )
        hint.setStyleSheet("color: #666; font-size: 11px;")
        hint.setWordWrap(True)
        root.addWidget(hint)

        self._error = QLabel("")
        self._error.setStyleSheet("color: #c0392b;")
        self._error.setWordWrap(True)
        root.addWidget(self._error)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel,
            self,
        )
        btns.accepted.connect(self._on_accept)
        btns.rejected.connect(self.reject)
        root.addWidget(btns)

    def _on_scheme_picked(self, idx: int) -> None:
        scheme = self._scheme_box.itemText(idx)
        if not scheme:
            return
        # Pre-fill the URL field with the scheme prefix if it's empty
        # — convenience, not enforcement. User can still type any URL.
        if not self._url_edit.text().strip():
            self._url_edit.setText(f"{scheme}://")

    def _on_accept(self) -> None:
        name = self._name_edit.text().strip()
        url = self._url_edit.text().strip()
        if not name:
            self._error.setText("Name is required.")
            return
        if not url:
            self._error.setText("Target URL is required.")
            return
        try:
            XL._validate_target_url(url)
        except ValueError as exc:
            # Surface inline rather than as a popup — the form is
            # right there and the user wants to fix it without
            # losing what they typed.
            self._error.setText(str(exc))
            return
        self._error.setText("")
        self.accept()

    # ------------------------------------------------------------------
    # Caller-facing accessors — only valid after .exec() returned
    # accepted.
    # ------------------------------------------------------------------
    def name(self) -> str:
        return self._name_edit.text().strip()

    def target_url(self) -> str:
        return self._url_edit.text().strip()

    def display_name(self) -> str:
        return self._display_edit.text().strip()
