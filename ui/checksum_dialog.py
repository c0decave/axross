"""One-shot dialog showing a file's checksum with copy-to-clipboard.

Used by the file pane's "Show Checksum…" entry. Construction takes
the already-computed value — the heavy lifting (native call or
stream-hash) happens in the caller, so this dialog stays a pure
renderer.
"""
from __future__ import annotations

from PyQt6.QtGui import QFont, QGuiApplication
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)


class ChecksumDialog(QDialog):
    """Show *value* as a selectable monospace string with a Copy button."""

    def __init__(self, path: str, algo: str, value: str,
                 source: str = "native", parent=None) -> None:
        super().__init__(parent)
        self._value = value
        self.setWindowTitle("Checksum")
        self.resize(640, 160)
        self._build_ui(path, algo, value, source)

    def _build_ui(self, path: str, algo: str, value: str,
                  source: str) -> None:
        root = QVBoxLayout(self)

        path_label = QLabel(path)
        path_label.setStyleSheet("color: #666;")
        path_label.setWordWrap(True)
        root.addWidget(path_label)

        meta = QLabel(f"{algo}  ({source})")
        meta.setStyleSheet("color: #666;")
        root.addWidget(meta)

        self._field = QLineEdit(value)
        self._field.setReadOnly(True)
        font = QFont("Monospace", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self._field.setFont(font)
        root.addWidget(self._field)

        btn_row = QHBoxLayout()
        copy_btn = QPushButton("Copy", self)
        copy_btn.clicked.connect(self._copy)
        btn_row.addWidget(copy_btn)
        btn_row.addStretch(1)
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, self)
        close.rejected.connect(self.reject)
        close.accepted.connect(self.accept)
        btn_row.addWidget(close)
        root.addLayout(btn_row)

    def _copy(self) -> None:
        QGuiApplication.clipboard().setText(self._value)
