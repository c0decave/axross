"""The file-manager prompt for a copy / move onto an existing name."""

from __future__ import annotations

from datetime import datetime

from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
)

from core.i18n import tr
from core.transfer_conflicts import ConflictAction, TransferConflict
from ui.close_corner import add_close_corner
from ui.format_utils import format_size


def _when(mtime: float | None) -> str:
    if mtime is None:
        return tr("unknown")
    try:
        return datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return tr("unknown")


def _describe(is_dir: bool, size: int, mtime: float | None) -> str:
    if is_dir:
        return tr("Folder, modified {when}").format(when=_when(mtime))
    return tr("{size}, modified {when}").format(size=format_size(size), when=_when(mtime))


class TransferConflictDialog(QDialog):
    """Overwrite / Overwrite if newer / Skip / Rename / Cancel for one name.

    ``result_choice()`` is ``(action, apply_to_all)`` or ``None`` for
    Cancel. A file against a folder (or the reverse) can only be skipped
    or renamed.
    """

    def __init__(self, conflict: TransferConflict, remaining: int = 0, parent=None) -> None:
        super().__init__(parent)
        self._choice: tuple[ConflictAction, bool] | None = None
        self.setWindowTitle(tr("File Already Exists"))
        layout = QVBoxLayout(self)

        if conflict.type_mismatch:
            what = tr("A folder") if conflict.dest_is_dir else tr("A file")
            headline = tr("{what} named “{name}” is already in {folder}.").format(
                what=what, name=conflict.name, folder=conflict.dest_dir
            )
        else:
            headline = tr("“{name}” already exists in {folder}.").format(
                name=conflict.name, folder=conflict.dest_dir
            )
        title = QLabel(headline)
        title.setWordWrap(True)
        layout.addWidget(title)

        grid = QGridLayout()
        grid.addWidget(QLabel(tr("Existing:")), 0, 0)
        grid.addWidget(
            QLabel(_describe(conflict.dest_is_dir, conflict.dest_size, conflict.dest_mtime)), 0, 1
        )
        grid.addWidget(QLabel(tr("New:")), 1, 0)
        grid.addWidget(
            QLabel(_describe(conflict.source_is_dir, conflict.source_size, conflict.source_mtime)),
            1,
            1,
        )
        layout.addLayout(grid)

        self.apply_all = QCheckBox(
            tr("Do this for the remaining {n} conflict(s)").format(n=remaining)
        )
        self.apply_all.setVisible(remaining > 0)
        layout.addWidget(self.apply_all)

        row = QHBoxLayout()
        labels = {
            ConflictAction.OVERWRITE: tr("Overwrite"),
            ConflictAction.OVERWRITE_IF_NEWER: tr("Overwrite if Newer"),
            ConflictAction.SKIP: tr("Skip"),
            ConflictAction.RENAME: tr("Rename"),
        }
        self.buttons: dict[ConflictAction, QPushButton] = {}
        for action, label in labels.items():
            button = QPushButton(label)
            button.clicked.connect(lambda _checked=False, a=action: self._choose(a))
            row.addWidget(button)
            self.buttons[action] = button
        if conflict.type_mismatch:
            self.buttons[ConflictAction.OVERWRITE].setEnabled(False)
            self.buttons[ConflictAction.OVERWRITE_IF_NEWER].setEnabled(False)
        self.buttons[ConflictAction.RENAME].setToolTip(
            tr("Keep both: the new one gets a free name such as “name (1).ext”")
        )
        self.buttons[ConflictAction.SKIP].setDefault(True)
        cancel = QPushButton(tr("Cancel"))
        cancel.setToolTip(tr("Cancel the whole transfer; nothing is copied"))
        cancel.clicked.connect(self.reject)
        row.addWidget(cancel)
        layout.addLayout(row)
        add_close_corner(self)

    def _choose(self, action: ConflictAction) -> None:
        # isHidden, not isVisible: the box counts while the dialog is up.
        apply_all = not self.apply_all.isHidden() and self.apply_all.isChecked()
        self._choice = (action, apply_all)
        self.accept()

    def reject(self) -> None:
        self._choice = None
        super().reject()

    def result_choice(self) -> tuple[ConflictAction, bool] | None:
        return self._choice
