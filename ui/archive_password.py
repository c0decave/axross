"""The question for the password of an encrypted archive (a 7z, ZIP
members with ZipCrypto). The answer is handed to core.archive for one
extraction or listing and kept by the archive view while it is open -
never written anywhere, never logged."""
from __future__ import annotations

from PyQt6.QtWidgets import QInputDialog, QLineEdit, QWidget

from core.i18n import tr


def ask_archive_password(parent: QWidget | None, name: str, *, wrong: bool = False) -> str | None:
    """The password the user types for archive *name*; None on Cancel or
    an empty answer. *wrong*: the last one did not open it."""
    from ui.plain_text import as_written

    if wrong:
        label = tr("The password does not open {name}.\nPassword:")
    else:
        label = tr("{name} is encrypted.\nPassword:")
    password, ok = QInputDialog.getText(
        parent,
        tr("Archive Password"),
        as_written(label.format(name=name)),
        QLineEdit.EchoMode.Password,
    )
    return password if ok and password else None
