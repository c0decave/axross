"""The questions that say a connection's trash is a folder of a share.

On this machine's disk and over SFTP the axross trash is a private folder
(0700) and a kept copy keeps its own mode. On S3, SMB, WebDAV, FTP and the
cloud backends it is a folder at the top of the share (core.trash
:func:`~core.trash.shared_trash_folder`): what goes there has that folder's
permissions, not those of the folder it came from. Move to Trash and Remove
Metadata in place say so and offer what keeps no copy there.
"""

from __future__ import annotations

from PyQt6.QtWidgets import QMessageBox

from core.i18n import tr
from ui.plain_text import as_written

#: The answers of :func:`ask_move_to_shared_trash`.
TRASH, DELETE = "trash", "delete"


def trash_note(folder: str) -> str:
    """The sentences Move to Trash adds for a trash folder *folder* of a share."""
    return tr(
        "On this connection the trash is the folder {folder} at the top of the share. "
        "There the files have the permissions of that folder, not those of the folder "
        "they are in now: whoever may open {folder} may open them. Delete Permanently "
        "keeps no copy."
    ).format(folder=folder)


def metadata_note(folder: str) -> str:
    """The sentences Remove Metadata in place adds for a trash *folder* of a share."""
    return tr(
        "The originals, with all their metadata, are kept in {folder}, the trash at the "
        "top of this share. There they have the permissions of that folder, not those of "
        "the folder they are in now: whoever may open {folder} may open them. Cleaned "
        "copies instead leave each original where it is and keep nothing in the trash."
    ).format(folder=folder)


def shares_note(backends) -> str:
    """The sentences a Duplicate Finder removal adds when some of *backends*
    keep their trash at the top of a share ("" when none does)."""
    from core.trash import shared_trash_folder

    folders = []
    for backend in backends:
        folder = shared_trash_folder(backend)
        if folder is not None and folder not in folders:
            folders.append(folder)
    if not folders:
        return ""
    return tr(
        "On a share the trash is the folder {folders} at its top. There the files have "
        "the permissions of that folder, not those of the folder they are in now: whoever "
        "may open it may open them."
    ).format(folders=", ".join(folders))


def _ask(parent, title: str, text: str, choices: list[tuple[str, str]]) -> str | None:
    """A question with *choices* ``(answer, label)``, the first the default;
    the answer chosen, None for Cancel."""
    box = QMessageBox(QMessageBox.Icon.Warning, title, as_written(text),
                      QMessageBox.StandardButton.NoButton, parent)
    buttons = {}
    for n, (answer, label) in enumerate(choices):
        button = box.addButton(label, QMessageBox.ButtonRole.AcceptRole if n == 0
                               else QMessageBox.ButtonRole.DestructiveRole
                               if answer == DELETE else QMessageBox.ButtonRole.ActionRole)
        buttons[id(button)] = answer
        if n == 0:
            box.setDefaultButton(button)
    cancel = box.addButton(QMessageBox.StandardButton.Cancel)
    box.setEscapeButton(cancel)
    box.exec()
    clicked = box.clickedButton()
    return buttons.get(id(clicked)) if clicked is not None else None


def ask_move_to_shared_trash(parent, title: str, question: str, folder: str) -> str | None:
    """Move to Trash, Delete Permanently or Cancel (None), with the
    trash folder named."""
    return _ask(parent, title, f"{question}\n\n{trash_note(folder)}",
                [(TRASH, tr("Move to Trash")), (DELETE, tr("Delete Permanently"))])


def ask_metadata_in_place(parent, question: str, folder: str) -> str | None:
    """``"in_place"``, ``"copy"`` or None (Cancel) for Remove Metadata whose
    originals would go to the trash folder *folder* of a share."""
    return _ask(parent, tr("Remove Metadata"), f"{question}\n\n{metadata_note(folder)}",
                [("in_place", tr("Keep Originals in the Trash")),
                 ("copy", tr("Cleaned Copies Instead"))])
