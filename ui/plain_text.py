"""Text from outside axross shown as it is, never as markup.

Qt guesses whether a tooltip or a label in AutoText is rich text
(``Qt.mightBeRichText``): a file, device, track or share named
``<img width=4000 height=4000 src=x>`` or ``<b>…</b>`` would be rendered -
restyled, hidden or laid out thousands of pixels wide - instead of read.
A name, path or tag is never ours, so wherever one is shown it goes
through here.
"""

from __future__ import annotations

import html


def plain_tooltip(text: str) -> str:
    """*text* as a tooltip that shows exactly *text*.

    A tooltip has no text format to set, so the text is escaped inside a
    rich-text block that keeps its spaces and line breaks (a path with
    two spaces in a row still reads as that path)."""
    if not text:
        return ""
    return f"<qt style='white-space:pre-wrap'>{html.escape(text)}</qt>"


def as_written(text: str) -> str:
    """*text* for a QMessageBox (or any AutoText label) so it shows exactly
    as written: escaped inside a rich-text block that keeps its spaces and
    line breaks. For the static ``QMessageBox.question()`` and friends,
    which guess the format and cannot be told PlainText: a remote file name
    interpolated into their text was rendered - line breaks, styled fake
    notices and live links (the Checksum and Overwrite questions)."""
    return f"<qt style='white-space:pre-wrap'>{html.escape(text or '', quote=False)}</qt>"


def set_plain(label, text: str | None = None):
    """Make *label* (a QLabel) show its text as plain text - optionally
    setting *text* - and return it."""
    from PyQt6.QtCore import Qt

    label.setTextFormat(Qt.TextFormat.PlainText)
    if text is not None:
        label.setText(text)
    return label


def plain_message(parent, icon, title: str, text: str, buttons=None):
    """A QMessageBox showing *text* as plain text (the static
    QMessageBox.warning() and friends guess the format); call ``exec()``."""
    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import QMessageBox

    box = QMessageBox(icon, title, text,
                      QMessageBox.StandardButton.Ok if buttons is None else buttons, parent)
    box.setTextFormat(Qt.TextFormat.PlainText)
    return box


def plain_item(parent, title: str, label: str, items: list[str]) -> tuple[str, bool]:
    """``QInputDialog.getItem(...)`` with *label* shown as plain text (its
    label guesses the format too); ``(choice, ok)``."""
    from PyQt6.QtWidgets import QDialog, QInputDialog, QLabel

    dialog = QInputDialog(parent)
    dialog.setWindowTitle(title)
    dialog.setLabelText(label)
    dialog.setComboBoxItems(items)
    dialog.setComboBoxEditable(False)
    for child in dialog.findChildren(QLabel):
        set_plain(child)
    ok = dialog.exec() == QDialog.DialogCode.Accepted
    choice = dialog.textValue()
    dialog.deleteLater()
    return choice, ok
