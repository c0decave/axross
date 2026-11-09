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
import re


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


# -- long texts from outside in a rich-text view ------------------------------------------
#
# A QTextBrowser lays out a paragraph at once, and some paragraphs cost far
# more than their length: one 250,000-character word took 6.6 s (Qt breaks
# a long word in quadratic time), 40,000 characters of alternating Hebrew
# and Latin letters 6.7 s and 200,000 more than 90 s (each change of
# direction is a run of its own). An agent's answer and a chat message
# (16,000 characters) come from outside: only a part of such a text is laid
# out, and the rest is a click away in a plain view (show_full_text).

#: The most characters of one text laid out in a rich-text view.
MAX_SHOWN_CHARS = 64 * 1024
#: The most right-to-left runs (Hebrew, Arabic, ...) of one text laid out:
#: 2500 runs between Latin letters took 0.17 s, 10,000 1.6 s.
MAX_SHOWN_RTL_RUNS = 1000
#: The longest word laid out (16,000 characters: about 0.03 s).
MAX_SHOWN_WORD = 16_000
#: Never less than this is shown of a text (when it has it).
MIN_SHOWN_CHARS = 4000

#: a run of right-to-left letters (Hebrew, Arabic, Syriac, Thaana, NKo, ...)
_RTL_RUN = re.compile("[\u0590-\u08ff\ufb1d-\ufdff\ufe70-\ufefc"
                      "\U00010800-\U00010fff\U0001e800-\U0001efff]+")
_WORD = re.compile(r"\S+")


def shown_length(text: str, limit: int = MAX_SHOWN_CHARS) -> int:
    """How much of *text* a rich-text view lays out: at most *limit*
    characters, cut before the :data:`MAX_SHOWN_RTL_RUNS`-th right-to-left
    run and inside a word longer than :data:`MAX_SHOWN_WORD` (never below
    :data:`MIN_SHOWN_CHARS`, or *limit* when that is less)."""
    end = min(len(text), limit)
    head = text[:end]
    for count, match in enumerate(_RTL_RUN.finditer(head), 1):
        if count >= MAX_SHOWN_RTL_RUNS:
            end = min(end, max(match.start(), MIN_SHOWN_CHARS))
            break
    for word in _WORD.finditer(text, 0, end):
        if word.end() - word.start() > MAX_SHOWN_WORD:
            end = min(end, max(word.start() + MAX_SHOWN_WORD, MIN_SHOWN_CHARS))
            break
    return min(end, len(text))


def _plain_lines(text: str, limit: int = 2 * 1024 * 1024, width: int = 1000,
                 max_lines: int = 100_000) -> tuple[str, bool]:
    """core.mail_html.plain_lines for a program exported without it: every
    line broken after *width* characters, at most *limit* characters and
    *max_lines* lines; and whether some was left out."""
    out: list[str] = []
    for line in text[:limit].split("\n"):
        pieces = [line[i:i + width] for i in range(0, len(line), width)] or [""]
        if len(out) + len(pieces) > max_lines:
            out.extend(pieces[:max_lines - len(out)])
            return "\n".join(out), True
        out.extend(pieces)
    return "\n".join(out), len(text) > limit


def show_full_text(parent, title: str, text: str):
    """*text* in a window of its own, as plain text (a QPlainTextEdit lays
    out only the lines on screen; every line is broken after
    core.mail_html.PLAIN_LINE characters, at most MAX_PLAIN of them)."""
    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import QDialog, QDialogButtonBox, QPlainTextEdit, QVBoxLayout

    from core.i18n import tr
    from ui.close_corner import add_close_corner
    from ui.icon_provider import set_window_icon

    try:
        from core.mail_html import plain_lines
    except ImportError:  # an exported tool comes without the mail viewer
        plain_lines = _plain_lines

    dialog = QDialog(parent)
    dialog.setWindowTitle(title)
    set_window_icon(dialog, "file")
    dialog.resize(800, 600)
    layout = QVBoxLayout(dialog)
    add_close_corner(dialog)
    view = QPlainTextEdit()
    view.setReadOnly(True)
    shown, cut = plain_lines(text)
    if cut:
        shown += "\n\n" + tr("[The rest of this text is not shown here.]")
    view.setPlainText(shown)
    layout.addWidget(view, 1)
    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
    buttons.rejected.connect(dialog.reject)
    layout.addWidget(buttons)
    dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
    dialog.show()
    return dialog
