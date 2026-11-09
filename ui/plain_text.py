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
#: or of direction marks, embeddings, overrides and isolates (LRM, RLM,
#: LRE/RLE/PDF/LRO/RLO, LRI/RLI/FSI/PDI; ALM is in the Arabic block): each
#: is a change of direction for Qt - "a" RLM NBSP repeated, 63,000
#: characters, kept the GUI thread 4.65 s.
_RTL_RUN = re.compile("[\u0590-\u08ff\ufb1d-\ufdff\ufe70-\ufefc"
                      "\U00010800-\U00010fff\U0001e800-\U0001efff"
                      "\u200e\u200f\u202a-\u202e\u2066-\u2069]+")
#: a word as Qt breaks lines: the no-break spaces (U+00A0, U+2007,
#: U+202F; Python's \s) join words - the word joiner U+2060 is no \s.
_WORD = re.compile("[\\S\u00a0\u2007\u202f]+")


#: a run of letters outside Latin (Greek, Cyrillic, CJK, ...): inside one
#: long word each is an item of its own for Qt - "a" NBSP alpha NBSP
#: repeated, 64,000 characters, kept the GUI thread 7.2 s.
#: (General punctuation - the no-break spaces among it - and variation
#: selectors belong to no script: they do not end a run; right-to-left
#: letters are counted as :data:`_RTL_RUN`.)
_SCRIPT_RUN = re.compile("[^\x00-\u036f\u0590-\u08ff\u2000-\u206f\ufb1d-\ufdff\ufe00-\ufe0f"
                         "\ufe70-\ufefc\U00010800-\U00010fff\U0001e800-\U0001efff]+")
#: Words longer than this have their changes of script counted.
LONG_WORD = 200
#: (a word only from its start: trying every place inside a long word
#: again would take quadratic time)
_LONG_WORD = re.compile("(?<![\\S\u00a0\u2007\u202f])[\\S\u00a0\u2007\u202f]{%d,}" % (LONG_WORD + 1))
_TOO_LONG_WORD = re.compile("(?<![\\S\u00a0\u2007\u202f])[\\S\u00a0\u2007\u202f]{%d,}"
                            % (MAX_SHOWN_WORD + 1))
#: The most changes of script inside long words laid out (as with
#: right-to-left runs: 16,000 such changes in one word took 1.15 s).
MAX_SHOWN_SCRIPT_RUNS = 1000
#: What one right-to-left run or change of script costs the layout, in
#: characters of plain words (:func:`layout_cost`): 128 lines of 1000
#: runs each took 4.5 s, 512,000 characters of plain words 0.2 s.
RUN_COST = 64


def _script_runs(text: str, end: int, stop_at: int = 0) -> tuple[int, int]:
    """The changes of script inside the long words of ``text[:end]``, and
    where the *stop_at*-th of them starts (*end* when there are fewer)."""
    count = 0
    for word in _LONG_WORD.finditer(text, 0, end):
        for match in _SCRIPT_RUN.finditer(text, *word.span()):
            count += 1
            if count == stop_at:
                return count, match.start()
    return count, end


def shown_length(text: str, limit: int = MAX_SHOWN_CHARS) -> int:
    """How much of *text* a rich-text view lays out: at most *limit*
    characters, cut before the :data:`MAX_SHOWN_RTL_RUNS`-th right-to-left
    run (or direction mark), before the :data:`MAX_SHOWN_SCRIPT_RUNS`-th
    change of script inside long words and inside a word longer than
    :data:`MAX_SHOWN_WORD` (never below :data:`MIN_SHOWN_CHARS`, or *limit*
    when that is less). Words end only where Qt breaks a line: a no-break
    space joins two."""
    end = min(len(text), limit)
    head = text[:end]
    for count, match in enumerate(_RTL_RUN.finditer(head), 1):
        if count >= MAX_SHOWN_RTL_RUNS:
            end = min(end, max(match.start(), MIN_SHOWN_CHARS))
            break
    word = _TOO_LONG_WORD.search(text, 0, end)
    if word:
        end = min(end, max(word.start() + MAX_SHOWN_WORD, MIN_SHOWN_CHARS))
    count, at = _script_runs(text, end, MAX_SHOWN_SCRIPT_RUNS)
    if count >= MAX_SHOWN_SCRIPT_RUNS:
        end = min(end, max(at, MIN_SHOWN_CHARS))
    return min(end, len(text))


def short_length(text: str, limit: int, max_runs: int = 16) -> int:
    """How much of *text* a line shown only by its start lays out: at most
    *limit* characters, cut before its *max_runs*-th right-to-left run or
    run of letters outside Latin (a transcript keeps thousands of such
    lines: 2000 of 200 mixed-direction characters took 3.3 s)."""
    end = min(len(text), limit)
    starts = sorted(m.start() for pattern in (_RTL_RUN, _SCRIPT_RUN) for m in pattern.finditer(text, 0, end))
    if len(starts) >= max_runs:
        end = min(end, max(starts[max_runs - 1], 1))
    return end


def layout_cost(text: str, end: int | None = None) -> int:
    """What laying out ``text[:end]`` costs, in characters of plain words:
    its length, and :data:`RUN_COST` for each right-to-left run and each
    change of script inside a long word (a transcript drawn again whole
    adds these up: eight answers of script changes took 21 s)."""
    end = len(text) if end is None else min(end, len(text))
    runs = sum(1 for _ in _RTL_RUN.finditer(text, 0, end))
    return end + RUN_COST * (runs + _script_runs(text, end)[0])


def _plain_lines(text: str, limit: int = 2 * 1024 * 1024, width: int = 1000,
                 max_lines: int = 100_000) -> tuple[str, bool]:
    """core.mail_html.plain_lines for a program exported without it: every
    line broken after *width* characters, at most *limit* characters and
    *max_lines* lines; and whether some was left out."""
    out: list[str] = []
    for line in re.split(r"\r\n|[\n\r\v\f\x1c-\x1e\x85\u2028\u2029]", text[:limit]):
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
