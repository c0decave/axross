"""The view of the in-app guides: a safe QTextBrowser, going to a heading,
find-in-page.

Shared by Help > Scripting Guide (ui.scripting_guide) and Help > Handbook
(ui.handbook). The guides are Markdown files of docs/:

* **Nothing is loaded.** :meth:`GuideBrowser.loadResource` answers None for
  every URL - no image, no style sheet, local or remote (the guides have
  none; a file that asked for one would get nothing).
* **No raw HTML.** The Markdown is rendered without HTML spans and blocks
  (ui.update_ui.NOTES_MARKDOWN), so ``<name>`` in the prose is text.
* **No link opens by itself.** ``setOpenLinks(False)``: every click goes
  to the dialog's handler, which decides what a link may do.
"""

from __future__ import annotations

from collections.abc import Callable

from PyQt6.QtCore import QUrl
from PyQt6.QtGui import QTextCursor
from PyQt6.QtWidgets import QTextBrowser, QWidget


class GuideBrowser(QTextBrowser):
    """A guide's text: Markdown without raw HTML, no resource loaded, every
    link to the owner (``anchorClicked``)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setOpenLinks(False)
        self.setOpenExternalLinks(False)
        #: The resources the text asked for and did not get (for tests).
        self.refused_resources: set[str] = set()

    def set_guide_markdown(self, text: str) -> None:
        from ui.update_ui import NOTES_MARKDOWN

        self.document().setMarkdown(text, NOTES_MARKDOWN)
        self.moveCursor(QTextCursor.MoveOperation.Start)

    def loadResource(self, kind: int, name: QUrl):  # noqa: N802 - Qt
        """Nothing, for every resource (see the module docstring)."""
        if len(self.refused_resources) < 100:
            self.refused_resources.add(name.toString())
        return None


def heading_block(view: QTextBrowser, match: Callable[[str], bool]) -> QTextCursor | None:
    """A cursor at the first heading block of *view* for which *match(text)*
    holds, or None."""
    block = view.document().begin()
    while block.isValid():
        if block.blockFormat().headingLevel() > 0 and match(block.text()):
            return QTextCursor(block)
        block = block.next()
    return None


def scroll_to(view: QTextBrowser, cursor: QTextCursor) -> None:
    """Put the heading of *cursor* at the top of *view*."""
    view.setTextCursor(cursor)
    rect = view.document().documentLayout().blockBoundingRect(cursor.block())
    view.verticalScrollBar().setValue(int(rect.top()))


def find_next(view: QTextBrowser, needle: str) -> bool:
    """Select the next match of *needle* in *view*, wrapping at the end.
    False when there is none (or *needle* is empty)."""
    if not needle:
        return False
    if view.find(needle):
        return True
    # Wrap: from the start once more. Nothing there either - the view goes
    # back where it was (it was left at the top, the place read lost).
    before = view.textCursor()
    scroll = view.verticalScrollBar().value()
    cursor = QTextCursor(before)
    cursor.movePosition(QTextCursor.MoveOperation.Start)
    view.setTextCursor(cursor)
    if view.find(needle):
        return True
    view.setTextCursor(before)
    view.verticalScrollBar().setValue(scroll)
    return False


__all__ = ["GuideBrowser", "find_next", "heading_block", "scroll_to"]
