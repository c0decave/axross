"""Python editor for the Scripts dock — QPlainTextEdit, no new dependency.

* :class:`PythonHighlighter` — keywords, builtins, strings (triple-quoted
  ones across lines), comments, numbers, decorators and the names after
  ``def`` / ``class``. A small scanner rather than a pile of overlapping
  regexes: a ``#`` inside a string must not start a comment, and a
  keyword inside a docstring must stay string.
* :class:`CodeEditor` — line numbers, auto-indent (keep the indent, one
  level more after a colon, one less after ``return`` / ``pass`` / …),
  Tab inserts four spaces and Shift+Tab removes up to four, both on every
  selected line, and :meth:`CodeEditor.go_to_line` for traceback links.

Colours follow the palette: a dark base gets the dark set, a light base
the light one, so the editor reads under every theme.
"""

from __future__ import annotations

import builtins
import keyword
import re

from PyQt6.QtCore import QRect, QSize, Qt
from PyQt6.QtGui import (
    QColor,
    QFont,
    QFontDatabase,
    QKeyEvent,
    QPainter,
    QPalette,
    QSyntaxHighlighter,
    QTextCharFormat,
    QTextCursor,
    QTextFormat,
)
from PyQt6.QtWidgets import QPlainTextEdit, QTextEdit, QWidget

INDENT = "    "

#: Statements after which the next line goes one level out.
_DEDENT_AFTER = re.compile(r"^\s*(return|pass|break|continue|raise)\b")

_KEYWORDS = frozenset(keyword.kwlist) | frozenset(getattr(keyword, "softkwlist", ()))
_BUILTINS = frozenset(n for n in dir(builtins) if not n.startswith("_")) - _KEYWORDS

_TOKEN = re.compile(
    r"(?P<comment>\#.*)"
    r"|(?P<string>(?:\b[rRbBuUfF]{1,2})?(?:'''|\"\"\"|'(?:\\.|[^'\\])*'?|\"(?:\\.|[^\"\\])*\"?))"
    r"|(?P<number>\b(?:0[xXoObB][0-9a-fA-F_]+|\d[\d_]*\.?\d*(?:[eE][+-]?\d+)?j?)\b)"
    r"|(?P<decorator>^\s*@[\w.]+)"
    r"|(?P<word>\b[A-Za-z_]\w*\b)"
)

#: (dark palette, light palette) colour per token kind.
_COLOURS: dict[str, tuple[str, str]] = {
    "keyword": ("#c586c0", "#8f08c4"),
    "builtin": ("#4ec9b0", "#267f99"),
    "string": ("#ce9178", "#a31515"),
    "comment": ("#6a9955", "#008000"),
    "number": ("#b5cea8", "#098658"),
    "decorator": ("#dcdcaa", "#795e26"),
    "definition": ("#dcdcaa", "#001080"),
}

#: Block states: inside a triple-quoted string opened with ''' or """.
_STATE_NONE, _STATE_SINGLE3, _STATE_DOUBLE3 = 0, 1, 2
_DELIMS = {_STATE_SINGLE3: "'''", _STATE_DOUBLE3: '"""'}


def _is_dark(palette: QPalette) -> bool:
    return palette.color(QPalette.ColorRole.Base).lightness() < 128


class PythonHighlighter(QSyntaxHighlighter):
    """Highlights one block at a time; a triple-quoted string carries over."""

    #: QTextFormat property holding the token kind, so tests (and themes)
    #: can tell formats apart without comparing colours.
    KIND_PROPERTY = QTextFormat.Property.UserProperty + 1

    def __init__(self, document, *, dark: bool = True) -> None:
        super().__init__(document)
        self.set_dark(dark)

    def set_dark(self, dark: bool) -> None:
        self._formats: dict[str, QTextCharFormat] = {}
        for kind, (on_dark, on_light) in _COLOURS.items():
            fmt = QTextCharFormat()
            fmt.setForeground(QColor(on_dark if dark else on_light))
            fmt.setProperty(self.KIND_PROPERTY, kind)
            if kind in ("keyword", "definition"):
                fmt.setFontWeight(QFont.Weight.Bold)
            if kind == "comment":
                fmt.setFontItalic(True)
            self._formats[kind] = fmt
        self.rehighlight()

    def _mark(self, start: int, length: int, kind: str) -> None:
        if length > 0:
            self.setFormat(start, length, self._formats[kind])

    def highlightBlock(self, text: str) -> None:  # noqa: N802 — Qt
        pos = 0
        state = self.previousBlockState()
        if state in _DELIMS:
            end = text.find(_DELIMS[state])
            if end < 0:
                self._mark(0, len(text), "string")
                self.setCurrentBlockState(state)
                return
            pos = end + 3
            self._mark(0, pos, "string")
        self.setCurrentBlockState(_STATE_NONE)
        previous_word = ""
        while pos < len(text):
            match = _TOKEN.search(text, pos)
            if match is None:
                break
            kind = match.lastgroup or ""
            start, end = match.span()
            token = match.group()
            if kind == "string" and token.lstrip("rRbBuUfF") in ("'''", '"""'):
                delim = token.lstrip("rRbBuUfF")
                close = text.find(delim, end)
                if close < 0:
                    self._mark(start, len(text) - start, "string")
                    self.setCurrentBlockState(_STATE_SINGLE3 if delim == "'''" else _STATE_DOUBLE3)
                    return
                end = close + 3
                self._mark(start, end - start, "string")
            elif kind == "word":
                if previous_word in ("def", "class"):
                    self._mark(start, end - start, "definition")
                elif token in _KEYWORDS:
                    self._mark(start, end - start, "keyword")
                elif token in _BUILTINS:
                    self._mark(start, end - start, "builtin")
                previous_word = token
            elif kind == "decorator":
                at = text.index("@", start)
                self._mark(at, end - at, "decorator")
            elif kind:
                self._mark(start, end - start, kind)
            pos = max(end, pos + 1)


class _LineNumberArea(QWidget):
    def __init__(self, editor: "CodeEditor") -> None:
        super().__init__(editor)
        self._editor = editor

    def sizeHint(self) -> QSize:  # noqa: N802 — Qt
        return QSize(self._editor.line_number_area_width(), 0)

    def paintEvent(self, event) -> None:  # noqa: N802 — Qt
        self._editor._paint_line_numbers(event)


class CodeEditor(QPlainTextEdit):
    """Plain-text Python editor with line numbers and indentation keys."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        self.setFont(font)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setTabStopDistance(self.fontMetrics().horizontalAdvance(" ") * len(INDENT))
        self.highlighter = PythonHighlighter(self.document(), dark=_is_dark(self.palette()))
        self._marked_line: int | None = None
        self._line_numbers = _LineNumberArea(self)
        self.blockCountChanged.connect(self._update_margins)
        self.updateRequest.connect(self._update_line_number_area)
        self.cursorPositionChanged.connect(self._refresh_selections)
        self.textChanged.connect(self._clear_mark)
        self._update_margins()
        self._refresh_selections()

    # -- line numbers ------------------------------------------------------
    def line_number_area_width(self) -> int:
        digits = len(str(max(1, self.blockCount())))
        return 8 + self.fontMetrics().horizontalAdvance("9") * max(3, digits)

    def _update_margins(self, *_args) -> None:
        self.setViewportMargins(self.line_number_area_width(), 0, 0, 0)

    def _update_line_number_area(self, rect: QRect, dy: int) -> None:
        if dy:
            self._line_numbers.scroll(0, dy)
        else:
            self._line_numbers.update(0, rect.y(), self._line_numbers.width(), rect.height())
        if rect.contains(self.viewport().rect()):
            self._update_margins()

    def resizeEvent(self, event) -> None:  # noqa: N802 — Qt
        super().resizeEvent(event)
        cr = self.contentsRect()
        self._line_numbers.setGeometry(
            QRect(cr.left(), cr.top(), self.line_number_area_width(), cr.height())
        )

    def _paint_line_numbers(self, event) -> None:
        painter = QPainter(self._line_numbers)
        palette = self.palette()
        painter.fillRect(event.rect(), palette.color(QPalette.ColorRole.AlternateBase))
        painter.setPen(palette.color(QPalette.ColorRole.PlaceholderText))
        block = self.firstVisibleBlock()
        top = round(self.blockBoundingGeometry(block).translated(self.contentOffset()).top())
        height = self.fontMetrics().height()
        width = self._line_numbers.width() - 4
        while block.isValid() and top <= event.rect().bottom():
            bottom = top + round(self.blockBoundingRect(block).height())
            if block.isVisible() and bottom >= event.rect().top():
                painter.drawText(
                    0,
                    top,
                    width,
                    height,
                    Qt.AlignmentFlag.AlignRight,
                    str(block.blockNumber() + 1),
                )
            block = block.next()
            top = bottom
        painter.end()

    # -- current line / marked line ----------------------------------------
    def go_to_line(self, line: int) -> bool:
        """Put the cursor on 1-based ``line`` and mark it until the next edit.
        Returns False (and moves nothing) for a line the text does not have."""
        if line < 1 or line > self.blockCount():
            return False
        block = self.document().findBlockByNumber(line - 1)
        cursor = QTextCursor(block)
        self.setTextCursor(cursor)
        self.centerCursor()
        self._marked_line = line - 1
        self._refresh_selections()
        self.setFocus()
        return True

    def _clear_mark(self) -> None:
        if self._marked_line is not None:
            self._marked_line = None
            self._refresh_selections()

    def _refresh_selections(self) -> None:
        palette = self.palette()
        selections = []
        current = QTextEdit.ExtraSelection()
        current.format.setBackground(palette.color(QPalette.ColorRole.AlternateBase))
        current.format.setProperty(QTextFormat.Property.FullWidthSelection, True)
        current.cursor = self.textCursor()
        current.cursor.clearSelection()
        selections.append(current)
        if self._marked_line is not None:
            block = self.document().findBlockByNumber(self._marked_line)
            if block.isValid():
                marked = QTextEdit.ExtraSelection()
                marked.format.setBackground(QColor(229, 164, 90, 90))  # the activity amber
                marked.format.setProperty(QTextFormat.Property.FullWidthSelection, True)
                marked.cursor = QTextCursor(block)
                selections.append(marked)
        self.setExtraSelections(selections)

    # -- keys ----------------------------------------------------------------
    def keyPressEvent(self, event: QKeyEvent) -> None:  # noqa: N802 — Qt
        if self.isReadOnly():
            super().keyPressEvent(event)
            return
        key = event.key()
        mods = event.modifiers()
        if key == Qt.Key.Key_Backtab or (
            key == Qt.Key.Key_Tab and mods & Qt.KeyboardModifier.ShiftModifier
        ):
            self._dedent_selection()
            return
        if key == Qt.Key.Key_Tab and not (mods & ~Qt.KeyboardModifier.KeypadModifier):
            if self.textCursor().hasSelection():
                self._indent_selection()
            else:
                self.textCursor().insertText(INDENT)
            return
        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and not (
            mods & ~Qt.KeyboardModifier.KeypadModifier
        ):
            self._newline_with_indent()
            return
        super().keyPressEvent(event)

    def _selected_blocks(self) -> list:
        cursor = self.textCursor()
        doc = self.document()
        first = doc.findBlock(cursor.selectionStart())
        last = doc.findBlock(cursor.selectionEnd())
        if cursor.hasSelection() and cursor.selectionEnd() == last.position() and last != first:
            last = last.previous()  # a selection ending at a line start excludes that line
        blocks = []
        block = first
        while block.isValid():
            blocks.append(block)
            if block == last:
                break
            block = block.next()
        return blocks

    def _indent_selection(self) -> None:
        cursor = self.textCursor()
        cursor.beginEditBlock()
        for block in self._selected_blocks():
            edit = QTextCursor(block)
            edit.insertText(INDENT)
        cursor.endEditBlock()

    def _dedent_selection(self) -> None:
        cursor = self.textCursor()
        cursor.beginEditBlock()
        for block in self._selected_blocks():
            text = block.text()
            remove = len(text) - len(text.lstrip(" "))
            remove = min(remove, len(INDENT))
            if remove:
                edit = QTextCursor(block)
                edit.movePosition(
                    QTextCursor.MoveOperation.Right, QTextCursor.MoveMode.KeepAnchor, remove
                )
                edit.removeSelectedText()
        cursor.endEditBlock()

    def _newline_with_indent(self) -> None:
        cursor = self.textCursor()
        line = cursor.block().text()[: cursor.positionInBlock()]
        indent = line[: len(line) - len(line.lstrip(" \t"))]
        stripped = line.rstrip()
        if stripped.endswith(":") and not stripped.lstrip().startswith("#"):
            indent += INDENT
        elif _DEDENT_AFTER.match(line):
            indent = indent[: max(0, len(indent) - len(INDENT))]
        cursor.insertText("\n" + indent)
        self.ensureCursorVisible()

    def changeEvent(self, event) -> None:  # noqa: N802 — Qt
        super().changeEvent(event)
        if event.type() == event.Type.PaletteChange:
            self.highlighter.set_dark(_is_dark(self.palette()))
            self._refresh_selections()


__all__ = ["INDENT", "CodeEditor", "PythonHighlighter"]
