"""The editor's text widget: line numbers, the current line, Pygments
highlighting, zoom and auto-indent on Enter, on QPlainTextEdit (QScintilla
is GPL; axross is Apache-2.0)."""

from __future__ import annotations

import logging
import re

from PyQt6.QtCore import QRect, QSize, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import (
    QColor,
    QFont,
    QPainter,
    QSyntaxHighlighter,
    QTextCharFormat,
    QTextCursor,
    QTextFormat,
)
from PyQt6.QtWidgets import QPlainTextEdit, QTextEdit, QWidget

log = logging.getLogger(__name__)

TEXT_ONLY = "Text only"
#: Above this many characters the document is not highlighted (lexing the
#: whole text on every pause would make typing lag).
MAX_HIGHLIGHT_CHARS = 2_000_000
#: Up to this many characters the text is lexed at once (a few ms); a larger
#: one on a worker thread, so typing never waits for Pygments.
SYNC_LEX_CHARS = 20_000
_SHEBANGS = {"bash": "Bash", "sh": "Bash", "zsh": "Bash", "python": "Python", "python3": "Python",
             "perl": "Perl", "ruby": "Ruby", "node": "JavaScript", "php": "PHP", "lua": "Lua"}


def language_for(name: str, text: str) -> str:
    """The Pygments language for a file *name* and its *text*: by the name,
    then by a "#!" line, else plain text."""
    from pygments.lexers import get_lexer_for_filename
    from pygments.util import ClassNotFound

    try:
        return get_lexer_for_filename(name).name
    except ClassNotFound:
        pass
    if text.startswith("#!"):
        return _SHEBANGS.get(_shebang_interpreter(text), TEXT_ONLY)
    return TEXT_ONLY


def _shebang_interpreter(text: str) -> str:
    """The interpreter's name in a "#!" line: "#! /bin/sh" (a space after
    "#!" is allowed) and "env" with options or variables before the name
    ("env -S python3 -u", "env LC_ALL=C bash") included. "" for none."""
    words = text[2:].split("\n", 1)[0].split()
    if words and words[0].rsplit("/", 1)[-1] == "env":
        words = [w for w in words[1:] if not w.startswith("-") and "=" not in w]
    return words[0].rsplit("/", 1)[-1] if words else ""


#: Languages where a line ending with ":" opens a block, and its indent step.
_COLON_BLOCKS = {"Python": "    ", "Python 2.x": "    ", "Cython": "    ", "YAML": "  "}
#: Languages where a line ending with "{" opens a block.
_BRACE_BLOCKS = frozenset({
    "C", "C++", "C#", "Go", "Rust", "Java", "Kotlin", "Scala", "Swift", "JavaScript", "TypeScript",
    "JSON", "CSS", "SCSS", "LessCss", "PHP", "Perl", "Bash", "PowerShell", "Lua", "Dart", "Groovy",
    "Nginx configuration file", "Objective-C",
})


def auto_indent(before: str, language: str) -> str:
    """The indentation Enter gives the new line, from the text *before* the
    cursor on the current line: its leading whitespace, plus one step after
    a line that ends with ":" (Python, YAML) or "{" (brace languages). The
    step is a tab when the line is indented with tabs, else the language's
    (two spaces for YAML, four otherwise). Nothing else is guessed."""
    indent = before[: len(before) - len(before.lstrip(" \t"))]
    code = before.strip()
    if not code:
        return indent
    opens = (code.endswith(":") and language in _COLON_BLOCKS and not code.startswith("#")) or (
        code.endswith("{") and language in _BRACE_BLOCKS)
    if not opens:
        return indent
    step = "\t" if "\t" in indent else _COLON_BLOCKS.get(language, "    ")
    return indent + step


def _lexer(language: str):
    from pygments.lexers import find_lexer_class

    cls = find_lexer_class(language)
    return cls() if cls is not None and language != TEXT_ONLY else None


class _Stale(Exception):
    """A newer text is being lexed: this result would be dropped anyway."""


#: Tokens lexed between two looks at whether the text is still current.
_STALE_CHECK_TOKENS = 2048


#: A character outside the BMP: one Python index, two QTextCursor positions.
_ASTRAL = re.compile("[\U00010000-\U0010ffff]")


def _token_ranges(
    lexer, text: str, starts: list[int], stale=None
) -> dict[int, list[tuple[int, int, object]]]:
    """Per block number: (start in block, length, token type) of every token
    piece, in QTextCursor positions like *starts*. Pure - runs on a worker
    thread for a large text. *stale* (no arguments) is asked now and then;
    True stops the work with _Stale."""
    import bisect

    # The lexer counts Python characters, Qt UTF-16 code units: every emoji
    # before a token moves it one position further in the document.
    astral = [m.start() for m in _ASTRAL.finditer(text)]
    length = len(text) + len(astral)
    ranges: dict[int, list[tuple[int, int, object]]] = {}
    for count, (index, ttype, value) in enumerate(lexer.get_tokens_unprocessed(text)):
        if stale is not None and count % _STALE_CHECK_TOKENS == 0 and stale():
            raise _Stale
        end = index + len(value)
        if astral:
            index += bisect.bisect_left(astral, index)
            end += bisect.bisect_left(astral, end)
        while index < end:
            number = bisect.bisect_right(starts, index) - 1
            block_start = starts[number]
            # The block's last character is the break before the next block.
            block_end = starts[number + 1] - 1 if number + 1 < len(starts) else length
            stop = min(end, block_end)
            if stop > index:
                ranges.setdefault(number, []).append((index - block_start, stop - index, ttype))
            index = block_end + 1 if end > block_end else end
    return ranges


class PygmentsHighlighter(QSyntaxHighlighter):
    """Lexes the whole document (after a pause in typing, at once for a
    new text) and paints each block from the token ranges that fall in it,
    so strings and comments that span lines come out right.

    A text above SYNC_LEX_CHARS is lexed on a worker thread; its result is
    applied only if no newer lexing started meanwhile (``generation``)."""

    _lexed = pyqtSignal(int, object)

    def __init__(self, document, dark: bool) -> None:
        super().__init__(document)
        self._lexer = None
        self._ranges: dict[int, list[tuple[int, int, object]]] = {}
        self._formats: dict = {}
        self.generation = 0
        self.applied_generation = 0
        self.set_dark(dark)
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(200)
        self._timer.timeout.connect(self.relex)
        self._lexed.connect(self._apply)
        document.contentsChange.connect(self._changed)

    @property
    def lexing(self) -> bool:
        """A worker is lexing a text whose result is still awaited."""
        return self.applied_generation != self.generation

    def set_dark(self, dark: bool) -> None:
        from pygments.styles import get_style_by_name

        self._style = get_style_by_name("monokai" if dark else "default")
        self._formats.clear()

    def set_language(self, language: str) -> None:
        self._lexer = _lexer(language)
        self.relex()

    def _format(self, ttype) -> QTextCharFormat:
        fmt = self._formats.get(ttype)
        if fmt is None:
            fmt = QTextCharFormat()
            style = self._style.style_for_token(ttype)
            if style.get("color"):
                fmt.setForeground(QColor("#" + style["color"]))
            if style.get("bold"):
                fmt.setFontWeight(QFont.Weight.Bold)
            if style.get("italic"):
                fmt.setFontItalic(True)
            self._formats[ttype] = fmt
        return fmt

    def _changed(self, _position: int, removed: int, added: int) -> None:
        # A new text (load, paste of a page) is lexed at once; typing waits.
        if removed + added > 1000 or self.document().characterCount() <= added + 1:
            self.relex()
        else:
            self._timer.start()

    def relex(self) -> None:
        """Lex the whole text again and repaint every block - at once for a
        small text, on a worker thread for a large one."""
        import threading

        self._timer.stop()
        self.generation += 1
        generation = self.generation
        document = self.document()
        text = document.toPlainText()
        lexer = self._lexer
        if lexer is None or len(text) > MAX_HIGHLIGHT_CHARS:
            self._apply(generation, {})
            return
        starts = []
        block = document.begin()
        while block.isValid():
            starts.append(block.position())
            block = block.next()
        if len(text) <= SYNC_LEX_CHARS:
            self._apply(generation, _token_ranges(lexer, text, starts))
            return

        def stale() -> bool:
            # A newer text replaced this one: stop instead of lexing to the
            # end for nothing - each typing pause in a large file starts a
            # lexer, and the stale ones held the interpreter from the GUI.
            return self.generation != generation

        def work() -> None:
            try:
                ranges = _token_ranges(lexer, text, starts, stale)
            except _Stale:
                return
            except Exception:  # noqa: BLE001 - a lexer bug leaves the text plain
                ranges = {}
            try:
                self._lexed.emit(generation, ranges)
            except RuntimeError:  # the editor is gone
                pass

        threading.Thread(target=work, name="axross-lex", daemon=True).start()

    def _apply(self, generation: int, ranges) -> None:
        if generation != self.generation:
            return  # a newer text is being lexed
        self.applied_generation = generation
        self._ranges = {
            number: [(start, length, fmt) for start, length, ttype in pieces
                     if not (fmt := self._format(ttype)).isEmpty()]
            for number, pieces in ranges.items()
        }
        self.rehighlight()

    def highlightBlock(self, _text: str) -> None:  # noqa: N802 - Qt
        for start, length, fmt in self._ranges.get(self.currentBlock().blockNumber(), ()):
            self.setFormat(start, length, fmt)


class _LineNumbers(QWidget):
    def __init__(self, editor: "CodeEditor") -> None:
        super().__init__(editor)
        self.editor = editor

    def sizeHint(self) -> QSize:  # noqa: N802 - Qt
        return QSize(self.editor.line_number_width(), 0)

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt
        self.editor.paint_line_numbers(event)


class CodeEditor(QPlainTextEdit):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        font = QFont("Monospace", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.setFont(font)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setTabStopDistance(self.fontMetrics().horizontalAdvance(" ") * 4)
        self.language = TEXT_ONLY
        self._numbers = _LineNumbers(self)
        dark = self.palette().base().color().lightness() < 128
        self.highlighter = PygmentsHighlighter(self.document(), dark)
        self.blockCountChanged.connect(lambda _n: self._update_margin())
        self.updateRequest.connect(self._scroll_numbers)
        self.cursorPositionChanged.connect(self._mark_current_line)
        self._update_margin()
        self._mark_current_line()

    # -- typing ------------------------------------------------------------------------------

    def keyPressEvent(self, event) -> None:  # noqa: N802 - Qt
        """Enter (main or keypad, no other modifier) starts the new line at
        auto_indent()'s column - one insert, so one undo step. Shift+Enter
        and everything else stay Qt's."""
        modifiers = event.modifiers() & ~Qt.KeyboardModifier.KeypadModifier
        if (event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter)
                and modifiers == Qt.KeyboardModifier.NoModifier and not self.isReadOnly()):
            cursor = self.textCursor()
            start = cursor.selectionStart()
            # Through a cursor, not block.text()[:n]: Qt counts UTF-16 units,
            # an emoji before the cursor would cut the slice one short.
            head = QTextCursor(self.document().findBlock(start))
            head.setPosition(start, QTextCursor.MoveMode.KeepAnchor)
            before = head.selectedText()
            cursor.insertText("\n" + auto_indent(before, self.language))
            self.setTextCursor(cursor)
            self.ensureCursorVisible()
            return
        super().keyPressEvent(event)

    # -- language and zoom -----------------------------------------------------------------

    def set_language(self, language: str) -> None:
        self.language = language if _lexer(language) is not None else TEXT_ONLY
        self.highlighter.set_language(self.language)

    def zoom(self, steps: int) -> None:
        font = self.font()
        font.setPointSizeF(max(6.0, font.pointSizeF() + steps))
        self.setFont(font)
        self.setTabStopDistance(self.fontMetrics().horizontalAdvance(" ") * 4)
        self._update_margin()

    # -- line numbers ----------------------------------------------------------------------

    def line_number_width(self) -> int:
        digits = len(str(max(1, self.blockCount())))
        return 10 + self.fontMetrics().horizontalAdvance("9") * max(3, digits)

    def _update_margin(self) -> None:
        self.setViewportMargins(self.line_number_width(), 0, 0, 0)

    def _scroll_numbers(self, rect: QRect, dy: int) -> None:
        if dy:
            self._numbers.scroll(0, dy)
        else:
            self._numbers.update(0, rect.y(), self._numbers.width(), rect.height())

    def resizeEvent(self, event) -> None:  # noqa: N802 - Qt
        super().resizeEvent(event)
        area = self.contentsRect()
        self._numbers.setGeometry(QRect(area.left(), area.top(), self.line_number_width(), area.height()))

    def paint_line_numbers(self, event) -> None:
        painter = QPainter(self._numbers)
        palette = self.palette()
        painter.fillRect(event.rect(), palette.window())
        painter.setPen(palette.placeholderText().color())
        block = self.firstVisibleBlock()
        top = round(self.blockBoundingGeometry(block).translated(self.contentOffset()).top())
        bottom = top + round(self.blockBoundingRect(block).height())
        width = self._numbers.width() - 5
        height = self.fontMetrics().height()
        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                painter.drawText(0, top, width, height, Qt.AlignmentFlag.AlignRight,
                                 str(block.blockNumber() + 1))
            block = block.next()
            top = bottom
            bottom = top + round(self.blockBoundingRect(block).height())

    def _mark_current_line(self) -> None:
        selection = QTextEdit.ExtraSelection()
        colour = self.palette().highlight().color()
        colour.setAlpha(40)
        selection.format.setBackground(colour)
        selection.format.setProperty(QTextFormat.Property.FullWidthSelection, True)
        selection.cursor = self.textCursor()
        selection.cursor.clearSelection()
        self.setExtraSelections([selection])
