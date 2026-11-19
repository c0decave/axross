"""The editor's text widget: line numbers, the current line, Pygments
highlighting, zoom and auto-indent on Enter, on QPlainTextEdit (QScintilla
is GPL; axross is Apache-2.0)."""

from __future__ import annotations

import logging
import re
import threading

from PyQt6.QtCore import QRect, QSize, Qt, QTimer
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

from core.lex_worker import style_of
from core.thread_relay import GuiCall

log = logging.getLogger(__name__)

TEXT_ONLY = "Text only"
#: Above this many characters the document is not highlighted (lexing the
#: whole text on every pause would make typing lag).
MAX_HIGHLIGHT_CHARS = 2_000_000
#: Up to this many characters the GUI waits for the lexing (a few ms), at
#: most SYNC_WAIT_SECONDS; a larger text is coloured when its tokens come.
SYNC_LEX_CHARS = 20_000
SYNC_WAIT_SECONDS = 1.0
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


def _paints(style):
    """Token type -> whether *style* gives it a colour, bold or italic: a
    token without any of them would get an empty format, which paints
    nothing (PygmentsHighlighter._format). Pure; one per lexing."""
    known: dict = {}

    def paints(ttype) -> bool:
        hit = known.get(ttype)
        if hit is None:
            entry = style_of(style, ttype)  # (a type the style leaves out: its parent's)
            hit = known[ttype] = bool(entry.get("color") or entry.get("bold") or entry.get("italic"))
        return hit

    return paints


def _token_ranges(
    lexer, text: str, starts: list[int], stale=None, paints=None
) -> dict[int, list[tuple[int, int, object]]]:
    """Per block number: (start in block, length, token type) of every token
    *lexer* finds in *text* (in this process: tests and tools; the editor
    lexes in a child, :func:`_ranges_of`)."""
    tokens = ((index, ttype, len(value))
              for index, ttype, value in lexer.get_tokens_unprocessed(text))
    return _ranges_of(tokens, text, starts, stale, paints)


def _ranges_of(
    tokens, text: str, starts: list[int], stale=None, paints=None
) -> dict[int, list[tuple[int, int, object]]]:
    """Per block number: (start in block, length, token type) of every piece
    of the *tokens* ((start, token type, length) in Python characters of
    *text*), in QTextCursor positions like *starts*. Pure - runs on a worker
    thread. *stale* (no arguments) is asked now and then; True stops the
    work with _Stale. *paints* (a token type) leaves out the tokens it says
    False for."""
    import bisect

    # The lexer counts Python characters, Qt UTF-16 code units: every emoji
    # before a token moves it one position further in the document.
    astral = [m.start() for m in _ASTRAL.finditer(text)]
    length = len(text) + len(astral)
    ranges: dict[int, list[tuple[int, int, object]]] = {}
    for count, (index, ttype, size) in enumerate(tokens):
        if stale is not None and count % _STALE_CHECK_TOKENS == 0 and stale():
            raise _Stale
        if paints is not None and not paints(ttype):
            continue
        end = index + size
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


def _changed_blocks(old: dict, new: dict, origin: list[int]) -> list[int]:
    """Numbers of the blocks whose paint under *new* differs from the paint
    they show. ``origin[n]`` is the number block n had when *old* was
    painted onto every block, -1 for a block Qt has painted since (an edited
    one: what it shows is unknown, so it is always repainted)."""
    return [n for n, was in enumerate(origin) if was < 0 or old.get(was) != new.get(n)]


class PygmentsHighlighter(QSyntaxHighlighter):
    """Lexes the whole document (after a pause in typing, at once for a
    new text) and paints each block from the token ranges that fall in it,
    so strings and comments that span lines come out right.

    The lexing runs in a child process (core.lex_worker: a lexer's regular
    expression stuck in backtracking held the GIL and froze the window),
    waited for on a worker thread; the GUI waits for a text up to
    SYNC_LEX_CHARS at most SYNC_WAIT_SECONDS, so a small file is coloured
    as it opens. A result is applied only if no newer lexing started
    meanwhile (``generation``); a text the child could not lex in time
    stays plain (``gave_up``) until another language or text comes.
    Only the blocks whose paint changed are repainted: ``_origin`` follows
    every edit since the last paint, so a block that moved down a line is
    compared with the ranges it was painted with, not with its new
    neighbour's."""

    def __init__(self, document, dark: bool) -> None:
        super().__init__(document)
        #: The editor's document, also while the highlighter is detached
        #: from it (detach()).
        self._doc = document
        #: A new text is going in (CodeEditor.setPlainText): its steps are
        #: not lexed one by one.
        self.loading = False
        #: The Pygments language name lexed with, None for plain text.
        self._lexer = None
        #: The child could not lex this text in time: plain until another
        #: language or a new text (CodeEditor.setPlainText).
        self.gave_up = False
        self._ranges: dict[int, list[tuple[int, int, object]]] = {}
        self._formats: dict = {}
        #: Per block: its number when _ranges were painted, -1 = edited since.
        self._origin: list[int] = [-1] * document.blockCount()
        #: Edits so far; a result lexed from an older text is painted whole.
        self._edits = 0
        self.generation = 0
        self.applied_generation = 0
        self.set_dark(dark)
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(200)
        self._timer.timeout.connect(self._relex_after_typing)
        # The lexer thread hands its result over through this, not through a
        # signal of the highlighter: closing the editor tab deletes the
        # highlighter, maybe while the thread reports (core/thread_relay.py).
        self._lexed = GuiCall(self._apply)
        document.contentsChange.connect(self._changed)

    def detach(self) -> None:
        """Stop painting (Qt clears the colours). The next lexing result
        attaches again; a text above MAX_HIGHLIGHT_CHARS or without a
        language stays detached."""
        if self.document() is not None:
            # Qt clears the colours in an edit block, which reports a
            # change of the document: not one to lex (it attached again).
            loading, self.loading = self.loading, True
            try:
                self.setDocument(None)
            finally:
                self.loading = loading

    @property
    def lexing(self) -> bool:
        """A worker is lexing a text whose result is still awaited."""
        return self.applied_generation != self.generation

    def set_dark(self, dark: bool) -> None:
        from pygments.styles import get_style_by_name

        self._style_name = "monokai" if dark else "default"
        self._style = get_style_by_name(self._style_name)
        self._formats.clear()
        self._origin = [-1] * len(self._origin)  # every block's colours change
        if self._lexer is not None:  # None while __init__ runs
            self.relex()

    def set_language(self, language: str) -> None:
        self._lexer = language if _lexer(language) is not None else None
        self.gave_up = False
        self._origin = [-1] * len(self._origin)
        self.relex()

    def _format(self, ttype) -> QTextCharFormat:
        fmt = self._formats.get(ttype)
        if fmt is None:
            fmt = QTextCharFormat()
            style = style_of(self._style, ttype)
            if style.get("color"):
                fmt.setForeground(QColor("#" + style["color"]))
            if style.get("bold"):
                fmt.setFontWeight(QFont.Weight.Bold)
            if style.get("italic"):
                fmt.setFontItalic(True)
            self._formats[ttype] = fmt
        return fmt

    def _changed(self, position: int, removed: int, added: int) -> None:
        self._edits += 1
        if self.loading:
            return  # CodeEditor.setPlainText lexes once it is in
        self._follow_edit(position, added)
        # A new text (load, paste of a page) is lexed at once; typing waits.
        if removed + added > 1000 or self._doc.characterCount() <= added + 1:
            self.relex()
        else:
            self._timer.start()

    def _follow_edit(self, position: int, added: int) -> None:
        """Mark the blocks the edit touched as -1 in _origin and shift the
        ones below with it: the edited region spans blocks first..last now
        and spanned that many minus the change of the block count before."""
        document = self._doc
        count = document.blockCount()
        first = document.findBlock(position)
        last = document.findBlock(position + added)
        last_number = last.blockNumber() if last.isValid() else count - 1
        span = last_number - first.blockNumber() + 1
        was = span - (count - len(self._origin))
        if not first.isValid() or span < 1 or was < 1:
            self._origin = [-1] * count
            return
        start = first.blockNumber()
        self._origin[start:start + was] = [-1] * span

    def _relex_after_typing(self) -> None:
        # The colours shown stay until the new ones come: no wait for the
        # child (one started anew after a long pause took up to a second).
        self.relex(wait=False)

    def relex(self, wait: bool = True) -> None:
        """Lex the whole text again and repaint the blocks whose colours
        changed - at once for a small text (*wait*: the GUI waits for it up
        to SYNC_WAIT_SECONDS), else when the child's tokens come."""
        self._timer.stop()
        self.generation += 1
        generation = self.generation
        document = self._doc
        language = self._lexer
        if (language is None or self.gave_up
                or document.characterCount() - 1 > MAX_HIGHLIGHT_CHARS):
            # Nothing to colour: detached, Qt paints no line at all - it
            # painted every line of a 12 MB file three times for nothing.
            self.detach()
            self._ranges = {}
            self._origin = list(range(document.blockCount()))
            self.applied_generation = generation
            return
        text = document.toPlainText()
        old, origin, edits = self._ranges, list(self._origin), self._edits
        if len(origin) != document.blockCount():  # an edit went unseen: paint all
            origin = [-1] * document.blockCount()
        starts = []
        block = document.begin()
        while block.isValid():
            starts.append(block.position())
            block = block.next()
        style = self._style_name

        def result(ranges):
            return ranges, _changed_blocks(old, ranges, origin), edits

        def stale() -> bool:
            # A newer text replaced this one: its child is ended instead of
            # lexing to the end for nothing - each typing pause in a large
            # file starts a lexing.
            return self.generation != generation

        lexed = self._lexed
        # The result goes to the GUI thread at once when it waits for it
        # (a small text), else through ``lexed``.
        handoff = threading.Lock()
        box: dict = {"late": len(text) > SYNC_LEX_CHARS or not wait}
        arrived = threading.Event()

        def work() -> None:
            from core import lex_worker

            try:
                tokens = lex_worker.lex(language, text, style, cancel=stale)
                ranges = _ranges_of(tokens, text, starts, stale)
            except (_Stale, lex_worker.LexCancelled):
                return
            except lex_worker.LexTooSlow as exc:
                log.warning("Highlighting left off: %s", exc)
                self.gave_up = True
                ranges = {}
            except Exception as exc:  # noqa: BLE001 - a lexer bug leaves the text plain
                log.debug("Highlighting failed: %s", exc)
                ranges = {}
            with handoff:
                if not box["late"]:
                    box["ranges"] = ranges
                    arrived.set()
                    return
            lexed(generation, result(ranges))

        threading.Thread(target=work, name="axross-lex", daemon=True).start()
        if box["late"]:
            return
        arrived.wait(SYNC_WAIT_SECONDS)
        with handoff:
            if "ranges" not in box:
                box["late"] = True  # it comes through ``lexed``
                return
        self._apply(generation, result(box["ranges"]))

    def _apply(self, generation: int, result) -> None:
        """Paint *result* (ranges, changed block numbers, edits when lexed):
        only the changed blocks, or every block when the text was edited
        after it was taken - its block numbers may be off by now."""
        if generation != self.generation:
            return  # a newer text is being lexed
        self.applied_generation = generation
        ranges, changed, edits = result
        self._ranges = ranges
        document = self._doc
        if self.document() is None:
            # Detached (a new text, or one back under the cap): attached
            # now, every line painted once with the ranges.
            self.setDocument(document)
            self.rehighlight()  # also drops Qt's own delayed pass
        elif edits != self._edits or len(changed) > document.blockCount() // 2:
            self.rehighlight()
        else:
            for number in changed:
                block = document.findBlockByNumber(number)
                if block.isValid():
                    self.rehighlightBlock(block)
        self._origin = list(range(document.blockCount()))

    def highlightBlock(self, _text: str) -> None:  # noqa: N802 - Qt
        for start, length, ttype in self._ranges.get(self.currentBlock().blockNumber(), ()):
            self.setFormat(start, length, self._format(ttype))


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
        # The lexing child (core.lex_worker) starts while the editor is built.
        from core import lex_worker

        lex_worker.warm()
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

    def setPlainText(self, text: str) -> None:  # noqa: N802 - Qt
        """A new text is painted once, when it is lexed: attached, Qt
        painted every line as the text went in, then again with the
        lexer's colours (and not at all is needed above the cap)."""
        highlighter = self.highlighter
        highlighter.detach()
        highlighter.gave_up = False  # another text: tried again
        highlighter.loading = True
        try:
            super().setPlainText(text)
        finally:
            highlighter.loading = False
        highlighter.relex()

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
