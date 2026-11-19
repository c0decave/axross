"""Lex a text with Pygments in a killable child process.

Pygments lexes with Python regular expressions, and ``re`` holds the GIL
for the whole of one match: a file that drives a lexer's pattern into
catastrophic backtracking (Pygments has had several such patterns) froze
the editor's window for as long as that one match took - also when the
lexing ran on a worker thread. So the editor's highlighter (ui.code_editor)
has a child lex the text and send the tokens back; the parent kills a child
past :data:`LEX_SECONDS`, or as soon as a newer text replaced the one it
lexes. Its memory is capped (RLIMIT_DATA), its CPU time bounded per
request, and it ends with its parent - core.image_worker's children, with
another command.

The child is ``python -I -c`` :data:`_CHILD_SOURCE` (a frozen build answers
``--lex-worker``, main.py). Answer: a header with the token types the text
has, then per token three unsigned 32-bit integers (start, length, the
type's index in the header's list). Tokens the style paints nothing for
(plain text) are left out.

Pure Python, no Qt.
"""

from __future__ import annotations

import logging
import os
import sys
from array import array

from core import image_worker as IW

log = logging.getLogger(__name__)

#: Seconds one text may take to be lexed, the child's start included (a
#: 1.8 MB Python file took 10 s on a busy machine; the editor colours at
#: most core.code_editor's MAX_HIGHLIGHT_CHARS).
LEX_SECONDS = 60.0
#: Data memory of the child: Pygments, the text and its tokens.
DATA_LIMIT = 2 * 1024**3
#: Idle children kept (one per editor that lexes at the same time is plenty).
POOL_SIZE = 2
TEXTS_PER_CHILD = 1000
POOL_IDLE_SECONDS = 300.0

_CHILD_SOURCE = r'''
import sys
if sys.argv[-4] not in sys.path:
    # a source checkout (an installed axross is on the path already: put
    # first, its folder - site-packages - would shadow the standard library)
    sys.path.insert(0, sys.argv[-4])
from core.lex_worker import _serve
_serve()
'''

LexError = IW.ImageWorkerError
LexTooSlow = IW.ImageTooSlow
LexCrashed = IW.ImageCrashed
LexCancelled = IW.ImageCancelled


def worker_argv(seconds: float | None = None) -> list[str]:
    """The command that starts a lexing child; a frozen build answers
    ``--lex-worker`` (main.py). The last four arguments as core.image_worker's."""
    seconds = LEX_SECONDS if seconds is None else seconds
    tail = [IW._project_root(), str(os.getpid()), str(IW.cpu_seconds_for(seconds)),
            str(DATA_LIMIT)]
    if getattr(sys, "frozen", False):
        return [sys.executable, "--lex-worker", *tail]
    return [sys.executable, "-I", "-c", _CHILD_SOURCE, *tail]


# -- the child -------------------------------------------------------------------

_lexers: dict = {}
_paints: dict = {}


def style_of(style, ttype) -> dict:
    """*style*'s entry for the token type *ttype* - its nearest ancestor's when the style does not
    list it (as Pygments' formatters look it up): style_for_token raised KeyError for a type a style
    leaves out - YamlLexer's Token.Literal.Scalar.Plain - and a YAML block was never coloured."""
    while ttype is not None:
        try:
            return style.style_for_token(ttype)
        except KeyError:
            ttype = ttype.parent
    return {}


def _paint_check(style_name: str):
    """Token type -> whether the style gives it a colour, bold or italic
    (ui.code_editor._paints, kept per style)."""
    known = _paints.get(style_name)
    if known is None:
        from pygments.styles import get_style_by_name

        style = get_style_by_name(style_name)
        known = _paints[style_name] = (style, {})
    style, seen = known

    def paints(ttype) -> bool:
        hit = seen.get(ttype)
        if hit is None:
            entry = style_of(style, ttype)
            hit = seen[ttype] = bool(entry.get("color") or entry.get("bold")
                                     or entry.get("italic"))
        return hit

    return paints


def _lex_request(request: dict) -> tuple[dict, bytes]:
    from pygments.lexers import find_lexer_class
    from pygments.util import ClassNotFound

    language = str(request.get("language", ""))
    lexer = _lexers.get(language)
    if lexer is None:
        cls = find_lexer_class(language)
        if cls is None:
            return {"error": "language"}, b""
        lexer = _lexers[language] = cls()
    try:
        paints = _paint_check(str(request.get("style") or "default"))
    except ClassNotFound:
        paints = _paint_check("default")
    text = str(request.get("text", ""))
    types: dict = {}
    out = array("I")
    try:
        for index, ttype, value in lexer.get_tokens_unprocessed(text):
            if not paints(ttype):
                continue
            number = types.get(ttype)
            if number is None:
                number = types[ttype] = len(types)
            out.extend((index, len(value), number))
    except MemoryError:
        raise
    except Exception as exc:  # noqa: BLE001 - a lexer's bug leaves the text plain
        return {"error": "lexer", "text": str(exc)[:500]}, b""
    names = [".".join(ttype) for ttype in types]
    return {"types": names, "count": len(out) // 3}, out.tobytes()


def _serve() -> None:
    def ready() -> None:
        import pygments.lexers  # noqa: F401 - loaded before the first text

    IW.serve(_lex_request, ready=ready)


def _child_main() -> int:
    """The frozen build's ``--lex-worker`` entry point."""
    _serve()
    return 0


# -- the parent ------------------------------------------------------------------


class LexChild(IW.ImageChild):
    """A lexing child (see core.image_worker.ImageChild)."""

    work_text = "highlighting the text"
    process_text = "the highlighting process"

    @staticmethod
    def _default_seconds() -> float:
        return LEX_SECONDS

    def _argv(self) -> list[str]:
        return worker_argv(self._seconds)


_POOL = IW.ChildPool(LexChild, lambda: POOL_SIZE, lambda: POOL_IDLE_SECONDS,
                     lambda: TEXTS_PER_CHILD, "lex-worker")


def lex(language: str, text: str, style: str = "default", cancel=None) -> list[tuple]:
    """The tokens of *text* in the Pygments *language* that *style* paints:
    ``(start, token type, length)`` in Python characters. Raises
    :class:`LexTooSlow` past :data:`LEX_SECONDS`, :class:`LexCancelled`
    when *cancel()* said so meanwhile, :class:`LexError` otherwise."""
    from pygments.token import string_to_tokentype

    def consume(head: dict, body) -> list[tuple]:
        if head.get("error") == "memory":
            raise LexError("not enough memory to highlight the text")
        if "error" in head:
            raise LexError(f"cannot highlight as {language!r}: {head.get('text') or head['error']}")
        try:
            names = [string_to_tokentype(str(n)) for n in head["types"]]
            count = int(head["count"])
        except (KeyError, TypeError, ValueError, AttributeError):
            raise LexError("the highlighting process answered nonsense") from None
        data = body.read_all() if hasattr(body, "read_all") else body
        numbers = array("I")
        if len(data) != count * 3 * numbers.itemsize:
            raise LexError("the highlighting process answered nonsense")
        numbers.frombytes(bytes(data))
        limit = len(text)
        tokens = []
        for i in range(0, len(numbers), 3):
            start, length, kind = numbers[i], numbers[i + 1], numbers[i + 2]
            if kind >= len(names) or start + length > limit:
                raise LexError("the highlighting process answered nonsense")
            tokens.append((start, names[kind], length))
        return tokens

    return _POOL.ask({"language": language, "text": text, "style": style}, consume, cancel)


def warm() -> None:
    """Start a lexing child now, without waiting for it (an editor opens)."""
    _POOL.warm()


def idle_pids() -> list[int]:
    """The process ids of the idle children (tests)."""
    return _POOL.idle_pids()


def close_pool() -> None:
    """End the idle children (tests)."""
    _POOL.close()


__all__ = [
    "LEX_SECONDS",
    "LexCancelled",
    "LexCrashed",
    "LexError",
    "LexTooSlow",
    "close_pool",
    "idle_pids",
    "lex",
    "warm",
    "worker_argv",
]
