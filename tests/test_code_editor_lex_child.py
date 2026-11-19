"""The editor's Pygments lexing runs in a child process (core.lex_worker).

Pygments lexes with Python regular expressions, and ``re`` holds the GIL for
the whole of one match: a file that drives a lexer's pattern into
catastrophic backtracking froze the whole window - also when the lexing ran
on a worker thread - for as long as the match took (a dozen characters more
doubles it). Now a child lexes and sends the tokens; the window stays live,
the child is killed past its bound and the text stays plain. A hostile file
is played by a lexer patched to run such a match, in the child and here.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QTimer  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import lex_worker as LW  # noqa: E402

APP = QApplication.instance() or QApplication([])

# A Python lexer whose first token runs a catastrophic match (~10 s here).
_HOSTILE = r'''
import re as _re
from pygments.lexers import python as _python
_real = _python.PythonLexer.get_tokens_unprocessed
def _slow(self, text, *args):
    if "HOSTILE" in text:
        _re.match(r"(a+)+$", "a" * 27 + "b")
    return _real(self, text, *args)
_python.PythonLexer.get_tokens_unprocessed = _slow
'''


@pytest.fixture(autouse=True)
def _fresh_pool():
    LW.close_pool()
    yield
    LW.close_pool()


@pytest.fixture
def hostile(monkeypatch, tmp_path):
    """A Python lexer that backtracks without end on a text with HOSTILE -
    in the lexing child, and in this process (where it would freeze)."""
    script = tmp_path / "hostile_lexer.py"
    script.write_text(_HOSTILE + LW._CHILD_SOURCE)
    real = LW.worker_argv

    def argv(*args, **kwargs):
        return [sys.executable, "-I", str(script), *real(*args, **kwargs)[-4:]]

    monkeypatch.setattr(LW, "worker_argv", argv)
    from pygments.lexers import python as py

    # recorded, so the teardown puts the real one back after the exec below
    monkeypatch.setattr(py.PythonLexer, "get_tokens_unprocessed",
                        py.PythonLexer.get_tokens_unprocessed)
    exec(compile(_HOSTILE, "<hostile>", "exec"), {})


def _editor(text: str, language: str = "Python"):
    from ui.code_editor import CodeEditor

    editor = CodeEditor()
    editor.set_language(language)
    editor.setPlainText(text)
    return editor


def _formats(editor, block: int = 0):
    return editor.document().findBlockByNumber(block).layout().formats()


def _wait(cond, timeout: float = 60.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return cond()


# -- happy -------------------------------------------------------------------------


def test_happy_a_small_file_is_coloured_at_once_by_the_child(monkeypatch):
    from pygments.lexers import python as py

    def never(*_a, **_k):
        raise AssertionError("lexed inside axross")

    monkeypatch.setattr(py.PythonLexer, "get_tokens_unprocessed", never)
    editor = _editor("import os\ndef f():\n    return 1\n")
    try:
        assert not editor.highlighter.lexing
        assert _formats(editor, 0) and _formats(editor, 1)
    finally:
        editor.deleteLater()


def test_happy_the_child_sends_tokens_as_pygments_names_them():
    from pygments.token import Keyword, Name

    tokens = LW.lex("Python", "def f(): pass\n", "default")
    kinds = {ttype for _index, ttype, _length in tokens}
    assert Keyword in kinds and Name.Function in kinds
    index, _ttype, length = next(t for t in tokens if t[1] == Name.Function)
    assert (index, length) == (4, 1)


# -- sad -------------------------------------------------------------------------


def test_sad_a_catastrophic_lexer_regex_does_not_freeze_the_window(hostile, monkeypatch):
    monkeypatch.setattr(LW, "LEX_SECONDS", 3.0)
    ticks: list[float] = []
    timer = QTimer()
    timer.setInterval(50)
    timer.timeout.connect(lambda: ticks.append(time.monotonic()))
    timer.start()
    started = time.monotonic()
    editor = _editor("# HOSTILE\nimport os\n" + "x = 1\n" * 50)
    try:
        opened = time.monotonic() - started
        # The window waited at most the short wait for colours of a small file.
        assert opened < 3.0, opened
        assert _wait(lambda: not editor.highlighter.lexing, timeout=30)
        # it kept painting meanwhile: no gap of a second between two ticks
        gaps = [b - a for a, b in zip(ticks, ticks[1:])]
        assert ticks and max(gaps, default=0) < 1.0, max(gaps, default=0)
        # given up: the text stays plain, no child is left spinning
        assert not _formats(editor, 1)
        assert LW.idle_pids() == []
    finally:
        timer.stop()
        editor.deleteLater()


def test_sad_after_a_given_up_text_an_edit_does_not_start_it_again(hostile, monkeypatch):
    monkeypatch.setattr(LW, "LEX_SECONDS", 2.0)
    editor = _editor("# HOSTILE\n" + "y = 2\n" * 10)
    try:
        assert _wait(lambda: not editor.highlighter.lexing, timeout=30)
        assert editor.highlighter.gave_up
        generation = editor.highlighter.generation
        editor.highlighter.relex()
        assert not editor.highlighter.lexing and editor.highlighter.generation >= generation
        # another language (or another file) is tried again
        editor.set_language("Bash")
        assert not editor.highlighter.gave_up
    finally:
        editor.deleteLater()


def test_sad_a_crashing_child_leaves_the_text_plain_and_axross_running(monkeypatch, tmp_path):
    script = tmp_path / "crash.py"
    script.write_text("import os, signal\nos.kill(os.getpid(), signal.SIGSEGV)\n")
    real = LW.worker_argv
    monkeypatch.setattr(LW, "worker_argv",
                        lambda *a, **k: [sys.executable, "-I", str(script), *real(*a, **k)[-4:]])
    editor = _editor("import os\n")
    try:
        assert _wait(lambda: not editor.highlighter.lexing, timeout=30)
        assert not _formats(editor, 0)
    finally:
        editor.deleteLater()


# -- edge ------------------------------------------------------------------------


def test_edge_the_child_is_started_isolated_and_bounded(monkeypatch):
    argv = LW.worker_argv()
    assert argv[0] == sys.executable and argv[1:3] == ["-I", "-c"]
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert LW.worker_argv() == [sys.executable, "--lex-worker", *argv[-4:]]
    main_source = (Path(__file__).resolve().parent.parent / "main.py").read_text()
    assert '["--lex-worker"]' in main_source and "core.lex_worker import _child_main" in main_source


def test_edge_a_replaced_text_ends_the_lexing_of_the_old_one(hostile, monkeypatch):
    """A text replaced while its lexer runs: that child is ended, not
    waited for, and the new text is coloured."""
    editor = _editor("# HOSTILE\n" + "z = 3\n" * 20)
    try:
        editor.setPlainText("import sys\n")
        assert _wait(lambda: not editor.highlighter.lexing and bool(_formats(editor, 0)),
                     timeout=20)
    finally:
        editor.deleteLater()


def test_edge_a_typing_pause_does_not_wait_for_the_child(monkeypatch):
    """After a pause in typing the colours shown stay until the new ones
    come: the window does not wait for the child (one started anew after a
    long pause took up to a second)."""
    editor = _editor("import os\n")
    try:
        assert _formats(editor, 0)
        calls = []
        real = LW.lex

        def slow(*args, **kwargs):
            calls.append(time.monotonic())
            time.sleep(0.8)
            return real(*args, **kwargs)

        monkeypatch.setattr(LW, "lex", slow)
        editor.moveCursor(editor.textCursor().MoveOperation.End)
        editor.insertPlainText("x = 1\n")
        started = time.monotonic()
        editor.highlighter._relex_after_typing()
        assert time.monotonic() - started < 0.4
        assert _wait(lambda: not editor.highlighter.lexing, timeout=20)
        assert calls and _formats(editor, 0)
    finally:
        editor.deleteLater()
