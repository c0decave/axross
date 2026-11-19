"""Large files and very long lines do not freeze the editor.

Review: a 12 MB source file took 17 s to open - the highlighter painted
every line three times (Qt's own pass on setPlainText, the relex after
it, and once more for set_language after the text), although above
MAX_HIGHLIGHT_CHARS nothing is coloured. A 6 MB one-line JSON file held
the window 27 s after it opened and every keypress 5 s: a line that long,
not wrapped, is laid out whole again and again.

Now the highlighter is detached from a text above the cap (and from one
without a language), a tab sets its language before its text, and a file
with a very long line opens wrapped - read-only, with a note and an Edit
Anyway button, when the line is long enough to make typing slow.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QMessageBox, QPlainTextEdit  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _python(lines: int) -> str:
    return "".join(f"def f{i}(x):\n    return x + {i}  # comment\n" for i in range(lines // 2))


def _count_highlights(act) -> int:
    from ui.code_editor import PygmentsHighlighter

    calls = []
    original = PygmentsHighlighter.highlightBlock

    def counting(self, text):
        calls.append(1)
        return original(self, text)

    with mock.patch.object(PygmentsHighlighter, "highlightBlock", counting):
        act()
        for _ in range(5):
            APP.processEvents()
    return len(calls)


def _wait(cond, timeout: float = 60.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.005)
    return cond()


def test_perf_a_text_above_the_cap_is_never_painted(monkeypatch):
    from ui import code_editor as CE

    monkeypatch.setattr(CE, "MAX_HIGHLIGHT_CHARS", 5_000)
    editor = CE.CodeEditor()
    text = _python(2_000)
    assert len(text) > CE.MAX_HIGHLIGHT_CHARS

    editor.set_language("Python")

    def load():
        editor.setPlainText(text)
        editor.highlighter.relex()

    assert _count_highlights(load) == 0
    assert editor.highlighter.document() is None
    assert not editor.highlighter.lexing


def test_happy_a_text_back_under_the_cap_is_coloured_again(monkeypatch):
    from ui import code_editor as CE

    monkeypatch.setattr(CE, "MAX_HIGHLIGHT_CHARS", 5_000)
    editor = CE.CodeEditor()
    editor.set_language("Python")
    editor.setPlainText(_python(2_000))
    editor.setPlainText("def f():\n    return 1\n")
    assert editor.highlighter.document() is editor.document()
    formats = editor.document().firstBlock().layout().formats()
    assert any(r.start == 0 and r.length == 3 for r in formats)


def test_perf_a_tab_paints_its_text_at_most_twice(tmp_path):
    from core.text_document import TextDocument
    from ui.editor_window import EditorTab

    path = tmp_path / "big.py"
    text = _python(2_000)
    path.write_text(text)
    document = TextDocument(LocalFS(), str(path))
    loaded = document.load()
    tabs = []
    calls = _count_highlights(
        lambda: tabs.append(EditorTab(LocalFS(), str(path), loaded, document, False)))
    blocks = tabs[0].editor.document().blockCount()
    assert tabs[0].editor.language == "Python"
    assert calls <= 2 * blocks, (calls, blocks)


@pytest.fixture
def window():
    from ui.editor_window import EditorWindow

    win = EditorWindow()
    win.show()
    yield win
    with mock.patch("ui.editor_window.QMessageBox.question",
                    return_value=QMessageBox.StandardButton.Discard):
        win.close()
    win.deleteLater()
    APP.processEvents()


def _one_line(chars: int) -> str:
    unit = '{"id": 1, "v": [1, 2, 3]}, '
    return "[" + unit * (chars // len(unit)) + "]\n"


def test_happy_a_long_line_opens_wrapped_and_writable(window, tmp_path):
    from ui import editor_window as EW

    path = tmp_path / "wide.txt"
    path.write_text(_one_line(EW.WRAP_LINE_CHARS + 1000))
    assert not window.wrap_action.isChecked()
    tab = window.open_file(LocalFS(), str(path))
    assert tab.editor.lineWrapMode() == QPlainTextEdit.LineWrapMode.WidgetWidth
    assert not tab.read_only and tab.long_line_note.isHidden()
    window._set_wrap(False)  # wrapping off for the others: this one stays wrapped
    assert tab.editor.lineWrapMode() == QPlainTextEdit.LineWrapMode.WidgetWidth


def test_edge_a_very_long_line_opens_read_only_with_edit_anyway(window, tmp_path):
    from ui import editor_window as EW

    path = tmp_path / "huge.txt"
    path.write_text("short\n" + _one_line(EW.READ_ONLY_LINE_CHARS + 1000))
    tab = window.open_file(LocalFS(), str(path))
    assert tab.read_only
    assert tab.editor.lineWrapMode() == QPlainTextEdit.LineWrapMode.WidgetWidth
    assert not tab.long_line_note.isHidden()
    assert "2" in tab.long_line_label.text()  # the line it is about
    tab.edit_anyway_button.click()
    assert not tab.read_only and not tab.editor.isReadOnly()
    assert tab.long_line_note.isHidden()


def test_happy_ordinary_lines_open_as_before(window, tmp_path):
    path = tmp_path / "plain.py"
    path.write_text(_python(40))
    tab = window.open_file(LocalFS(), str(path))
    assert tab.editor.lineWrapMode() == QPlainTextEdit.LineWrapMode.NoWrap
    assert not tab.read_only and tab.long_line_note.isHidden()
    assert _wait(lambda: not tab.editor.highlighter.lexing)


@pytest.mark.parametrize("ending", ["\r", "\r\n", "\u2029"])
def test_edge_short_lines_with_other_line_ends_are_not_one_long_line(ending):
    """A classic Mac file (CR only, and a text of U+2029 paragraph
    separators) is many short lines to the editor - each of those ends a
    block - yet the long-line check split at LF only: 2 MB of 60-character
    CR lines opened read-only as "Line 1 is 2,000,000 characters long"."""
    from ui import editor_window as EW

    text = ("x" * 59 + ending) * (EW.READ_ONLY_LINE_CHARS // 60 + 100)
    assert EW._longest_line(text) == (59, 1)


def test_edge_the_long_line_is_found_among_cr_lines():
    from ui import editor_window as EW

    text = "a\rb\r" + "y" * (EW.WRAP_LINE_CHARS + 5) + "\rc"
    assert EW._longest_line(text) == (EW.WRAP_LINE_CHARS + 5, 3)
