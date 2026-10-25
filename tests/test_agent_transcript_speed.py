"""The Agent dock's transcript stays quick with a long conversation.

Measured 2026-10-25 on a kept tab of 850 transcript lines (offscreen,
scratch benchmark bench_gui.py): the tab was filled line by line with
QTextBrowser.append (79-97 ms per tab, 391-441 ms for a dock restoring four
such tabs), and a click on a Thinking block cleared the transcript and drew
every line again (128-173 ms per click). A tab is now filled with one
setHtml, and a click draws only the block it opens or closes. What the
transcript shows is the same document as before (compared as HTML).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtGui import QTextCursor  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QTextBrowser  # noqa: E402

import ui.agent_dock as AD  # noqa: E402
from core.agent_session import AgentSession, SessionStore  # noqa: E402
from tests.test_agent_loop import _no_proxy  # noqa: E402,F401
from tests.test_agent_tabs import env  # noqa: E402,F401

APP = QApplication.instance() or QApplication([])


class _CountingBrowser(QTextBrowser):
    """The transcript widget, counting how it is filled."""

    def __init__(self, *args) -> None:
        super().__init__(*args)
        self.appends = 0
        self.set_htmls = 0

    def append(self, text: str) -> None:  # noqa: D102 - counted pass-through
        self.appends += 1
        super().append(text)

    def setHtml(self, text: str) -> None:  # noqa: N802 - Qt name
        self.set_htmls += 1
        super().setHtml(text)


def _transcript(steps: int) -> list[dict]:
    """A conversation as a session keeps it: per step a task, a thinking
    block of several lines, a tool call and result, an answer - with markup
    characters that must stay text."""
    out = []
    for i in range(steps):
        out += [
            {"who": "You:", "text": f"task {i}: what is in <folder> & why?", "muted": False},
            {"who": "Thinking:", "text": f"step {i} first line\nsecond line of {i}\nthird <b>",
             "muted": True, "kind": "reasoning"},
            {"who": "→", "text": f'list_dir {{"path": "/srv/{i}"}}', "muted": True},
            {"who": "←", "text": "list_dir: ok", "muted": True},
            {"who": "Agent:", "text": f"answer {i}\n\nwith a blank line", "muted": False},
        ]
    return out


def _restored(env, monkeypatch, transcript, *, counting=False):
    """A dock that restores one kept tab holding *transcript*, shown."""
    if counting:
        monkeypatch.setattr(AD, "QTextBrowser", _CountingBrowser)
    env.fake({"content": "ok"})
    store = SessionStore(env.store_dir)
    store.save(AgentSession(title="long", folder=str(env.root),
                            transcript=[dict(e) for e in transcript]))
    dock = env.dock()
    dock.resize(700, 600)
    dock.show()
    APP.processEvents()
    return dock, dock.current_tab()


def _reference_html(tab) -> str:
    """The transcript as the dock drew it before: line by line, appended."""
    ref = QTextBrowser()
    ref.document().setDefaultFont(tab.transcript.document().defaultFont())
    for index in range(len(tab._entries)):
        ref.append(tab._entry_html(index))
    return ref.toHtml()


def _reasoning(tab) -> list[int]:
    return [i for i, e in enumerate(tab._entries) if e["kind"] == "reasoning"]


def _count_renders(monkeypatch, tab) -> list[int]:
    calls: list[int] = []
    original = tab._entry_html

    def counted(index: int) -> str:
        calls.append(index)
        return original(index)

    monkeypatch.setattr(tab, "_entry_html", counted)
    return calls


def _click_block(tab, index: int) -> None:
    """Click the Thinking label of the transcript line *index*, as a person would."""
    block = tab.transcript.document().findBlockByNumber(index)
    cursor = QTextCursor(block)
    cursor.setPosition(block.position() + 3)  # inside "▸ Thinking"
    tab.transcript.setTextCursor(cursor)
    tab.transcript.ensureCursorVisible()
    APP.processEvents()
    point = tab.transcript.cursorRect(cursor).center()
    QTest.mouseClick(tab.transcript.viewport(), Qt.MouseButton.LeftButton, pos=point)
    APP.processEvents()


# -- happy ------------------------------------------------------------------------------------


def test_happy_a_kept_long_tab_is_filled_at_once_with_the_same_transcript(env, monkeypatch):
    dock, tab = _restored(env, monkeypatch, _transcript(60), counting=True)
    assert len(tab._entries) == 300
    assert tab.transcript.appends == 0, "not line by line"
    assert tab.transcript.set_htmls == 1, "one fill for the whole transcript"
    assert tab.transcript.toHtml() == _reference_html(tab)
    text = tab.transcript.toPlainText()
    assert "task 59: what is in <folder> & why?" in text and "third <b>" not in text


def test_happy_a_click_on_thinking_draws_only_that_block(env, monkeypatch):
    _dock, tab = _restored(env, monkeypatch, _transcript(60))
    index = _reasoning(tab)[30]
    calls = _count_renders(monkeypatch, tab)
    tab.toggle_reasoning(index)
    assert calls == [index], "only the toggled block is drawn"
    assert "second line of 30" in tab.transcript.toPlainText()
    assert tab.transcript.toHtml() == _reference_html(tab)
    calls.clear()
    tab.toggle_reasoning(index)
    assert calls == [index]
    assert "second line of 30" not in tab.transcript.toPlainText()
    assert tab.transcript.toHtml() == _reference_html(tab)


def test_happy_e2e_clicking_thinking_blocks_of_a_long_tab_opens_and_closes_them(env, monkeypatch):
    _dock, tab = _restored(env, monkeypatch, _transcript(60))
    for index in (_reasoning(tab)[0], _reasoning(tab)[29], _reasoning(tab)[-1]):
        step = tab._entries[index]["text"].split()[1]
        _click_block(tab, index)
        assert index in tab._open, index
        assert f"second line of {step}" in tab.transcript.toPlainText()
        _click_block(tab, index)
        assert index not in tab._open, index
        assert f"second line of {step}" not in tab.transcript.toPlainText()
    assert tab.transcript.toHtml() == _reference_html(tab)


# -- sad --------------------------------------------------------------------------------------


def test_sad_a_link_that_names_no_thinking_block_draws_nothing(env, monkeypatch):
    _dock, tab = _restored(env, monkeypatch, _transcript(5))
    before = tab.transcript.toHtml()
    calls = _count_renders(monkeypatch, tab)
    for index in (-1, len(tab._entries), 0, 3):  # out of range, a task, a tool result
        tab.toggle_reasoning(index)
    assert calls == []
    assert tab.transcript.toHtml() == before


def test_sad_a_paragraph_separator_in_a_line_stays_inside_that_line(env, monkeypatch):
    # U+2029 made Qt start a new block inside one transcript line, so the
    # blocks no longer matched the lines; it is shown as a line break now.
    transcript = _transcript(3)
    transcript[1]["text"] = "first second paragraph\nthird"
    transcript[4]["text"] = "answer  next paragraph"
    _dock, tab = _restored(env, monkeypatch, transcript)
    assert tab.transcript.document().blockCount() == len(tab._entries)
    tab.toggle_reasoning(1)
    assert "second paragraph" in tab.transcript.toPlainText()
    assert tab.transcript.toHtml() == _reference_html(tab)


def test_sad_a_transcript_out_of_step_with_its_lines_is_drawn_again_whole(env, monkeypatch):
    _dock, tab = _restored(env, monkeypatch, _transcript(4))
    # Something wrote a block of its own into the document.
    cursor = QTextCursor(tab.transcript.document())
    cursor.movePosition(QTextCursor.MoveOperation.End)
    cursor.insertBlock()
    cursor.insertText("stray")
    index = _reasoning(tab)[2]
    tab.toggle_reasoning(index)
    assert "stray" not in tab.transcript.toPlainText()
    assert "second line of 2" in tab.transcript.toPlainText()
    assert tab.transcript.toHtml() == _reference_html(tab)


# -- edge -------------------------------------------------------------------------------------


def test_edge_an_empty_kept_tab_and_its_first_lines(env, monkeypatch):
    _dock, tab = _restored(env, monkeypatch, [])
    assert tab._entries == [] and tab.transcript.toPlainText() == ""
    tab._append("You:", "hello")
    tab._append("Thinking:", "a\nb", muted=True, kind="reasoning")
    tab.toggle_reasoning(1)
    assert "a\nb" in tab.transcript.toPlainText().replace(" ", "\n")
    assert tab.transcript.toHtml() == _reference_html(tab)


def test_edge_lines_appended_after_the_fill_toggle_like_the_kept_ones(env, monkeypatch):
    _dock, tab = _restored(env, monkeypatch, _transcript(10))
    tab._append("Thinking:", "late one\nlate two", muted=True, kind="reasoning")
    tab._append("Agent:", "late answer")
    calls = _count_renders(monkeypatch, tab)
    tab.toggle_reasoning(len(tab._entries) - 2)
    tab.toggle_reasoning(_reasoning(tab)[0])
    assert calls == [len(tab._entries) - 2, _reasoning(tab)[0]]
    assert "late two" in tab.transcript.toPlainText()
    assert tab.transcript.toHtml() == _reference_html(tab)


def test_edge_a_kept_long_tab_opens_at_its_end(env, monkeypatch):
    _dock, tab = _restored(env, monkeypatch, _transcript(60))
    bar = tab.transcript.verticalScrollBar()
    assert bar.maximum() > 0
    assert bar.value() == bar.maximum(), "the latest lines are in view"


def test_edge_toggling_the_first_and_the_last_block_keeps_the_view(env, monkeypatch):
    _dock, tab = _restored(env, monkeypatch, _transcript(60))
    bar = tab.transcript.verticalScrollBar()
    bar.setValue(bar.maximum())
    APP.processEvents()
    last = _reasoning(tab)[-1]
    tab.toggle_reasoning(last)
    APP.processEvents()
    assert bar.value() == bar.maximum()
    bar.setValue(0)
    tab.toggle_reasoning(_reasoning(tab)[0])
    APP.processEvents()
    assert bar.value() == 0
    assert tab.transcript.toHtml() == _reference_html(tab)


@pytest.mark.parametrize("steps", [1, 2])
def test_edge_tiny_transcripts_match_the_line_by_line_document(env, monkeypatch, steps):
    _dock, tab = _restored(env, monkeypatch, _transcript(steps))
    assert tab.transcript.toHtml() == _reference_html(tab)
    tab.toggle_reasoning(1)
    assert tab.transcript.toHtml() == _reference_html(tab)
