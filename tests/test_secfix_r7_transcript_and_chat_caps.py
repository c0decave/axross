"""Round-7 finding L2: the layout cost of outside text in two views.

* ui/agent_dock.py appended an agent's line to the transcript whole: Qt
  lays out a paragraph at once, one 250,000-character word took 6.6 s and
  200,000 characters of alternating Hebrew and Latin letters more than
  90 s. Now a line lays out at most ui.plain_text.shown_length() of its
  text with a "Show all" link (a plain view), and past
  MAX_TRANSCRIPT_SHOWN characters the oldest lines show only their start.
* ui/chat_panel.py laid out a 16,000-character remote message whole:
  0.6-0.9 s of GUI thread per mixed-direction message. Now a message
  shows MAX_MESSAGE_SHOWN characters, "Show all" opens the rest.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QPlainTextEdit  # noqa: E402

import ui.agent_dock as AD  # noqa: E402
from core import chat as C  # noqa: E402
from tests.test_agent_loop import _no_proxy  # noqa: E402,F401
from tests.test_agent_tabs import env  # noqa: E402,F401
from tests.test_agent_transcript_speed import _reference_html, _restored, _transcript  # noqa: E402
from ui import chat_panel as CP  # noqa: E402
from ui import plain_text as PT  # noqa: E402

APP = QApplication.instance() or QApplication([])
MIXED = "אa"            # one Hebrew and one Latin letter: two direction runs


# -- the shared cut -------------------------------------------------------------------------


def test_edge_shown_length_cuts_mixed_direction_runs_and_long_words_only():
    assert PT.shown_length("plain words " * 1000) == len("plain words " * 1000)
    assert PT.shown_length(MIXED * 20_000) == PT.MIN_SHOWN_CHARS
    assert PT.shown_length("x" * 250_000) == PT.MAX_SHOWN_WORD
    assert PT.shown_length("word " * 100_000) == PT.MAX_SHOWN_CHARS
    assert PT.shown_length(MIXED * 20_000, 1000) == 1000
    assert PT.shown_length("") == 0


# -- the agent transcript -------------------------------------------------------------------


def test_sad_a_long_mixed_direction_answer_lays_out_only_its_start(env, monkeypatch):
    _dock, tab = _restored(env, monkeypatch, _transcript(2))
    text = MIXED * 20_000                      # 40,000 characters: 6.7 s before
    started = time.monotonic()
    tab._show("Agent:", text)
    APP.processEvents()
    assert time.monotonic() - started < 2.0
    shown = tab.transcript.toPlainText()
    assert MIXED * 100 in shown and text not in shown
    assert f"{AD.FULL_SCHEME}:{len(tab._entries) - 1}" in tab.transcript.toHtml()
    assert tab.transcript.document().blockCount() == len(tab._entries)
    dialog = tab.show_full_entry(len(tab._entries) - 1)
    view = dialog.findChild(QPlainTextEdit)
    assert view.toPlainText().replace("\n", "") == text
    dialog.close()


def test_happy_ordinary_lines_show_whole_and_unchanged(env, monkeypatch):
    _dock, tab = _restored(env, monkeypatch, _transcript(3))
    tab._show("Agent:", "a normal answer\nwith two lines and <markup> & such")
    html = tab.transcript.toHtml()
    assert AD.FULL_SCHEME not in html
    assert "with two lines and <markup> & such" in tab.transcript.toPlainText()
    assert tab.transcript.toHtml() == _reference_html(tab)


def test_sad_past_the_transcript_cap_the_oldest_lines_show_only_their_start(env, monkeypatch):
    monkeypatch.setattr(AD, "MAX_TRANSCRIPT_SHOWN", 20_000)
    _dock, tab = _restored(env, monkeypatch, _transcript(1))
    for i in range(8):
        tab._show("Agent:", f"long {i} " + "z" * 5000)
    assert tab._shown_chars <= AD.MAX_TRANSCRIPT_SHOWN
    assert 0 in tab._collapsed and len(tab._entries) - 1 not in tab._collapsed
    assert tab.transcript.document().blockCount() == len(tab._entries)
    first_answer = next(i for i, e in enumerate(tab._entries) if e["text"].startswith("long 0"))
    assert first_answer in tab._collapsed
    block = tab.transcript.document().findBlockByNumber(first_answer).text()
    assert len(block) < 400 and "long 0" in block
    assert tab.transcript.toHtml() == _reference_html(tab)
    # the whole text is a click away
    dialog = tab.show_full_entry(first_answer)
    assert "z" * 5000 in dialog.findChild(QPlainTextEdit).toPlainText().replace("\n", "")
    dialog.close()


def test_edge_a_restored_long_transcript_is_drawn_with_its_older_lines_collapsed(env, monkeypatch):
    monkeypatch.setattr(AD, "MAX_TRANSCRIPT_SHOWN", 20_000)
    transcript = _transcript(1) + [{"who": "Agent:", "text": f"old {i} " + "q" * 6000, "muted": False}
                                   for i in range(6)]
    _dock, tab = _restored(env, monkeypatch, transcript)
    assert tab._collapsed and len(tab._entries) - 1 not in tab._collapsed
    assert tab._shown_chars <= AD.MAX_TRANSCRIPT_SHOWN
    assert len(tab.transcript.toPlainText()) < 25_000
    assert tab.transcript.document().blockCount() == len(tab._entries)


def test_sad_a_link_the_transcript_did_not_make_opens_nothing(env, monkeypatch):
    from PyQt6.QtCore import QUrl

    _dock, tab = _restored(env, monkeypatch, _transcript(1))
    assert tab.show_full_entry(99) is None
    opened = []
    monkeypatch.setattr(AD, "show_full_text", lambda *a: opened.append(a))
    tab._on_anchor(QUrl(f"{AD.FULL_SCHEME}:nope"))
    tab._on_anchor(QUrl("https://evil.example/"))
    assert opened == []


# -- the chat conversation ------------------------------------------------------------------


def _message(text: str) -> C.ChatMessage:
    return C.ChatMessage("!room", "@mallory:evil.example", C.clean_text(text))


def test_sad_a_long_chat_message_shows_its_start_and_a_link_to_the_rest():
    text = MIXED * 8000
    started = time.monotonic()
    line = CP.message_html(_message(text), "", f"{CP.MORE_SCHEME}:1")
    assert len(line) < CP.MAX_MESSAGE_SHOWN + 1000
    assert f'href="{CP.MORE_SCHEME}:1"' in line
    assert time.monotonic() - started < 1.0


def test_edge_a_web_address_the_cut_runs_through_is_no_link():
    text = "see " + "w " * ((CP.MAX_MESSAGE_SHOWN - 20) // 2) + "https://example.org/" + "p" * 200
    line = CP.message_html(_message(text))
    assert "https://example." in line and 'href="https://example' not in line
    short = CP.message_html(_message("see https://example.org/x"))
    assert 'href="https://example.org/x"' in short


def test_happy_e2e_the_conversation_shows_a_long_message_quickly_and_all_of_it_on_a_click():
    from PyQt6.QtCore import QUrl

    import core.chat_irc as I

    acc = C.Account(protocol="irc", name="t", settings={"server": "127.0.0.1", "port": 1,
                    "tls": I.TLS_OFF, "nick": "alice", "proxy": "none"})
    client = I.IrcClient(acc)
    try:
        client._add_conversation("#c", C.CONV_CHANNEL, "#c")
        view = CP.ConversationView(client, "#c")
        view.resize(700, 500)
        view.show()
        APP.processEvents()
        text = MIXED * 8000
        started = time.monotonic()
        for _ in range(5):
            view.add_message(_message(text))
            APP.processEvents()
        assert time.monotonic() - started < 2.5        # 0.6-0.9 s each before
        view.add_message(_message("short one"))
        assert "short one" in view.view.toPlainText()
        assert text not in view.view.toPlainText()
        assert len(view._long_texts) == 5
        dialog = view.show_whole_message("5")
        assert dialog.findChild(QPlainTextEdit).toPlainText().replace("\n", "") == text
        dialog.close()
        assert view.show_whole_message("999") is None
        view._link(QUrl(f"{CP.MORE_SCHEME}:x"))         # no number: nothing
        view.close()
    finally:
        client.runner.stop()
