"""Round-8 content findings: what text and drawings from outside cost.

* No-break spaces (U+00A0, U+2007, U+202F) are white space for Python's
  ``\\s`` but join words for Qt: core.mail_html.breakable() and
  ui.plain_text.shown_length() saw words of one or two characters where
  Qt laid out one line of 128,000 (a Hebrew/Latin mail 44 s, an agent
  answer 7.2 s). Direction marks (RLM, LRE ... PDF, RLI ... PDI) were no
  change of direction for the caps, script changes inside a long word
  were free.
* The plain view's line cap counted only "\\n": 2 MB of "\\r" (or U+2029)
  were 2,000,001 blocks for Qt (6.35 s, 954 MB).
* The agent transcript, drawn again whole on restore, added such answers
  up: 8 answers 8.9 s + 12.8 s.
* Release notes: a 20,000-character Markdown table 4 s, 20,000 "<" 2.4 s
  (_unmark searched the document again for every mark).
* SVG: the gate counts elements, not their cost (8.8 KB filled path drawn
  100 times: 23 s); the drawing now runs in a child that is killed.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

import ui.agent_dock as AD  # noqa: E402
from core import mail_html as M  # noqa: E402
from tests.test_agent_loop import _no_proxy  # noqa: E402,F401
from tests.test_agent_tabs import env  # noqa: E402,F401
from tests.test_agent_transcript_speed import _restored, _transcript  # noqa: E402
from ui import plain_text as PT  # noqa: E402

APP = QApplication.instance() or QApplication([])
NBSP = "\u00a0"
ZWSP = "\u200b"


def _child(code: str, *, memory: int = 2 * 1024**3, timeout: float = 120.0) -> subprocess.CompletedProcess:
    """Run *code* in a child interpreter with an address-space cap (a
    regression must not take the test run's memory with it)."""
    def limit():
        import resource

        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))

    env = dict(os.environ, QT_QPA_PLATFORM="offscreen", PYTHONPATH=str(ROOT))
    return subprocess.run([sys.executable, "-c", textwrap.dedent(code)], capture_output=True, text=True,
                          timeout=timeout, env=env, cwd=str(ROOT),
                          preexec_fn=limit if os.name == "posix" else None)


# -- mail: words end where Qt breaks lines ------------------------------------------------


@pytest.mark.parametrize("space", [NBSP, "\u2007", "\u202f"])
def test_sad_no_break_spaces_join_words_for_the_word_cap(space):
    text, run = M.breakable(("x" + space) * 1000)
    assert ZWSP in text                       # one 2000-character word for Qt: broken up
    assert all(len(part) <= M.MAX_WORD for part in text.split(ZWSP))
    assert run <= M.MAX_WORD


def test_happy_ordinary_spaces_still_end_words():
    text, run = M.breakable("word " * 1000)
    assert ZWSP not in text and text == "word " * 1000 and run == 0
    text, _ = M.breakable("a\tb\nc\u3000d " * 500)
    assert ZWSP not in text


def test_edge_a_text_that_starts_with_a_no_break_space_is_one_word():
    text, run = M.breakable(NBSP + "x" * 300)
    assert ZWSP in text and text.replace(ZWSP, "") == NBSP + "x" * 300
    assert run == 301 - M.MAX_WORD


def test_sad_hebrew_latin_mail_joined_by_no_break_spaces_is_broken_up():
    html = "<p>" + "&#1488;&nbsp;a&nbsp;" * 4000 + "</p>"
    shown = M.sanitise(html)
    assert shown.count(ZWSP) >= 16_000 // M.MAX_WORD - 1


# -- mail: the plain view's line ends -----------------------------------------------------


@pytest.mark.parametrize("end", ["\r", "\r\n", "\u2029", "\u2028", "\v", "\f", "\x85"])
def test_sad_every_line_end_counts_for_the_line_cap(end):
    shown, cut = M.plain_lines(("x" + end) * 300_000)
    assert cut
    assert shown.count("\n") == M.MAX_PLAIN_LINES - 1
    assert "\r" not in shown and "\u2029" not in shown and "\u2028" not in shown


def test_happy_crlf_is_one_line_end_and_text_stays():
    assert M.plain_lines("a\r\nb\rc\nd") == ("a\nb\nc\nd", False)
    assert M.plain_lines("") == ("", False)


def test_edge_exported_fallback_counts_line_ends_too():
    shown, cut = PT._plain_lines("\r" * 200_000)
    assert cut and shown.count("\n") == 100_000 - 1


def test_sad_plain_view_of_carriage_returns_stays_small_in_qt():
    # 2 MB of "\r": 2,000,001 Qt blocks and 954 MB before - in a child with
    # an address-space cap.
    result = _child("""
        from PyQt6.QtWidgets import QApplication, QPlainTextEdit
        from core import mail_html as M
        app = QApplication([])
        shown, cut = M.plain_lines("\\r" * 2_000_000)
        view = QPlainTextEdit()
        view.setPlainText(shown)
        print(view.document().blockCount(), cut)
    """)
    assert result.returncode == 0, result.stderr[-2000:]
    blocks, cut = result.stdout.split()
    assert int(blocks) <= M.MAX_PLAIN_LINES and cut == "True"


# -- the shared cut of agent answers and chat messages ------------------------------------


def test_sad_no_break_spaces_join_words_for_shown_length():
    assert PT.shown_length(("a" + NBSP + "α" + NBSP) * 16_000) == PT.MIN_SHOWN_CHARS
    assert PT.shown_length(("x" + NBSP) * 32_000) == PT.MAX_SHOWN_WORD
    assert PT.shown_length(("x" + "\u202f") * 32_000) == PT.MAX_SHOWN_WORD


@pytest.mark.parametrize("unit", ["a\u200f", "a\u200e", "a\u202ab\u202c", "a\u202eb\u202c",
                                  "a\u2067b\u2069", "a\u2066b\u2069", "a\u2068b\u2069",
                                  "a\u200f" + NBSP, "a\u200f "])
def test_sad_direction_marks_count_as_changes_of_direction(unit):
    text = unit * (64_000 // len(unit))
    assert PT.shown_length(text) == PT.MIN_SHOWN_CHARS


def test_sad_script_changes_inside_one_long_word_are_capped():
    assert PT.shown_length("aα" * 32_000) == PT.MIN_SHOWN_CHARS


def test_happy_ordinary_text_of_any_script_is_shown_whole():
    for text in ("Καλημέρα κόσμε, τι κάνεις; " * 1500, "Привет, мир! Как дела? " * 1500,
                 "plain words and more " * 2000, "שלום עולם " * 400):
        assert PT.shown_length(text) == len(text), text[:20]
        assert PT.layout_cost(text) >= len(text)
    assert PT.layout_cost("plain words " * 100) == len("plain words " * 100)


def test_edge_layout_cost_and_short_length():
    mixed = "אa" * 2000
    assert PT.layout_cost(mixed) == len(mixed) + PT.RUN_COST * 2000
    assert PT.layout_cost(mixed, 10) == 10 + PT.RUN_COST * 5
    assert PT.short_length("plain text " * 50, 200) == 200
    assert PT.short_length(mixed, 200) < 40
    assert PT.short_length("", 200) == 0


# -- the agent transcript -----------------------------------------------------------------


def test_sad_an_answer_of_script_changes_between_no_break_spaces_is_cut(env, monkeypatch):
    _dock, tab = _restored(env, monkeypatch, _transcript(1))
    text = ("a" + NBSP + "α" + NBSP) * 16_000     # 7.2 s before
    started = time.monotonic()
    tab._show("Agent:", text)
    APP.processEvents()
    assert time.monotonic() - started < 3.0
    index = len(tab._entries) - 1
    block = tab.transcript.document().findBlockByNumber(index).text()
    assert len(block) < PT.MIN_SHOWN_CHARS + 200
    assert f"{AD.FULL_SCHEME}:{index}" in tab.transcript.toHtml()


def test_sad_restoring_many_costly_answers_collapses_by_cost(env, monkeypatch):
    answers = [{"who": "Agent:", "text": ("a" + NBSP + "α" + NBSP) * 16_000, "muted": False}
               for _ in range(8)]
    answers += [{"who": "Agent:", "text": "אa" * 2000, "muted": False} for _ in range(120)]
    started = time.monotonic()
    _dock, tab = _restored(env, monkeypatch, _transcript(1) + answers)   # 21.7 s before
    APP.processEvents()
    assert time.monotonic() - started < 10.0
    assert len(tab._collapsed) > 100 and len(tab._entries) - 1 not in tab._collapsed
    shown = tab.transcript.toPlainText()
    assert len(shown) < 128 * 200 + 60_000
    assert tab.transcript.document().blockCount() == len(tab._entries)


def test_happy_ordinary_answers_are_not_collapsed(env, monkeypatch):
    answers = [{"who": "Agent:", "text": f"answer {i}: " + "plain words " * 500, "muted": False}
               for i in range(20)]
    _dock, tab = _restored(env, monkeypatch, _transcript(1) + answers)
    assert not tab._collapsed
    assert "answer 0: plain words" in tab.transcript.toPlainText()


# -- release notes ------------------------------------------------------------------------


def test_sad_twenty_thousand_less_than_signs_render_quickly():
    from ui.update_ui import ReleaseNotesView

    view = ReleaseNotesView()
    started = time.monotonic()
    view.set_notes("<" * 20_000)                     # 2.4 s before (_unmark)
    assert time.monotonic() - started < 1.5
    assert view.toPlainText() == "<" * 20_000


def test_happy_unmark_still_takes_the_added_backslash_out_of_code():
    from ui.update_ui import ReleaseNotesView

    view = ReleaseNotesView()
    view.set_notes("a <b> and `x<y` and\n\n```\n<<z>>\n```\n\n| a | b |\n|---|---|\n| `<` | < |\n")
    text = view.toPlainText()
    assert "\u2060" not in text and "\\<" not in text
    assert "a <b> and x<y and" in text and "<<z>>" in text
    assert view.document().rootFrame().childFrames()           # the small table stays a table


def test_sad_a_table_of_too_many_cells_is_shown_as_text():
    from ui.update_ui import MAX_NOTES_TABLE_CELLS, ReleaseNotesView, table_cells

    body = "|" + "a|" * 100 + "\n|" + "-|" * 100 + "\n" + ("|" * 101 + "\n") * 190   # 4 s before
    assert table_cells(body) > MAX_NOTES_TABLE_CELLS
    view = ReleaseNotesView()
    started = time.monotonic()
    view.set_notes(body)
    assert time.monotonic() - started < 1.5
    assert not view.document().rootFrame().childFrames()


def test_edge_table_cells_counts_rows_without_pipes_and_quoted_tables():
    from ui.update_ui import table_cells

    assert table_cells("|a|b|\n|-|-|\n|x|y|\n\nafter") == 4
    assert table_cells("|" + "a|" * 1000 + "\n|" + "-|" * 1000 + "\n" + "x\n" * 100) == 1000 * 101
    assert table_cells("> | a |\n> |---|\n> | x |\n") == 2
    assert table_cells("---\n- a - b\nno table here") == 0


# -- SVG: drawn in a child that is killed -------------------------------------------------


SVG_HEAD = ('<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100" viewBox="0 0 100 100">')


def _svg(tmp_path, body: str) -> str:
    path = tmp_path / "picture.svg"
    path.write_text(SVG_HEAD + body + "</svg>")
    return str(path)


def test_sad_a_costly_svg_is_stopped_at_the_time_limit(tmp_path, monkeypatch):
    from core import previews as P
    from core import svg_worker

    d = "M0 0" + "l50 99l-49 -98" * 500
    path = _svg(tmp_path, f'<defs><path id="p" d="{d}" fill="red"/></defs>' + '<use href="#p"/>' * 100)
    assert P.svg_refusal(Path(path).read_bytes()) is None     # the gate lets it through: 8.8 KB
    monkeypatch.setattr(svg_worker, "RENDER_SECONDS", 2.0)
    started = time.monotonic()
    with pytest.raises(P.PreviewTooLarge, match="longer than"):
        P._render_svg(path, 512)                              # 23 s in this process before
    assert time.monotonic() - started < 8.0


def test_happy_an_svg_is_drawn_by_the_child(tmp_path):
    from core import previews as P

    path = _svg(tmp_path, '<rect width="100" height="50" fill="#ff0000"/>')
    image = P._render_svg(path, 64)
    assert (image.width(), image.height()) == (64, 64)
    assert image.pixelColor(10, 10).red() == 255 and image.pixelColor(10, 50).alpha() == 0


def test_happy_an_svg_with_text_is_drawn_too(tmp_path):
    from core import previews as P

    path = _svg(tmp_path, '<rect width="100" height="100" fill="white"/>'
                          '<text x="0" y="80" font-size="90" fill="black">W</text>')
    image = P._render_svg(path, 64)
    assert (image.width(), image.height()) == (64, 64)
    assert any(image.pixelColor(x, y).red() < 128 for x in range(64) for y in range(64))


def test_edge_xml_that_is_no_svg_is_refused_by_the_child(tmp_path):
    from core import previews as P

    path = tmp_path / "not.svg"
    path.write_text("<html><body>hi</body></html>")
    with pytest.raises(P.PreviewDecodeFailed):
        P._render_svg(str(path), 64)


def test_edge_the_child_is_started_isolated_and_bounded():
    from core import svg_worker

    argv = svg_worker.worker_argv(256, 5, 3.0)
    assert argv[0] == sys.executable and argv[1:3] == ["-I", "-c"]
    assert argv[-5:] == [str(os.getpid()), str(svg_worker.cpu_seconds_for(3.0)),
                         str(svg_worker.ADDRESS_SPACE_LIMIT), "256", "5"]
