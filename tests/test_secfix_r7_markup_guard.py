"""Round-7 findings M1/M2: rich text the markup guard let through.

* M1 - the guard counted ``</table>`` with a regular expression over the
  raw text, so a ``</table>`` inside an attribute value
  (``<i title='</table>'>``) or an HTML comment - no tag for Qt - counted
  a level down: a 476-byte remote name of 17 nested tables kept the GUI
  thread 33.5 s in "Delete {name}?". Now an end tag counts only where an
  HTML parser reads one (ui/markup_guard.py ``_EndTagOffsets``).
* M2 - a CSS comment between property and colon (``font-size/**/:4000px``)
  passed every size check, and sizes under the caps added up
  (letter-spacing 1999px x 200 letters: 402172 px wide; margins x30:
  58391 px tall). Now comments and escapes are read the way Qt's CSS
  scanner reads them, and what passes the checks is laid out off screen
  and shown as written when the markup makes it larger than
  MAX_RENDER_WIDTH_PX / MAX_RENDER_HEIGHT_PX (and than its words take).
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

import ui  # noqa: E402,F401 - installs ui.markup_guard
from ui import markup_guard as MG  # noqa: E402

APP = QApplication.instance() or QApplication([])

#: the remote name of the report: 6 plain levels, then a fake close per level
FAKE_CLOSE_NAME = ("<table><tr><td>" * 6 + "<i title='</table>'><table><tr><td>" * 11 + "x")


def test_sad_a_close_tag_inside_an_attribute_or_comment_closes_no_table():
    for unit in ('<table><tr><td><b title="</table>"></b>',
                 "<table><tr><td><!--</table>-->",
                 "<table><tr><td><i title='</table>'>",
                 "<ul><li><b title='</ul>'>"):
        text = unit * 30 + "x"
        assert MG.bombs_layout(text), unit
        assert MG.defuse(text) != text, unit
    assert MG.bombs_layout(FAKE_CLOSE_NAME)
    message = "Delete " + FAKE_CLOSE_NAME + "?"
    assert MG.defuse_message(message) != message


def test_happy_real_close_tags_still_close():
    """Tables one after the other (each closed) are no nesting."""
    text = "<table><tr><td>x</td></tr></table>" * 20
    assert not MG.bombs_layout(text)
    text = "<TABLE><tr><td>x</td></tr></TABLE >\n" * 20
    assert not MG.bombs_layout(text)
    nested_ok = "<table><tr><td>" * 3 + "x" + "</td></tr></table>" * 3
    assert MG.defuse(nested_ok) == nested_ok


def test_sad_a_css_comment_or_escape_hides_no_size():
    for text in ('<span style="font-size/**/:4000px">X</span>',
                 '<td style="padding/**/:9999px">x',
                 '<span style="letter-spacing/**/:99999px">ABCDEFGHIJ</span>',
                 '<p style="-qt-block-indent/**/:999">x',
                 '<p style="margin-left/* a */:40000px">x',
                 '<p style="margin-left:40000px/*">x',
                 '<p style="margin-left:\\34 0000px">x',
                 "<html><head><style>p { font-size/**/: 4000px }</style></head><p>x"):
        assert MG.bombs_layout(text), text
        assert MG.defuse(text) != text, text


def test_sad_sizes_that_add_up_are_shown_as_written():
    """Each value is under the caps; together they lay out tens of
    thousands of pixels: measured, shown as written."""
    for text in ('<span style="letter-spacing:1999px">' + "W" * 200 + "</span>",
                 '<p style="margin-top:1999px">x</p>' * 30,
                 '<div style="margin-left:1999px">' * 30 + "x" + "</div>" * 30,
                 '<table cellpadding="1999" cellspacing="1999" border="1999"><tr><td>' * 6 + "x",
                 "<table><tr>" + '<td width="1999">x</td>' * 100 + "</tr></table>"):
        assert MG.bombs_layout(text), text[:60]
        out = MG.defuse(text)
        assert out.startswith("<qt class='axross-defused'"), text[:60]


def test_happy_long_rich_text_is_as_large_as_its_words():
    """A long paragraph or many lines are wide or tall because of their
    words, not the markup: rendered as before."""
    # (each under MAX_RICH_CHARS: a longer rich text is shown as written,
    # tests/test_r9_content_caps.py)
    paragraph = "<b>Note</b>: " + "word " * 800
    lines = "<p style='color:#888'>" + "<br>".join(f"line {i}" for i in range(300)) + "</p>"
    for text in (paragraph, lines,
                 "<table width='100%' cellpadding='3'><tr><td>a</td><td>b</td></tr></table>",
                 "<p style='margin:2px 0; font-size:14px'>x</p>"):
        assert not MG.bombs_layout(text), text[:60]
        assert MG.defuse(text) == text


def test_edge_off_the_gui_thread_nothing_is_measured(monkeypatch):
    """No QTextDocument off the GUI thread: the static checks still hold."""
    import threading

    text = '<span style="letter-spacing:1999px">' + "W" * 200 + "</span>"
    MG._rendered_too_large.cache_clear()
    result = {}
    worker = threading.Thread(target=lambda: result.update(
        bombs=MG.bombs_layout(text), static=MG.bombs_layout(FAKE_CLOSE_NAME)))
    worker.start()
    worker.join(30)
    assert result == {"bombs": False, "static": True}
    assert MG.bombs_layout(text)  # on the GUI thread it is measured


def test_e2e_the_fake_close_name_shows_at_once_in_a_message_box():
    """The 476-byte name of the report in "Delete {name}?": shown in well
    under a second (33.5 s before), in a child so a regression fails."""
    code = textwrap.dedent(f"""
        import sys, time
        sys.path.insert(0, {str(ROOT)!r})
        import ui
        from PyQt6.QtWidgets import QApplication, QMessageBox
        app = QApplication([])
        name = {FAKE_CLOSE_NAME!r}
        started = time.monotonic()
        box = QMessageBox(QMessageBox.Icon.Question, "Delete", "Delete " + name + "?")
        box.show(); app.processEvents()
        size = box.size()
        print(round(time.monotonic() - started, 2), size.width(), size.height())
    """)
    env = dict(os.environ, QT_QPA_PLATFORM="offscreen")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         timeout=60, env=env)
    seconds, width, height = out.stdout.split()[-3:]
    assert float(seconds) < 2.0, out.stdout
    assert int(width) < 2000 and int(height) < 2000
