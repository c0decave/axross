"""Round-5 finding: a mail froze the GUI thread (core/mail_html.py).

The safe view (ui/mail_project.py SafeBrowser) lays a mail's sanitised HTML
out on the GUI thread, and the sanitiser let through what Qt lays out in
exponential or quadratic time:

* tables nested 256 deep - 21 nested tables, a 467-byte mail, kept the GUI
  thread busy for 25.5 s, 24 for minutes;
* text inside nested tables - each table around it lays it out again;
* one long word (no break opportunity) - 400,000 characters took 10 s;
* MAX_OUTPUT checked before escaping: 4 MB of ``&#`` made 12.6 MB of HTML
  (one 12.6 MB word), and setHtml never came back.

Now tables nest at most MAX_TABLE_DEPTH deep, lists and quotes
MAX_INDENT_DEPTH, the work inside tables is capped (the tables end there,
the rest shows as text), a long word gets a zero-width break opportunity
every MAX_WORD characters, and the escaped output counts.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import mail_html as M  # noqa: E402
from core.mail_html import sanitise  # noqa: E402

ZWSP = "​"


def _depth(out: str, tag: str) -> int:
    depth = deepest = 0
    i = 0
    while True:
        start = out.find(f"<{tag}", i)
        end = out.find(f"</{tag}>", i)
        if start == -1 and end == -1:
            return deepest
        if start != -1 and (end == -1 or start < end):
            depth += 1
            deepest = max(deepest, depth)
            i = start + 1
        else:
            depth -= 1
            i = end + 1


def _text(out: str) -> str:
    from html.parser import HTMLParser

    parts: list[str] = []

    class P(HTMLParser):
        def handle_data(self, data):
            parts.append(data)

    p = P()
    p.feed(out)
    p.close()
    return "".join(parts).replace(ZWSP, "")


# -- the decision ---------------------------------------------------------------------------

def test_happy_an_ordinary_newsletter_keeps_its_tables_and_words():
    mail = ("<table><tr><td><table><tr><td>Hello <b>you</b></td><td>"
            "<a href='https://shop.example/x'>Shop</a></td></tr></table></td></tr></table>"
            "<ul><li>one<ul><li>two</li></ul></li></ul>")
    out = sanitise(mail)
    assert _depth(out, "table") == 2 and out.count("<td>") == 3
    assert _depth(out, "ul") == 2
    assert ZWSP not in out
    assert "Hello" in out and "shop.example" in out


def test_sad_tables_nest_no_deeper_than_the_limit_and_keep_their_text():
    out = sanitise("<html><body>" + "<table><tr><td>" * 30 + "Invoice attached")
    assert _depth(out, "table") == M.MAX_TABLE_DEPTH
    assert "Invoice attached" in out
    assert out.count("<table>") == out.count("</table>")
    out = sanitise("<blockquote>" * 200 + "<ul><li>" * 200 + "x")
    assert _depth(out, "blockquote") + _depth(out, "ul") <= M.MAX_INDENT_DEPTH
    assert "<div>" * (M.MAX_NESTING + 1) not in sanitise("<div>" * 1000 + "x")


def test_edge_the_end_tag_of_a_table_left_out_does_not_close_the_one_around_it():
    inner = "<table><tr><td>" * M.MAX_TABLE_DEPTH
    deeper = "<table><tr><td>deep</td><td>cell</td></tr></table>"
    out = sanitise(inner + deeper + "after" + "</td></tr></table>" * M.MAX_TABLE_DEPTH)
    # "after" is still inside the innermost table that was kept
    innermost = out.rfind("<td>")
    assert out.find("after") > innermost and out.find("after") < out.find("</td>", innermost)
    assert "deep" in out and "cell" in out
    assert out.count("<table>") == out.count("</table>") == M.MAX_TABLE_DEPTH


def test_sad_the_work_inside_tables_is_capped():
    out = sanitise("<table><tr><td>" * 6 + "lorem ipsum " * 200_000)
    assert out.count("<table>") == out.count("</table>")
    closed = out.rfind("</table>")
    assert closed < len(out) // 4, "most of the text is shown after the tables"
    assert _text(out).count("lorem") > 100_000


def test_sad_a_long_word_gets_break_opportunities():
    out = sanitise("<p>Hello " + "A" * 10_000 + "</p>")
    assert out.count(ZWSP) == 10_000 // M.MAX_WORD - (10_000 % M.MAX_WORD == 0)
    assert _text(out) == "Hello " + "A" * 10_000
    # a word goes on across the tags inside it
    out = sanitise("<b>x</b>" * 1000)
    assert out.count(ZWSP) >= 1000 // M.MAX_WORD - 1


def test_edge_the_escaped_output_is_what_is_capped():
    out = sanitise("&#" * 2_000_000)
    assert len(out) <= M.MAX_OUTPUT + 1024
    tail = out[-10:]
    assert "&" not in tail or ";" in tail[tail.rfind("&"):], "cut inside a character reference"


# -- end to end: the viewer's layout --------------------------------------------------------

_LAYOUT = """
import sys, time
sys.path.insert(0, sys.argv[2])
from PyQt6.QtWidgets import QApplication
app = QApplication([])
import ui
from ui.mail_project import _safe_browser_class
view = _safe_browser_class()(); view.resize(900, 600); view.show(); app.processEvents()
text = open(sys.argv[1], encoding="utf-8").read()
start = time.perf_counter(); view.setHtml(text); app.processEvents()
print("TOOK", time.perf_counter() - start, flush=True)
"""


def _layout_seconds(html_text: str, tmp_path, limit: float = 60) -> float:
    """setHtml + first layout of the safe view, in a child (a regression
    fails here instead of hanging the run)."""
    import subprocess

    page = tmp_path / "mail.html"
    page.write_text(html_text, encoding="utf-8")
    root = str(Path(__file__).resolve().parents[1])
    try:
        out = subprocess.run([sys.executable, "-c", _LAYOUT, str(page), root],
                             capture_output=True, text=True, timeout=limit, cwd=root)
    except subprocess.TimeoutExpired:
        return float("inf")
    took = [line for line in out.stdout.splitlines() if line.startswith("TOOK ")]
    assert took, out.stderr[-2000:]
    return float(took[0].split()[1])


@pytest.mark.parametrize("mail", [
    "<html><body>" + "<table><tr><td>" * 24 + "Invoice attached",
    "<p>Hello " + "A" * 400_000,
    "&#" * 2_000_000,
    "<table><tr><td>" * 6 + "lorem ipsum " * 100_000,
], ids=["nested-tables", "long-word", "escaped-growth", "text-in-nested-tables"])
def test_e2e_the_safe_view_lays_a_hostile_mail_out_quickly(mail, tmp_path):
    """Each took 10 s to minutes on the GUI thread before."""
    assert _layout_seconds(sanitise(mail), tmp_path) < 5.0
