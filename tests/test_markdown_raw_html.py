"""Raw HTML in a Markdown file: an allowed subset, in the Qt viewer, the
terminal and an exported page alike (core.markdown_doc._safe_html).

READMEs centre a logo with ``<p align="center"><img …></p>``, fold details
away in ``<details>`` / ``<summary>``, write keys as ``<kbd>`` and formulas
with ``<sub>`` / ``<sup>``; all of that was shown as its source text. Now
those tags are kept - with the attributes each may have, nothing else - and
any other tag goes (its text stays; a script's or a style's goes with it),
comments go. The file stays untrusted: these tests are the hostile part.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("markdown_it", reason="markdown-it-py not installed")
pytest.importorskip("mdit_py_plugins", reason="mdit-py-plugins not installed")

from core import markdown_doc as MD  # noqa: E402
from core import markdown_term as T  # noqa: E402

ANSI = re.compile(r"\x1b(\[[0-9;]*m|\]8;;[^\x1b]*\x1b\\)")

README = """<p align="center"><img src="logo.png" width="200" alt="Logo"><br><b>tagline</b></p>

<!-- a comment nobody sees -->

<details>
<summary>More <kbd>Ctrl</kbd>+<kbd>C</kbd></summary>

Inside **Markdown**.

</details>

H<sub>2</sub>O and x<sup>2</sup>, a<br>b, <ins>new</ins> <del>old</del> <span>plain</span>.
"""

HOSTILE = """<script>alert(1)</script>

<style>body { background: url(https://tracker.example/x) }</style>

<img src="logo.png" onerror="alert(1)" style="width:9999px" width="99999">
<img src="javascript:alert(1)"> <img src=x onload=alert(1)//>
<a href="jav&#x61;script:alert(1)">charref</a> <a href=" javascript:x">space</a>
<a href="https://ok.example" target="_blank" onclick="x()">ok</a>
<svg onload="alert(1)"><text>svg text</text></svg>
<iframe src="https://evil.example">frame text</iframe>
<scr<script>ipt>alert(2)</script>
<div style="background:url(https://tracker.example/y)" align="center;color:red">div text</div>
<details open ontoggle="alert(1)"><summary>s</summary></details>
<base href="https://evil.example/"><meta http-equiv="refresh" content="0;url=https://evil.example">
<form action="https://evil.example"><input type="checkbox" checked><button>press</button></form>
<math><mi xlink:href="javascript:alert(1)">m</mi></math>
<!--><script>alert(3)</script>-->
<b>&#27;[31mred&#x202e;flip</b>

Inline <script>alert(4)</script> and <img src="https://tracker.example/t.png" alt="t"> end.
"""


def plain(text: str) -> str:
    return ANSI.sub("", text)


def term(text: str, width: int = 70, **options) -> str:
    return T.render(text, T.Options(width=width, **options))


def qt_page(text: str) -> str:
    pytest.importorskip("PyQt6.QtWidgets")
    from ui.markdown_html import to_html

    return to_html(MD.parse(text))


def browser_page(text: str) -> str:
    pytest.importorskip("PyQt6.QtWidgets")
    from ui.markdown_html import export_html

    return export_html(MD.parse(text))


# -- what is kept -------------------------------------------------------------------------------

def test_happy_a_readmes_html_is_shown_in_qt():
    page = qt_page(README)
    assert '<p align="center"><img src="logo.png" width="200" alt="Logo" /><br /><b>tagline</b></p>' in page
    assert "comment" not in page
    # (folded as GitHub folds it: its summary the link that opens it)
    assert ('<p class="summary"><a class="fold" href="#axross-details-1"><b>▸ More <span class="kbd">Ctrl</span>'
            '+<span class="kbd">C</span></b></a></p>') in page
    assert "<strong>Markdown</strong>" not in page
    from ui.markdown_html import to_html_parts

    assert "<strong>Markdown</strong>" in "".join(to_html_parts(MD.parse(README), blocks=0, toggled={1}))
    assert "H<sub>2</sub>O" in page and "x<sup>2</sup>" in page and "a<br />b" in page
    assert "<u>new</u>" in page and "<del>old</del>" in page and "<span>" not in page and "plain" in page


def test_happy_a_readmes_html_is_shown_in_the_terminal():
    out = plain(term(README, images="none"))
    assert "🖼 Logo" in out and "tagline" in out and "<" not in out and "comment" not in out
    assert "▾ More Ctrl+C" in out and "Inside Markdown." in out
    assert "H₂O and x²" in out and "a\nb" in out and "new old plain." in out


def test_happy_an_exported_page_keeps_real_details_and_kbd():
    page = browser_page(README)
    assert "<details>" in page and "<summary>More <kbd>Ctrl</kbd>" in page and "</details>" in page


def test_happy_an_html_heading_is_a_heading_of_the_outline():
    """<h1 align="center">Project</h1> is a heading as GitHub shows it: in
    the outline, with its anchor (tests/test_markdown_reader_bugs3.py)."""
    page = qt_page('<h1 align="center">Logo line</h1>\n\n# Real\n')
    assert '<h1 align="center"><a name="logo-line"></a>Logo line</h1>' in page
    assert [h.text for h in MD.parse('<h1 align="center">Logo line</h1>\n\n# Real\n').headings] == [
        "Logo line", "Real"]


# -- what never is ------------------------------------------------------------------------------

@pytest.mark.parametrize("render", [qt_page, browser_page])
def test_sad_hostile_html_keeps_nothing_that_runs_loads_or_misleads(render):
    page = render(HOSTILE).lower()
    body = page.split("<body>", 1)[1]
    # ("<scr<script>ipt>" leaves the text "ipt>alert(2)": text, no tag)
    for bad in ("<script", "alert(1)", "alert(3)", "alert(4)", "onerror", "onload", "onclick", "ontoggle",
                "javascript",
                "<style", "url(", "<iframe", "<svg", "<base", "<meta", "<form", "<input", "<button",
                "<math", "target=", "style=", "9999", "evil.example", "\x1b", "\u202e"):
        assert bad not in body, bad
    assert "frame text" not in body and "svg text" not in body  # (dropped with their tags)
    assert "div text" in body and "charref" in body and "press" in body
    assert '<a href="https://ok.example">ok</a>' in body


def test_sad_hostile_html_sends_the_terminal_nothing_of_its_own():
    out = term(HOSTILE, depth="truecolor")
    rest = ANSI.sub("", out)
    assert "\x1b" not in rest and "\u202e" not in out
    text = plain(out)
    for bad in ("<script", "alert(1)", "alert(3)", "alert(4)", "onerror", "<style", "url(", "<iframe",
                "frame text", "svg text"):
        assert bad not in text, bad
    assert "redflip" in text and "div text" in text
    assert "🖼 t end." in text and "tracker.example" not in text  # (a remote picture: its alt text)
    links = re.findall(r"\x1b\]8;;([^\x1b]*)\x1b\\", out)
    assert all(link.startswith(("https://", "file://")) for link in links if link), links


def test_sad_an_image_of_raw_html_is_read_as_a_markdown_images_is(tmp_path):
    pytest.importorskip("PyQt6.QtWidgets")
    from core.local_fs import LocalFS
    from ui import markdown_view as MV

    page = qt_page('<img src="/etc/passwd"> <img src="../up.png"> <img src="https://x.example/a.png">\n')
    names = re.findall(r'<img src="([^"]*)"', page)
    source = MV.ImageSource(LocalFS(), str(tmp_path / "doc.md"))
    assert [source.kind(name)[0] for name in names] == ["outside", "outside"]
    assert "▣ a.png" in page  # (on the network: a chip, never an image to load)
    exported = browser_page('<img src="/etc/passwd"> <img src="https://x.example/a.png">\n')
    assert "<img" not in exported.split("<body>", 1)[1]


def test_edge_unclosed_and_stray_tags_end_where_their_paragraph_or_the_page_does():
    page = qt_page("<b>bold\n\nnext </i> paragraph\n\n<details>\n\nopen to the end\n")
    assert "<p><b>bold</b></p>" in page and "</i>" not in page
    assert page.count('<div class="details">') == 1 and page.rstrip().endswith("</div>\n</body></html>")
    out = plain(term("<b>bold\n\nnext </i> paragraph\n"))
    assert out.splitlines()[2] == "next paragraph"


def test_edge_a_script_between_markdown_inlines_takes_its_text_along():
    page = qt_page("a <script>**x** y</script> b\n")
    assert "x" not in page.split("<body>", 1)[1].replace("<p>a  b</p>", "")
    assert "a b" in plain(term("a <script>**x** y</script> b\n"))
