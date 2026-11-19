"""What readers of the glow / mdcat / GitHub / Typora class show beyond the
Markdown set (tests/test_markdown_full.py), in the Qt viewer and in the
terminal alike:

* GitHub's alerts - ``> [!NOTE]``, TIP, IMPORTANT, WARNING, CAUTION - as a
  box with a bar and a title in their colour;
* math - ``$…$``, ``$$…$$`` and a ``math`` fence - as text people read (the
  common TeX commands as Unicode), and "$5 and $10" left as text;
* emoji short codes (``:tada:``), never in code;
* a page of its own for a web browser (Export HTML): what the viewer shows,
  loading nothing but the images beside it.
"""

from __future__ import annotations

import io
import os
import re
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("markdown_it", reason="markdown-it-py not installed")
pytest.importorskip("mdit_py_plugins", reason="mdit-py-plugins not installed")

from core import markdown_doc as MD  # noqa: E402
from core import markdown_term as T  # noqa: E402

ANSI = re.compile(r"\x1b(\[[0-9;]*m|\]8;;[^\x1b]*\x1b\\)")


def plain(text: str) -> str:
    return ANSI.sub("", text)


def term(text: str, width: int = 60, **options) -> str:
    return T.render(text, T.Options(width=width, **options))


ALERTS = """> [!NOTE]
> Useful *information*.

> [!warning]
> Mind this.
> - and this

> [!TIP] text on the marker's line

> A plain quote.

> [!FOO]
> not an alert
"""


# -- GitHub's alerts ----------------------------------------------------------------------------

def test_happy_alerts_are_known_by_their_marker_in_any_case():
    doc = MD.parse(ALERTS)
    kinds = [MD.alert_of(t) for t in doc.tokens if t.type == "blockquote_open"]
    assert kinds == ["note", "warning", "", "", ""]  # (GitHub: the marker alone on its line)
    texts = [t.content for t in doc.tokens if t.type == "inline"]
    assert "Useful *information*." in texts
    assert not any("[!NOTE]" in text or "[!warning]" in text for text in texts)


def test_happy_alerts_in_the_terminal_have_a_title_and_a_bar_in_their_colour():
    out = term(ALERTS, depth="truecolor")
    lines = plain(out).splitlines()
    assert lines[0] == "┃ ℹ Note" and lines[1] == "┃ Useful information."
    assert "┃ ⚠ Warning" in lines and "┃ • and this" in lines
    assert "│ A plain quote." in lines and "│ [!FOO]" in "\n".join(lines)
    r, g, b = T._rgb(T.DARK["note"])
    assert f"\x1b[1;38;2;{r};{g};{b}mℹ Note" in out


def test_happy_alerts_in_qt_are_a_box_with_a_bar_and_a_translated_title():
    pytest.importorskip("PyQt6.QtWidgets")
    from ui.markdown_html import LIGHT, to_html

    page = to_html(MD.parse(ALERTS), dark=False)
    assert f'<td width="4" bgcolor="{LIGHT["note"]}" style="padding: 0px">' in page
    assert f'color: {LIGHT["warning"]}">⚠ Warning</p>' in page
    # (a plain quote: a bar in the rule's colour, as GitHub - Qt draws no border on one side)
    assert page.count('class="quote"') == 3 and f'<td width="4" bgcolor="{LIGHT["rule"]}" style="padding: 0px">' in page


def test_edge_an_alert_with_only_its_marker_and_one_in_a_list():
    doc = MD.parse("> [!CAUTION]\n\n- > [!IMPORTANT]\n  > deep\n")
    assert [MD.alert_of(t) for t in doc.tokens if t.type == "blockquote_open"] == ["caution", "important"]
    lines = plain(term("> [!CAUTION]\n\n- > [!IMPORTANT]\n  > deep\n")).splitlines()
    assert lines[0] == "┃ ✖ Caution"
    assert "• ┃ ❖ Important" in lines and "  ┃ deep" in lines


def test_edge_quotes_are_not_italic_any_more():
    """GitHub's quotes are not italic; the viewer's were, every one."""
    pytest.importorskip("PyQt6.QtWidgets")
    from ui.markdown_html import style_sheet

    rule = re.search(r"blockquote \{[^}]*\}", style_sheet(False)).group(0)
    assert "italic" not in rule


# -- math ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("tex, shown", [
    (r"x^2 + y_i", "x² + yᵢ"),
    (r"\frac{a+b}{2}", "(a+b)/2"),
    (r"\sum_{i=1}^{n} i^2", "∑ᵢ₌₁ⁿ i²"),
    (r"e^{i\pi}", "e^(iπ)"),
    (r"\sqrt{x^2+y^2}", "√(x²+y²)"),
    (r"\mathbb{R}^n", "ℝⁿ"),
    (r"\alpha \leq \infty", "α ≤ ∞"),
    (r"\text{if } x \in \{1,2\}", "if x ∈ {1,2}"),
    (r"\frac{\frac{1}{2}}{3}", "(1/2)/3"),
    (r"\int_0^\infty e^{-x}\,dx", "∫_0^∞ e⁻ˣ dx"),
    (r"\begin{aligned} a &= b \\ c &= d \end{aligned}", "a = b\nc = d"),
    (r"\unknown{x}", r"\unknown{x}"),
])
def test_happy_math_is_shown_as_text_people_read(tex, shown):
    assert MD.math_text(tex) == shown


def test_happy_dollars_of_prices_stay_text_and_math_keeps_its_underscores():
    doc = MD.parse("tickets are $5 and $10, but $a_1*b_2*$ is math\n")
    children = doc.tokens[1].children
    assert [c.type for c in children] == ["text", "math_inline", "text"]
    assert children[0].content == "tickets are $5 and $10, but "
    assert children[1].content == "a_1*b_2*"  # (no emphasis out of its stars)


def test_happy_math_blocks_in_the_terminal_and_qt():
    text = "Inline $E = mc^2$.\n\n$$\n\\sum_{i=1}^n i\n$$\n\n```math\n\\alpha\n```\n\n$$ x $$ (eq1)\n"
    out = plain(term(text))
    assert "Inline E = mc²." in out
    assert re.search(r"^ +∑ᵢ₌₁ⁿ i$", out, re.M) and re.search(r"^ +α$", out, re.M)
    assert re.search(r"^ +x   \(eq1\)$", out, re.M)
    pytest.importorskip("PyQt6.QtWidgets")
    from ui.markdown_html import to_html

    page = to_html(MD.parse(text))
    page = page.replace("<i>", "").replace("</i>", "")  # (letters in italic since the tenth round: bugs10)
    # (real superscripts on a page - Unicode's small letters in the terminal: bugs6)
    page = re.sub(r'<a name="axross-itex:[^"]*"></a>', "", page)  # (its TeX for a copy: bugs14)
    assert '<span class="math">E = mc<sup>2</sup></span>' in page  # (letters in italic since the tenth round: bugs10)
    # (a display sum large, its limits above and below it, since the eleventh round: bugs11)
    assert '<font size="5">∑</font>' in page and "=1</span></font>" in page  # (its limit tight: bugs12)
    assert '<p class="math-block" align="center">α</p>' in page and "(eq1)" in page


def test_sad_hostile_math_is_bounded_and_escaped():
    assert MD.math_text("{" * 15000 + "}" * 15000)  # (beyond MATH_LIMIT: as written, at once)
    began = time.monotonic()
    MD.math_text("{" * 9000 + "x" + "}" * 9000)
    MD.math_text(r"\frac{a}{b}" * 1500)
    assert time.monotonic() - began < 2
    out = term("$\x1b]8;;http://x\x1b\\a<b$\n", depth="truecolor")
    assert "\x1b]8;;http://x" not in out
    pytest.importorskip("PyQt6.QtWidgets")
    from ui.markdown_html import to_html

    page = to_html(MD.parse("$a<b$ and $$<script>$$\n"))
    plain = page.replace("<i>", "").replace("</i>", "")  # (letters in italic since the tenth round)
    assert "a &lt; b" in plain and "<script" not in page  # (relations spaced; never markup)


# -- emoji --------------------------------------------------------------------------------------

def test_happy_emoji_short_codes_but_never_in_code_or_inside_words():
    doc = MD.parse("Done :tada: :+1::+1: `:tada:` x:tada: 10:30:45 :nope:\n\n```\n:tada:\n```\n")
    assert [c.content for c in doc.tokens[1].children] == ["Done 🎉 👍👍 ", ":tada:",
                                                           " x:tada: 10:30:45 :nope:"]
    assert doc.tokens[3].content == ":tada:\n"
    assert "Done 🎉" in plain(term("Done :tada:"))


# -- export -------------------------------------------------------------------------------------

def test_happy_export_html_is_a_page_of_its_own_that_loads_nothing_remote():
    pytest.importorskip("PyQt6.QtWidgets")
    from ui.markdown_html import EXPORT_POLICY, export_html

    text = ("# Title\n\n> [!TIP]\n> tip\n\n![here](pic.png) ![far](https://tracker.example/x.png)"
            " ![inline](data:image/png;base64,iVBORw0KGgo=) ![abs](/etc/passwd)\n\n"
            "[js](javascript:alert(1)) $x^2$\n")
    read = "data:image/png;base64,iVBORw0KGgo="  # (what the viewer read for "pic.png")
    page = export_html(MD.parse(text), title="Doc <1>", images={"pic.png": read})
    assert page.startswith("<!DOCTYPE html>") and "<title>Doc &lt;1&gt;</title>" in page
    assert f'content="{EXPORT_POLICY}"' in page and "default-src 'none'" in EXPORT_POLICY
    assert "script-src" not in EXPORT_POLICY and "<script" not in page
    assert f'<img src="{read}" alt="here" />' in page
    # (only what the viewer read is in it - any other image a chip naming it)
    assert page.count("<img") == 1 and "▣ far" in page and "▣ inline" in page and "▣ abs" in page
    assert '<img src="https://tracker.example' not in page and '<img src="/etc/passwd"' not in page
    assert 'class="markdown-alert markdown-alert-tip"' in page
    assert 'href="javascript' not in page
    assert '<span class="math">x<sup>2</sup></span>' in page.replace("<i>", "").replace("</i>", "")  # (letters in italic since the tenth round: bugs10)
    assert 'id="title"' in page


def test_happy_a_mermaid_diagram_is_a_labelled_code_block_in_both():
    text = "```mermaid\ngraph TD; A-->B\n```\n\n```python\nx = 1\n```\n"
    out = plain(term(text))
    assert " mermaid – diagram, shown as its source " in out and "graph TD; A-->B" in out
    pytest.importorskip("PyQt6.QtWidgets")
    from ui.markdown_html import to_html

    page = to_html(MD.parse(text))
    assert '<p class="code-label">mermaid – diagram, shown as its source</p>' in page
    assert '<p class="code-label">python</p>' in page
    assert "graph TD; A--&gt;B" in page


# -- axross-mdcat and axross-markdown without a window ------------------------------------------

def test_happy_mdcat_watch_draws_the_file_anew_when_it_changes(tmp_path, capsys, monkeypatch):
    from core import markdown_cli as C

    doc = tmp_path / "notes.md"
    doc.write_text("# First\n")
    calls = []

    def sleep(_seconds):
        calls.append(1)
        if len(calls) == 1:
            doc.write_text("# Second version\n")

    monkeypatch.setattr("time.sleep", sleep)
    args = C._parser().parse_args(["--watch", "--color", "never", str(doc)])
    assert C._watch(args, 60, "none", True, "none", False, poll=0, rounds=3) == 0
    out = capsys.readouterr().out
    assert out.count("█ First") == 1 and out.count("█ Second version") == 1
    assert C.main(["--watch", "-"]) == 2 and "one file" in capsys.readouterr().err


@pytest.mark.parametrize("version, links", [(551, False), (590, True)])
def test_sad_links_go_through_less_only_when_it_passes_them_on(tmp_path, monkeypatch, version, links):
    """less before 566 shows an OSC 8 hyperlink as text ("ESC]8;;https://…"):
    through such a less the address beside the link is all there is."""
    from core import markdown_cli as C

    paged = tmp_path / "paged.txt"
    less = tmp_path / "less"
    less.write_text(f"#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'less {version} (GNU regex)'; exit 0; fi\n"
                    f"cat > '{paged}'\n")
    less.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ.get('PATH', '')}")

    class Tty(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(sys, "stdout", Tty())
    doc = tmp_path / "doc.md"
    doc.write_text("[web](https://example.org)\n")
    assert C.main(["--pager", "--color", "truecolor", "--images", "none", str(doc)]) == 0
    out = paged.read_text()
    assert ("\x1b]8;;https://example.org" in out) is links
    assert "‹https://example.org›" in out


def test_happy_axross_markdown_html_writes_a_page_with_its_images(tmp_path, capsys):
    pytest.importorskip("PyQt6.QtWidgets")
    from PIL import Image

    from ui.markdown_app import main

    Image.new("RGB", (8, 6), (0, 128, 0)).save(tmp_path / "pic.png")
    (tmp_path / "doc.md").write_text("# Doc\n\n![p](pic.png) ![up](../up.png)\n\n<img src=\"pic.png\" width=\"4\">\n")
    assert main(["axross-markdown", "--html", str(tmp_path / "doc.md")]) == 0
    page = capsys.readouterr().out
    assert page.startswith("<!DOCTYPE html>") and "Content-Security-Policy" in page
    assert page.count('<img src="data:image/png;base64,') == 2
    assert '<img src="../up.png"' not in page and "▣ up" in page  # (above the folder: never read)
    assert main(["axross-markdown", "--html", str(tmp_path / "missing.md")]) == 1
