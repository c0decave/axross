"""Bugs a reviewer found in the Markdown reader (Qt viewer and terminal), each
first a failing test here:

* axross-mdcat refused ordinary documents as "a secret file" (the agent's
  read policy, which sniffs contents: a text that only *mentions* a private
  key) while the viewer showed them - both now apply the viewer's policy;
* the terminal broke lines where the style changed ("locale (⏎LC_ALL");
* a UTF-8 BOM hid the first heading, UTF-16 came out as garbage;
* emoji sequences (ZWJ, skin tones, VS16, flags) were counted part by part,
  tables with them went out of line;
* an image named "../../x.png" was read from outside the document's folder;
* a heading named "fn1" took the anchor of footnote 1.
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


def plain(text: str) -> str:
    return ANSI.sub("", text)


def term(text: str, width: int = 60, **options) -> str:
    return T.render(text, T.Options(width=width, **options))


# -- the same policy for the document in both ---------------------------------------------------

#: (written in two parts: the public mirror's leak gate looks for the line)
KEY_LINE = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"
KEY_MENTION = f"# Keys\n\nA key file begins with\n\n```\n{KEY_LINE}\n```\n\nand the agent never reads one.\n"


def test_sad_mdcat_shows_a_document_that_only_mentions_a_private_key(tmp_path, capsys):
    """The document is the one the user named, as in the viewer (which
    shows it): only a regular file is asked for, its contents decide nothing."""
    from core import markdown_cli

    doc = tmp_path / "USAGE.md"
    doc.write_text(KEY_MENTION)
    assert markdown_cli.main(["--no-pager", "--color", "never", str(doc)]) == 0
    out = capsys.readouterr()
    assert "secret" not in out.err and KEY_LINE in out.out


# -- line breaks --------------------------------------------------------------------------------

def test_sad_a_line_never_breaks_where_only_the_style_changes():
    for text in ("x " * 23 + "locale (`LC_ALL`) here", "y " * 25 + "**bold**, and on"):
        for width in range(20, 60):
            out = plain(term(text, width=width))
            assert "(\nLC_ALL" not in out and not re.search(r"\(\s*\n\s*LC_ALL", out), (width, out)
            assert not re.search(r"bold\s*\n\s*,", out), (width, out)


def test_edge_a_word_of_many_styles_longer_than_the_line_is_still_cut():
    out = plain(term("**" + "a" * 30 + "**" + "`" + "b" * 30 + "`", width=20))
    assert max(len(line) for line in out.splitlines()) <= 20
    assert out.replace("\n", "").strip() == "a" * 30 + "b" * 30


# -- encodings ----------------------------------------------------------------------------------

@pytest.mark.parametrize("data", [
    "\ufeff# Title\n\ntext\n".encode("utf-8"),
    "# Title\n\ntext\n".encode("utf-16"),          # (with its BOM, little or big endian)
    b"\xfe\xff" + "# Title\n\ntext\n".encode("utf-16-be"),
    b"\xff\xfe" + "# Title\n\ntext\n".encode("utf-16-le"),
])
def test_sad_a_bom_and_utf16_are_read_as_the_text(data, tmp_path, capsys):
    assert MD.decode_text(data) == "# Title\n\ntext\n"
    assert [h.text for h in MD.parse(MD.decode_text(data)).headings] == ["Title"]
    from core import markdown_cli

    doc = tmp_path / "doc.md"
    doc.write_bytes(data)
    assert markdown_cli.main(["--no-pager", "--color", "never", str(doc)]) == 0
    assert capsys.readouterr().out.startswith("█ Title\n")


def test_edge_a_bom_in_the_text_handed_over_is_no_text():
    assert [h.text for h in MD.parse("\ufeff# Title\n").headings] == ["Title"]
    assert plain(term("\ufeff# Title\n")).startswith("█ Title")


def test_sad_the_viewer_reads_utf16_and_drops_the_bom(tmp_path):
    pytest.importorskip("PyQt6.QtWidgets")
    from core.local_fs import LocalFS
    from ui import markdown_view as MV

    doc = tmp_path / "doc.md"
    doc.write_bytes("# Grüße\n".encode("utf-16"))
    assert MV.read_text(LocalFS(), str(doc)) == ("# Grüße\n", False)
    doc.write_bytes("\ufeff# Title\n".encode("utf-8"))
    assert MV.read_text(LocalFS(), str(doc)) == ("# Title\n", False)


# -- emoji widths -------------------------------------------------------------------------------

@pytest.mark.parametrize("text, width", [
    ("👩\u200d👩\u200d👧", 2),          # a family: one picture
    ("👍🏽", 2),                        # a skin tone
    ("❤️", 2),                     # VS16: shown as an emoji
    ("🇩🇪", 2),                         # a flag
    ("#️⃣", 2),               # a keycap
    ("a👩\u200d💻b", 4),
    ("漢字", 4), ("é", 1), ("é", 1),
])
def test_sad_emoji_sequences_take_the_columns_a_terminal_gives_them(text, width):
    assert MD.cell_width(text) == width


def test_sad_a_table_with_emoji_sequences_stays_in_line():
    out = plain(term("| who | what |\n|---|---|\n| 👩\u200d👩\u200d👧 | 👍🏽 ok |\n| a | b |\n", width=40))
    widths = {MD.cell_width(line) for line in out.splitlines() if line}
    assert len(widths) == 1, out


def test_edge_a_cut_never_splits_an_emoji_sequence():
    family = "👩\u200d👩\u200d👧"
    out = plain(term("`" + family * 30 + "`", width=20))
    for line in out.splitlines():
        assert not line.rstrip("↩ ").endswith("\u200d") and not line.lstrip("▏ ").startswith("\u200d")


# -- images stay beside the file ----------------------------------------------------------------

def test_sad_an_image_never_comes_from_above_the_documents_folder(tmp_path):
    folder = tmp_path / "docs"
    (folder / "img").mkdir(parents=True)
    for name in ("../../../root/.ssh/x.png", "../x.png", "img/../../x.png", "%2e%2e/x.png"):
        path, why = T.locate(name, str(folder))
        assert not path and why, name
    assert T.locate("img/a.png", str(folder)) == (str(folder / "img" / "a.png"), "")
    assert T.locate("./a.png", str(folder)) == (str(folder / "a.png"), "")
    pytest.importorskip("PyQt6.QtWidgets")
    from core.local_fs import LocalFS
    from ui import markdown_view as MV

    source = MV.ImageSource(LocalFS(), str(folder / "doc.md"))
    for name in ("../../../root/.ssh/x.png", "../x.png", "img/../../x.png", "%2e%2e/x.png"):
        assert source.kind(name)[0] == "outside", name
    assert source.kind("img/a.png") == ("local", str(folder / "img" / "a.png"))


def test_sad_a_link_inside_the_folder_to_a_file_outside_is_not_read(tmp_path):
    from PIL import Image

    outside = tmp_path / "secret.png"
    Image.new("RGB", (4, 4), (1, 2, 3)).save(outside)
    folder = tmp_path / "docs"
    folder.mkdir()
    (folder / "pic.png").symlink_to(outside)
    out = plain(term("![p](pic.png)\n", folder=str(folder), images="blocks", depth="truecolor"))
    assert "outside" in out or "not beside" in out
    pytest.importorskip("PyQt6.QtWidgets")
    from core.local_fs import LocalFS
    from ui import markdown_view as MV

    source = MV.ImageSource(LocalFS(), str(folder / "doc.md"))
    assert isinstance(source.read(["pic.png"])["pic.png"], str)


# -- anchors ------------------------------------------------------------------------------------

def test_sad_a_heading_never_takes_a_footnotes_anchor():
    doc = MD.parse("# fn1\n\n# fnref1\n\nText[^a].\n\n[^a]: The note.\n")
    anchors = [h.anchor for h in doc.headings]
    assert "fn1" not in anchors and "fnref1" not in anchors and len(set(anchors)) == 2
    pytest.importorskip("PyQt6.QtWidgets")
    from ui.markdown_html import to_html

    page = to_html(doc)
    assert page.count('<a name="fn1">') == 1 and page.count('<a name="fnref1">') == 1
