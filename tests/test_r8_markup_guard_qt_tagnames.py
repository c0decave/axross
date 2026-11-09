"""Round-8 H2: the markup guard read tags as an HTML parser does; Qt's
rich-text parser reads more as a tag (ui/markup_guard.py).

Qt takes a quoted tag name (``<"img">``, ``<'table'>``), a name with
character references (``<&#105;mg>``, ``<t&#97;ble>``) and a quoted
attribute name (``<span "<"=1 style=…>``) as markup; the guard looked for
``<`` followed by a letter and saw none. A 40-byte archive name,
``<b></b><'img' src=&#47;dev&#47;zero>.zip``, made "Could not extract
{name}" read /dev/zero until std::bad_alloc killed axross; nested quoted
tables froze the GUI thread 33-37 s; a 56-byte name laid out a 3.2 GB
message box; ``<"style">`` / ``<"title">`` hid the rest of a message; and
html.parser ends a comment at ``-- >`` where Qt reads on to ``-->``.

Now rich text is rendered only when every ``<`` in it starts a tag written
in one plain form both parsers read alike (ASCII name Qt knows, ASCII
attribute names, values quoted or plain, no comment); anything else is
shown as written. A label or message box set to RichText counts as rich
whatever Qt.mightBeRichText says.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication, QLabel, QMessageBox  # noqa: E402

import ui  # noqa: E402,F401 - installs ui.markup_guard
from tests.test_markup_guard import assert_survives  # noqa: E402
from ui import markup_guard as MG  # noqa: E402

APP = QApplication.instance() or QApplication([])

#: the 40-byte archive name of the report (no "/" in it)
CRASH_NAME = "<b></b><'img' src=&#47;dev&#47;zero>.zip"

#: spellings Qt reads as the tag the guard checks for
TAG_SPELLINGS = ('<"table">', "<'table'>", "<t&#97;ble>", "<&#116;able>", '<t"able">',
                 "<tab\x00le>", "<table/x>", "<bloc\u212aquote>", "<\u00a0table>")


def _shown(text: str) -> str:
    """What a QLabel showing *text* through the guard reads as."""
    from PyQt6.QtGui import QTextDocument

    label = QLabel(text)
    doc = QTextDocument()
    if label.textFormat() == Qt.TextFormat.PlainText or not Qt.mightBeRichText(label.text()):
        return label.text()
    doc.setHtml(label.text())
    return doc.toPlainText()


# -- the decision -------------------------------------------------------------------------------

def test_sad_quoted_and_entity_tag_names_are_shown_as_written():
    for spelling in TAG_SPELLINGS:
        text = "<b></b>" + spelling + "<tr><td>x"
        assert MG.unvouched(text), repr(spelling)
        out = MG.defuse(text)
        assert out != text and out.startswith("<qt class='axross-defused'"), repr(spelling)
        assert MG.original_of(out) == text
    for spelling in ("<\"img\" src='/dev/zero'>", "<'img' src=&#47;dev&#47;zero>",
                     "<&#105;mg src='/dev/zero'>", "<i&#109;g src='/dev/zero'>"):
        assert MG.defuse("<b></b>" + spelling) != "<b></b>" + spelling, spelling


def test_sad_quoted_attribute_names_comments_and_hiding_tags():
    for text in ('<b></b><span "<"=1 style="letter-spacing:1999px">' + "W" * 200 + "</span>",
                 '<b></b><p "<"=1 style="margin-top:1999px">x</p>' * 12,
                 '<b></b><"table" cellpadding=99999 border=99999><tr><td>x',
                 "<table><tr><td>" * 6 + ("<!---- ></table>-->" + "<table><tr><td>") * 10 + "x",
                 "<b>x</b><!-- -- ></table>-->",
                 "<b>x</b><title>Verified</title>", "<b>x</b><head>", "<b>x</b><script>x",
                 "<b>x</b><unknowntag>", "<b>x</b><b", "<b>x</b> a < b",
                 "<b title='a<b'>x</b>", "<b x=1\"2\">x</b>", "<b b&#97;ckground=x>x</b>"):
        assert MG.unvouched(text), text[:60]
        assert MG.defuse(text) != text, text[:60]
    for text in ("Could not extract report.pdf<br><b>Extracted.</b><\"style\">:\nerror",
                 "Could not extract report.pdf<br><b>Extracted.</b><\"title\">:\nerror",
                 'x<br><b>ok</b> <"a" href="https://evil.example">open</a>'):
        assert MG.defuse_message(text) != text


def test_happy_our_own_rich_text_still_renders():
    for text in ("<b>Bold</b> and <i>italic</i>", "<a href='https://x'>a link</a>",
                 "<a href=https://example.org/a/b?c=d&amp;e=f>x</a>",
                 '<p style="color:#7f8c8d">x<br/>y<br>z</p>', "<TABLE><TR><TD>x</TD></TR></TABLE>",
                 "<qt style='white-space:pre-wrap'>a &lt;b&gt; path</qt>",
                 "<html><body><h3>Title</h3><ul><li>one</li></ul><hr></body></html>",
                 "<span\nstyle='font-weight:600'>x</span >", "plain text", "a < b and c > d", ""):
        assert not MG.unvouched(text), text
        assert MG.defuse(text) == text, text
        assert MG.defuse_message(text.replace("<a ", "<b ")) == text.replace("<a ", "<b ")


def test_edge_non_strings_and_texts_qt_shows_plain_pass():
    assert not MG.unvouched(None)
    assert not MG.unvouched(42)
    # not rich text for Qt: shown plain anyway, left alone
    assert MG.defuse("report <'img'>.zip") == "report <'img'>.zip"
    # a defused text is vouched (re-defusing it changes nothing)
    once = MG.defuse("<b></b><'img' src=x>")
    assert MG.defuse(once) == once


def test_edge_vouching_is_linear():
    import time

    text = "<b>" + "<b x='1' " * 20000 + "x"
    started = time.perf_counter()
    assert MG.unvouched(text)
    assert time.perf_counter() - started < 2.0
    text = "<b>x</b>" * 30000
    started = time.perf_counter()
    assert not MG.unvouched(text)
    assert time.perf_counter() - started < 2.0


# -- widgets ------------------------------------------------------------------------------------

def test_sad_quoted_name_reaches_a_label_as_written():
    text = "Could not extract " + CRASH_NAME
    assert _shown(text) == text


def test_sad_rich_text_widgets_count_every_text_as_rich():
    # Qt.mightBeRichText says no (no known tag first), Qt renders it rich anyway
    text = "Missing tool x <img src='/dev/zero'>"
    label = QLabel()
    label.setTextFormat(Qt.TextFormat.RichText)
    label.setText(text)
    assert label.text() != text and MG.original_of(label.text()) == text
    # ... also when the format is switched after the text was set
    label = QLabel(text)
    label.setTextFormat(Qt.TextFormat.RichText)
    assert label.text() != text and MG.original_of(label.text()) == text
    box = QMessageBox()
    box.setTextFormat(Qt.TextFormat.RichText)
    box.setText("Could not open x<'table'><tr><td>y")
    assert box.text().startswith("<qt class='axross-defused'")


def test_happy_rich_text_label_keeps_its_link():
    label = QLabel()
    label.setTextFormat(Qt.TextFormat.RichText)
    label.setText('Install it <a href="features">Show in Features…</a>')
    assert label.text() == 'Install it <a href="features">Show in Features…</a>'


def test_sad_size_bomb_box_stays_small():
    box = QMessageBox(QMessageBox.Icon.Warning, "Error",
                      "Could not open <b></b><\"table\" cellpadding=99999 border=99999><tr><td>x")
    box.show()
    APP.processEvents()
    assert box.height() < 2000 and box.width() < 4000, (box.width(), box.height())
    box.close()


# -- crash and freeze, in a child with a 3 GiB address space -----------------------------------

def test_sad_extract_error_box_does_not_read_dev_zero():
    """The report's crash: QMessageBox.warning as file_pane shows a failed
    extraction - std::bad_alloc on the old guard."""
    assert_survives(f"""
        from PyQt6.QtCore import QTimer
        from PyQt6.QtWidgets import QLabel, QMessageBox
        name = {CRASH_NAME!r}
        QTimer.singleShot(300, lambda: [w.reject() for w in app.topLevelWidgets()
                                        if isinstance(w, QMessageBox)])
        QMessageBox.warning(None, "Extract Archive",
                            "Could not extract {{name}}:\\n{{error}}".format(name=name, error="bad"))
        for spelling in ("<\\"img\\" src='/dev/zero'>", "<&#105;mg src='/dev/zero'>"):
            label = QLabel("<b></b>" + spelling)
            label.show(); pump()
    """)


def test_sad_quoted_table_bomb_does_not_freeze_a_label():
    """18 nested quoted tables: 37 s on the GUI thread before."""
    import time

    started = time.perf_counter()
    assert_survives("""
        from PyQt6.QtWidgets import QLabel
        name = "<b></b>" + '<"table"><tr><td>' * 18 + "x"
        label = QLabel(name)
        label.show(); pump()
        label.setToolTip("<b></b>" + "<t&#97;ble><tr><td>" * 18 + "x")
    """)
    assert time.perf_counter() - started < 30


def test_edge_extract_failure_message_is_escaped_at_the_call_site():
    """file_pane formats the archive name into the message as written
    (ui.plain_text.as_written), not as markup."""
    source = (ROOT / "ui" / "file_pane.py").read_text(encoding="utf-8")
    at = source.index('tr("Could not extract {name}:\\n{error}")')
    assert "as_written(" in source[at - 80:at]
