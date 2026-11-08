"""No text shown by axross can make Qt read a file it names (ui/markup_guard.py).

``<img src="/dev/zero">`` in a file name, a link target, an FTP server's
error or an LLM's answer made Qt's rich text read /dev/zero until the
process aborted (std::bad_alloc). Found by the second review round: opening
such a folder, the Properties of such a link, a hostile server's login
error, View Media, the Duplicate Index history - and every message box that
shows outside text. The crash cases run in a child with a memory limit: a
regression fails the test instead of taking the test run down.
"""

from __future__ import annotations

import os
import resource
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

import ui  # noqa: E402,F401 - installs the guard
from ui import markup_guard as MG  # noqa: E402

APP = QApplication.instance() or QApplication([])

DEV_ZERO = '<img src="/dev/zero">'


def _limit_memory():  # pragma: no cover - runs in the child
    resource.setrlimit(resource.RLIMIT_AS, (3 << 30, 3 << 30))


def run_child(body: str, *, timeout: float = 90) -> subprocess.CompletedProcess:
    """Run *body* (with a QApplication ``app`` and the ui package imported)
    in a child capped at 3 GiB; reading /dev/zero dies there, quickly."""
    code = textwrap.dedent("""
        import os, sys
        sys.path.insert(0, {root!r})
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PyQt6.QtWidgets import QApplication
        app = QApplication([])
        import ui
        def pump(n=20):
            for _ in range(n):
                app.processEvents()
    """).format(root=str(ROOT)) + textwrap.dedent(body) + "\nprint('SURVIVED', flush=True)\n"
    return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                          timeout=timeout, preexec_fn=_limit_memory, cwd=str(ROOT))


def assert_survives(body: str) -> str:
    out = run_child(body)
    assert "SURVIVED" in out.stdout, (
        f"the child died (rc {out.returncode}):\n{out.stdout[-2000:]}\n{out.stderr[-2000:]}")
    return out.stdout


# -- the decision ---------------------------------------------------------------------------

def test_happy_our_own_rich_text_is_left_as_it_is():
    for text in ("<b>Bold</b> and <i>italic</i>", "<a href='https://x'>a link</a>",
                 "<qt style='white-space:pre-wrap'>a &lt;b&gt; path</qt>", "plain text",
                 "a < b and c > d", ""):
        assert MG.defuse(text) == text


def test_sad_text_that_loads_a_resource_is_shown_as_written():
    for text in (DEV_ZERO, "<IMG SRC=/proc/kcore>", "x <img width=4000 height=4000 src=x>",
                 "<table background='/dev/zero'><tr><td>x</td></tr></table>",
                 "<p style=\"background-image: url(/dev/zero)\">x</p>"):
        out = MG.defuse(text)
        assert out != text and "&lt;" in out
        doc_text = _rendered(out)
        assert doc_text.strip() == text.strip(), (text, doc_text)


def _rendered(rich: str) -> str:
    from PyQt6.QtGui import QTextDocument

    doc = QTextDocument()
    doc.setHtml(rich)
    return doc.toPlainText()


def test_edge_non_strings_and_plain_looking_text_pass_through():
    assert MG.defuse(None) is None
    assert MG.defuse(42) == 42
    # names the word background without being markup: not rich text, untouched
    assert MG.defuse("background: url(x) in a CSS file name") == \
        "background: url(x) in a CSS file name"


# -- layout bombs: rich text that loads nothing but asks for an absurd size ------------------

LAYOUT_BOMBS = (
    "<table width=40000><tr><td>x</td></tr></table>",
    "<table WIDTH = '40000'><tr><td>x</td></tr></table>",
    "<table><tr><td width=40000>x</td></tr></table>",
    "<table height=40000><tr><td>x</td></tr></table>",
    "<table cellpadding=40000><tr><td>x</td></tr></table>",
    "<table cellspacing=40000><tr><td>x</td></tr></table>",
    "<table border=40000><tr><td>x</td></tr></table>",
    "<table><tr><td colspan=100000>x</td></tr></table>",
    "<table width=&#52;0000><tr><td>x</td></tr></table>",  # Qt decodes the entity
    "<table title='a>b' width=40000><tr><td>x</td></tr></table>",
    "<hr width=40000>",
    "<font size=1000>x</font>",
    '<p style="font-size:4000px">x</p>',
    '<span style="font-size:4000pt">x</span>',
    "<p style='font-size:4e4px'>x</p>",
    "<p style='font: bold 40000px serif'>x</p>",
    "<p style='font-size:40000%'>x</p>",
    '<p style="margin-left:40000px">x</p>',
    "<p style='MARGIN-LEFT:2000em'>x</p>",
    '<p style="text-indent:40000px">x</p>',
    '<p style="line-height:40000px">x</p>',
    "<p style='line-height:40000'>x</p>",
    '<p style="letter-spacing:4000px">xx</p>',
    '<p style="word-spacing:40000px">x y</p>',
    '<p style="-qt-block-indent:1000">x</p>',
    "<ul style='-qt-list-indent:1000'><li>x</li></ul>",
    "<table style='border:40000px solid'><tr><td>x</td></tr></table>",
    "<td style='padding-left:40000px'>x",
    "<html><head><style>p { margin-left: 40000px }</style></head><body><p>x</p></body></html>",
    "<blockquote>" * 40 + "x",
    "<ol>" * 40 + "<li>x",
    "<table><tr><td>" * 14 + "x",
    "<table><tr>" + "<td>x</td>" * 1200 + "</tr></table>",
)


def test_sad_a_layout_bomb_is_shown_as_written():
    """A huge width, height, border, font, indent or span, tables or lists
    nested too deep: shown as the text it is, not laid out."""
    for text in LAYOUT_BOMBS:
        assert MG.bombs_layout(text), text
        out = MG.defuse(text)
        assert out != text and "&lt;" in out, text
        assert _rendered(out).strip() == text.strip(), text


def test_happy_our_own_sizes_and_nesting_are_left_as_they_are():
    """What axross' own rich texts use - percentages, a few pixels, a
    table in a table, a list in a list - renders as before; a big number
    in the text shown (not in markup) is not a size."""
    for text in ("<table width=\"100%\" cellspacing=\"0\" cellpadding=\"3\"><tr>"
                 "<td valign=\"top\" width=\"32%\">a</td><td colspan=\"2\" "
                 "style=\"padding-top:10px\">b</td></tr></table>",
                 "<h3 style='margin:2px 0;'>Title</h3><p style=\"color:#888\">x</p>",
                 "<p style='font-size:14px; font-weight:700; line-height:120%'>x</p>",
                 "<span style='font: bold 12pt sans-serif'>x</span>",
                 "<qt style='white-space:pre-wrap'>a &lt;b&gt; path</qt>",
                 "<table><tr><td><table><tr><td>x</td></tr></table></td></tr></table>",
                 "<ul><li>a<ul><li>b<ul><li>c</li></ul></li></ul></li></ul>",
                 "<blockquote>q</blockquote>" * 40,  # many, one after the other
                 "<b>Size</b>: width=40000, font-size: 4000px",
                 "<table><tr>" + "<td>x</td>" * 300 + "</tr></table>",
                 "<hr width=100%>",
                 # a name with a bomb in it, escaped into our own rich text
                 "<qt style='white-space:pre-wrap'>&lt;table width=40000&gt;</qt>"):
        assert not MG.bombs_layout(text), text
        assert MG.defuse(text) == text, text
    for bomb in LAYOUT_BOMBS:  # defused once is defused for good
        assert MG.defuse(MG.defuse(bomb)) == MG.defuse(bomb)
    assert MG.defuse("width=40000 in a plain name") == "width=40000 in a plain name"


def test_e2e_a_layout_bomb_keeps_labels_and_tooltips_small():
    """Set on a label or as a tooltip, a layout bomb keeps the size a few
    words take - not tens of thousands of pixels - and nested tables lay
    out at once instead of doubling the time per level (14 took seconds)."""
    import time

    from PyQt6.QtWidgets import QLabel

    from tests.markup_probe import tooltip_width

    for text in (b for b in LAYOUT_BOMBS if len(b) < 120):  # nested ones: long as text
        label = QLabel()
        label.setWordWrap(True)
        label.setText(text)
        hint = label.sizeHint()
        assert hint.width() < 1500 and hint.height() < 500, (text, hint)
        assert tooltip_width(text) < 1500, text
    started = time.monotonic()
    label = QLabel()
    label.setText("<table><tr><td>" * 14 + "x")
    label.sizeHint()
    assert time.monotonic() - started < 2.0


# -- the wrappers, in this process (harmless payload) ---------------------------------------

WIDE = "<img width=4000 height=4000 src=nothing-here>"


def test_happy_labels_tooltips_and_boxes_get_the_defused_text():
    from PyQt6.QtGui import QAction, QStandardItem
    from PyQt6.QtWidgets import (
        QComboBox,
        QLabel,
        QListWidgetItem,
        QMessageBox,
        QTableWidgetItem,
        QTabWidget,
        QTreeWidgetItem,
        QWidget,
    )

    label = QLabel(WIDE)
    assert "&lt;img" in label.text()
    label.setText(WIDE)
    assert "&lt;img" in label.text()
    plain = QLabel()
    plain.setTextFormat(Qt.TextFormat.PlainText)
    plain.setText(WIDE)
    assert plain.text() == WIDE  # shown as text anyway: left exactly as given
    widget = QWidget()
    widget.setToolTip(WIDE)
    assert "&lt;img" in widget.toolTip()
    action = QAction("x")
    action.setToolTip(WIDE)
    assert "&lt;img" in action.toolTip()
    for item, get in ((QListWidgetItem("x"), lambda i: i.toolTip()),
                      (QTableWidgetItem("x"), lambda i: i.toolTip()),
                      (QStandardItem("x"), lambda i: i.toolTip())):
        item.setToolTip(WIDE)
        assert "&lt;img" in get(item)
    tree = QTreeWidgetItem(["x"])
    tree.setToolTip(0, WIDE)
    assert "&lt;img" in tree.toolTip(0)
    tree.setData(0, Qt.ItemDataRole.ToolTipRole, WIDE)
    assert "&lt;img" in tree.toolTip(0)
    combo = QComboBox()
    combo.addItem("x")
    combo.setItemData(0, WIDE, Qt.ItemDataRole.ToolTipRole)
    assert "&lt;img" in combo.itemData(0, Qt.ItemDataRole.ToolTipRole)
    tabs = QTabWidget()
    tabs.addTab(QWidget(), "t")
    tabs.setTabToolTip(0, WIDE)
    assert "&lt;img" in tabs.tabToolTip(0)
    box = QMessageBox(QMessageBox.Icon.Warning, "t", WIDE)
    assert "&lt;img" in box.text()
    box.setInformativeText(WIDE)
    assert "&lt;img" in box.informativeText()
    box.deleteLater()


def test_edge_a_label_switched_to_plain_text_shows_the_original_again():
    """QLabel(text) then setTextFormat(PlainText) - the text was defused while
    the format was AutoText; plain text shows it as written."""
    from PyQt6.QtWidgets import QLabel, QMessageBox

    label = QLabel(WIDE)
    label.setTextFormat(Qt.TextFormat.PlainText)
    assert label.text() == WIDE
    box = QMessageBox(QMessageBox.Icon.Warning, "t", "x: " + WIDE)
    box.setInformativeText(WIDE)
    box.setTextFormat(Qt.TextFormat.PlainText)
    assert box.text() == "x: " + WIDE and box.informativeText() == WIDE
    box.deleteLater()
    assert MG.original_of("<qt style='white-space:pre-wrap'>a &lt;b&gt;</qt>") == \
        "<qt style='white-space:pre-wrap'>a &lt;b&gt;</qt>"  # only our own marker


def test_happy_a_text_view_still_shows_a_real_local_image(tmp_path):
    from PyQt6.QtGui import QImage, QTextDocument
    from PyQt6.QtCore import QUrl
    from PyQt6.QtWidgets import QTextBrowser

    picture = tmp_path / "pic.png"
    image = QImage(7, 5, QImage.Format.Format_ARGB32)
    image.fill(0xFF00FF00)
    assert image.save(str(picture))
    view = QTextBrowser()
    loaded = view.loadResource(QTextDocument.ResourceType.ImageResource.value,
                               QUrl.fromLocalFile(str(picture)))
    assert loaded is not None and not loaded.isNull()
    size = (loaded.width(), loaded.height()) if isinstance(loaded, QImage) \
        else (QImage.fromData(loaded).width(), QImage.fromData(loaded).height())
    assert size == (7, 5)


def test_sad_a_text_view_refuses_devices_fifos_and_huge_files(tmp_path, monkeypatch):
    from PyQt6.QtCore import QUrl
    from PyQt6.QtGui import QImage, QTextDocument
    from PyQt6.QtWidgets import QTextEdit

    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    big = tmp_path / "big.png"
    big.write_bytes(b"\0" * 2048)
    monkeypatch.setattr(MG, "MAX_IMAGE_BYTES", 1024)
    view = QTextEdit()
    for target in ("/dev/zero", str(fifo), str(big)):
        got = view.loadResource(QTextDocument.ResourceType.ImageResource.value,
                                QUrl.fromLocalFile(target))
        assert isinstance(got, QImage) and (got.width(), got.height()) == (1, 1), target


# -- the crash cases, each in a child -------------------------------------------------------

def test_e2e_every_entry_point_survives_dev_zero():
    assert_survives(f"""
        from PyQt6.QtCore import QPoint, Qt
        from PyQt6.QtGui import QStandardItem, QStandardItemModel
        from PyQt6.QtWidgets import (QLabel, QMessageBox, QTextBrowser, QTextEdit, QToolTip,
                                     QTreeWidget, QTreeWidgetItem, QWidget)
        P = {DEV_ZERO!r}
        label = QLabel("Could not open " + P); label.show(); pump()
        label.setText("Loading " + P + "…"); pump()
        w = QWidget(); w.setToolTip(P); w.show(); pump()
        QToolTip.showText(QPoint(5, 5), P); pump()
        box = QMessageBox(QMessageBox.Icon.Warning, "t", "530 " + P); box.show(); pump()
        box.setInformativeText(P); pump(); box.close()
        tree = QTreeWidget(); item = QTreeWidgetItem(["x"]); item.setToolTip(0, P)
        tree.addTopLevelItem(item); tree.show(); pump()
        for cls in (QTextEdit, QTextBrowser):
            v = cls(); v.setHtml("<p>" + P + "</p>"); v.show(); pump()
            v.setMarkdown("![x](/dev/zero)"); pump()
        from PyQt6.QtCore import QTimer
        QTimer.singleShot(300, lambda: [b.close() for b in app.topLevelWidgets()
                                        if isinstance(b, QMessageBox)])
        QMessageBox.critical(None, "Connection Failed", "530 " + P)
    """)


def test_e2e_opening_a_folder_named_markup_survives(tmp_path):
    folder = tmp_path / "<img src=" / "dev" / "zero>"
    folder.mkdir(parents=True)
    assert_survives(f"""
        import time
        from core.local_fs import LocalFS
        from ui.file_pane import FilePaneWidget
        pane = FilePaneWidget(LocalFS()); pane.resize(800, 500); pane.show(); pump()
        pane.navigate_async({str(tmp_path / '<img src=/dev/zero>')!r}); pump()
        assert pane.minimumSizeHint().width() < 2000, pane.minimumSizeHint().width()
        end = time.time() + 2
        while time.time() < end:
            pump(1); time.sleep(0.01)
    """)


def test_e2e_properties_of_a_markup_link_survive(tmp_path):
    link = tmp_path / "crash"
    os.symlink(DEV_ZERO, link)
    assert_survives(f"""
        from core.local_fs import LocalFS
        from ui.properties_dialog import PropertiesDialog
        fs = LocalFS()
        item = next(i for i in fs.list_dir({str(tmp_path)!r}) if i.name == "crash")
        dialog = PropertiesDialog(fs, {str(link)!r}, item)
        dialog.show(); pump()
    """)


def test_e2e_an_llm_answer_with_an_image_survives_the_transcript():
    assert_survives(f"""
        from PyQt6.QtWidgets import QTextBrowser
        view = QTextBrowser()
        view.setMarkdown("Here you go: ![x](/dev/zero) and " + {DEV_ZERO!r})
        view.show(); pump()
    """)


# -- review round 3: style sheets and character references ----------------------------------

STYLE_SHEET_TEXTS = (
    '<link rel="stylesheet" type="text/css" href="FILE"><b>topic</b>',
    '<style>@import "FILE";</style><b>topic</b>',
    '<p style="background-image:u&#114;l(FILE)">topic</p>',
    '<table b&#97;ckground="FILE"><tr><td>x</td></tr></table>',
    '<p style="background:\\75rl(FILE)">topic</p>',
)


@pytest.mark.parametrize("template", STYLE_SHEET_TEXTS)
def test_sad_style_sheets_and_encoded_attributes_are_shown_as_written(template):
    """The guard knew <img, background and url( only: ``<link
    rel=stylesheet>``, ``<style>@import``, and attributes written with
    character references (``b&#97;ckground=``, ``u&#114;l(``) passed, and
    Qt read the file they name (/dev/zero: the process died)."""
    text = template.replace("FILE", "/dev/zero")
    out = MG.defuse(text)
    assert out != text and _rendered(out).strip() == text.strip()


@pytest.mark.parametrize("template", STYLE_SHEET_TEXTS[:4])
def test_sad_qt_opens_no_file_a_defused_label_names(template, tmp_path):
    """End to end: the text in a QLabel (AutoText) - a FIFO stands for the
    file, and a writer process notes whether Qt opened it."""
    from PyQt6.QtWidgets import QLabel

    fifo = tmp_path / "f.css"
    os.mkfifo(fifo)
    marker = tmp_path / "opened"
    writer = subprocess.Popen([sys.executable, "-I", "-c",
                               "import sys;f=open(sys.argv[1],'wb');open(sys.argv[2],'w').close();"
                               "f.write(b'p{}');f.close()", str(fifo), str(marker)])
    try:
        QLabel(template.replace("FILE", str(fifo))).sizeHint()
        try:
            writer.wait(0.5)  # the writer ends at once when Qt opened the FIFO
        except subprocess.TimeoutExpired:
            pass
        assert not marker.exists()
    finally:
        writer.kill()
        writer.wait()


def test_happy_plain_text_made_rich_is_left_as_it_is():
    """Qt.convertFromPlainText of a text naming url( or @import loads
    nothing (the words are text, not a tag): it is not defused."""
    for text in ('see url(/dev/zero) and @import "x"', 'background: red; <style> is escaped'):
        rich = Qt.convertFromPlainText(text)
        assert MG.defuse(rich) == rich


def test_e2e_an_irc_topic_with_a_style_sheet_survives_its_tooltip():
    """An IRC server's 332 topic ``<style>@import "/dev/zero";</style>``
    became the topic label's tooltip as it came; hovering it made Qt read
    /dev/zero until the process died. It is shown as plain text now."""
    out = assert_survives("""
        import asyncio
        from PyQt6.QtCore import QPoint, Qt
        from PyQt6.QtWidgets import QToolTip
        import core.chat as C, core.chat_irc as I
        from ui.chat_panel import ConversationView
        acc = C.Account(protocol="irc", name="t", settings={"server": "127.0.0.1", "port": 1,
                        "tls": I.TLS_OFF, "nick": "alice", "proxy": "none"})
        c = I.IrcClient(acc)
        c._add_conversation("#c", C.CONV_CHANNEL, "#c")
        topic = '<style>@import "/dev/zero";</style>Welcome'
        asyncio.run(c._on_332(I.parse_line(f":srv 332 alice #c :{topic}\\r\\n")))
        view = ConversationView(c, "#c"); view.show(); pump()
        print("PLAIN", view.topic.toolTip() == Qt.convertFromPlainText(topic), flush=True)
        QToolTip.showText(QPoint(5, 5), view.topic.toolTip(), view.topic); pump()
        c.runner.stop()
    """)
    assert "PLAIN True" in out
