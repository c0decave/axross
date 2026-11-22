"""The Markdown viewer window as a reader (ui.markdown_viewer, ui.markdown_view):

* links open in the same window - another Markdown file at the heading its
  ``#fragment`` names, a folder's README, a text file as its text, an image
  at its own size - and Back / Forward go through the places visited;
* a file changed on disk is shown anew where it was scrolled to (also when
  an editor saves by renaming a new file over it);
* find marks every match and says which one of how many;
* export to HTML (images in it) and PDF; the copy printed loads nothing itself;
* the outline names long headings whole in a tooltip and marks the heading
  being read; the text keeps a readable width; code blocks can be copied;
  images fit the width as it changes, a click shows one at its own size; a
  theme chosen since is taken.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
pytest.importorskip("markdown_it", reason="markdown-it-py not installed")

from PyQt6 import sip  # noqa: E402
from PyQt6.QtCore import QCoreApplication, QEvent, QUrl  # noqa: E402
from PyQt6.QtGui import QColor, QImage, QPalette  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from ui import markdown_view as MV  # noqa: E402
from tests import markdown_timing as TB  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)


def wait_until(predicate, timeout: float = 60.0) -> bool:  # (a wait, not a budget: it returns when true)
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if predicate():
            return True
        time.sleep(0.01)
    return bool(predicate())


def _png(path: Path, width: int = 40, height: int = 30) -> None:
    image = QImage(width, height, QImage.Format.Format_RGB32)
    image.fill(QColor("red"))
    assert image.save(str(path), "PNG")


@pytest.fixture
def site(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "empty").mkdir()
    lines = ["# Start", "", "[other](other.md#second-part) [lic](LICENSE) [sub](sub) [empty](empty) "
             "[pic](pic.png) [bin](data.bin) [py](tool.py) [key](key.txt) [here](#later)", ""]
    lines += [f"para {n}\n" for n in range(80)]
    lines += ["## Later", "", "text", "", "```python", "def f():", "    return 1", "```", ""]
    (tmp_path / "index.md").write_text("\n".join(lines))
    (tmp_path / "other.md").write_text("# Other\n\n" + "".join(f"line {n}\n\n" for n in range(120))
                                       + "## Second part\n\nhere\n\n" + "".join(f"tail {n}\n\n" for n in range(60)))
    (tmp_path / "LICENSE").write_text("MIT License\n\nCopyright 2026\n")
    (tmp_path / "sub" / "README.md").write_text("# Sub readme\n")
    (tmp_path / "data.bin").write_bytes(b"\x00\x01\x02" * 100)
    (tmp_path / "tool.py").write_text("def x():\n    return 2\n")
    (tmp_path / "key.txt").write_text("not really\n")
    _png(tmp_path / "pic.png", 300, 200)
    return tmp_path


def _viewer(path: Path, width: int = 900, height: int = 600):
    from ui.markdown_viewer import MarkdownViewerDialog

    viewer = MarkdownViewerDialog(LocalFS(), str(path))
    viewer.resize(width, height)
    viewer.show()
    assert wait_until(lambda: viewer.loaded_once)
    # (and laid out: a page with fenced code is prepared on a worker that waits for its lexing child - on a
    # busy machine a child's start alone took longer than the pump, the page empty when the test scrolled)
    wait_until(lambda: viewer.view._readable and not viewer.view._scheduled, 30)
    pump(0.1)
    return viewer


def _close(viewer) -> None:
    if not sip.isdeleted(viewer):
        viewer.close()
        viewer.deleteLater()
    pump()


def _scroll(viewer) -> int:
    return viewer.view.browser.verticalScrollBar().value()


# -- links and history --------------------------------------------------------------------------

def test_happy_a_link_with_a_fragment_opens_there_in_this_window_and_back_returns(site):
    viewer = _viewer(site / "index.md")
    try:
        viewer.view.browser.verticalScrollBar().setValue(300)
        viewer.follow(QUrl("other.md#second-part"))
        assert wait_until(lambda: viewer.path == str(site / "other.md") and viewer.view.headings()
                          == ["Other", "Second part"])
        assert wait_until(lambda: _scroll(viewer) > 1000)  # (at "Second part", not at the top)
        top = viewer.view.browser.cursorForPosition(viewer.view.browser.viewport().rect().topLeft())
        assert "Second part" in top.block().text() or top.block().text().startswith(("here", "line 1"))
        assert viewer.back()
        assert wait_until(lambda: viewer.path == str(site / "index.md") and _scroll(viewer) == 300)
        assert viewer.forward()
        assert wait_until(lambda: viewer.path == str(site / "other.md") and _scroll(viewer) > 1000)
        assert viewer.windowTitle().startswith("other.md")
    finally:
        _close(viewer)


def test_happy_an_anchor_jump_is_remembered_and_alt_left_returns(site):
    viewer = _viewer(site / "index.md")
    try:
        assert _scroll(viewer) == 0 and not viewer.back_button.isEnabled()
        viewer.view.clicked(QUrl("#later"))
        assert _scroll(viewer) > 0 and viewer.back_button.isEnabled()
        assert viewer.view.back() and _scroll(viewer) == 0
        assert viewer.view.forward() and _scroll(viewer) > 0
    finally:
        _close(viewer)


def test_happy_text_files_folders_and_images_open_others_are_named(site, monkeypatch):
    viewer = _viewer(site / "index.md")
    try:
        viewer.follow(QUrl("LICENSE"))
        assert wait_until(lambda: viewer.shown_as == "text" and "MIT License" in viewer.view.browser.toPlainText())
        assert viewer.path == str(site / "LICENSE")
        viewer.back()
        assert wait_until(lambda: viewer.shown_as == "markdown" and viewer.view.headings()[:1] == ["Start"])
        viewer.follow(QUrl("tool.py"))
        assert wait_until(lambda: "def x():" in viewer.view.browser.toPlainText())
        assert "python" in viewer.view.browser.toPlainText()  # (its language named)
        viewer.back()
        viewer.follow(QUrl("sub"))
        assert wait_until(lambda: viewer.path == str(site / "sub" / "README.md"))
        viewer.back()
        assert wait_until(lambda: viewer.path == str(site / "index.md"))
        for link, why in (("empty", "a folder without a README"), ("data.bin", "not a text file"),
                          ("missing.txt", "Cannot read")):
            viewer.follow(QUrl(link))
            assert wait_until(lambda why=why: why in viewer.view.status.text()), link
            assert viewer.path == str(site / "index.md")
        from core import protected_places

        monkeypatch.setattr(protected_places, "read_refusal",
                            lambda path, **kw: "secret" if path.endswith("key.txt") else None)
        viewer.follow(QUrl("key.txt"))
        assert wait_until(lambda: "a secret file" in viewer.view.status.text())
        shown = []
        monkeypatch.setattr(MV.ImageZoom, "show", lambda self: shown.append(self))
        viewer.follow(QUrl("pic.png"))
        assert wait_until(lambda: shown) and shown[0].image.width() == 300
    finally:
        _close(viewer)


# -- changes on disk ----------------------------------------------------------------------------

def test_happy_a_file_changed_on_disk_is_shown_anew_where_it_was(site):
    viewer = _viewer(site / "other.md")
    try:
        viewer.view.browser.verticalScrollBar().setValue(500)
        text = (site / "other.md").read_text().replace("line 3\n", "line three\n")
        (site / "other.md").write_text(text)
        assert TB.until_within(wait_until, lambda: "line three" in viewer.view.browser.toPlainText(), 8)
        assert _scroll(viewer) == 500
        # (said once the page is made: "Rendering…" stays meanwhile)
        assert TB.until_within(wait_until, lambda: "changed on disk" in viewer.view.status.text(), 8)
        # An editor that writes a new file and renames it over the old one.
        (site / "new.tmp").write_text(text.replace("line three", "line THREE"))
        os.replace(site / "new.tmp", site / "other.md")
        assert TB.until_within(wait_until, lambda: "line THREE" in viewer.view.browser.toPlainText(), 8)
        (site / "new.tmp").write_text(text.replace("line three", "line 3!"))
        os.replace(site / "new.tmp", site / "other.md")
        assert TB.until_within(wait_until, lambda: "line 3!" in viewer.view.browser.toPlainText(), 8)
    finally:
        _close(viewer)


# -- find ---------------------------------------------------------------------------------------

def test_happy_find_marks_every_match_and_counts_them(site):
    viewer = _viewer(site / "index.md")
    try:
        viewer.find_field.setText("para 7")  # para 7, para 70 ... para 79: eleven
        assert wait_until(lambda: viewer.find_count.text() == "1 of 11")
        assert len(viewer.view.browser.extraSelections()) == 11
        assert viewer.find_next() and viewer.find_count.text() == "2 of 11"
        assert viewer.find_next(backward=True) and viewer.find_count.text() == "1 of 11"
        assert viewer.find_next(backward=True) and viewer.find_count.text() == "11 of 11"  # (round)
        viewer.find_field.setText("para 7x")
        assert wait_until(lambda: viewer.find_count.text() == "no match")
        assert "Not found" in viewer.view.status.text()
        viewer.end_find()
        assert viewer.view.browser.extraSelections() == [] and viewer.find_count.text() == ""
    finally:
        _close(viewer)


# -- export -------------------------------------------------------------------------------------

def test_happy_export_html_puts_the_images_in_and_pdf_is_written(site, tmp_path):
    (site / "page.md").write_text("# Page\n\n![pic](pic.png) ![far](https://tracker.example/t.png)\n\n"
                                  "> [!NOTE]\n> n\n")
    viewer = _viewer(site / "page.md")
    try:
        assert wait_until(lambda: isinstance(viewer.view.originals.get("pic.png"), QImage))
        out = tmp_path / "out" / "page.html"
        out.parent.mkdir()
        assert viewer.export_html(str(out)) == str(out)
        page = out.read_text()
        assert '<img src="data:image/png;base64,' in page and 'alt="pic"' in page
        assert "Content-Security-Policy" in page and '<img src="https://tracker.example' not in page
        assert "markdown-alert-note" in page and "<title>page.md</title>" in page
        pdf = tmp_path / "page.pdf"
        assert viewer.export_pdf(str(pdf)) == str(pdf)
        assert pdf.read_bytes().startswith(b"%PDF-") and "Saved" in viewer.view.status.text()
        assert viewer.export_html(str(tmp_path / "missing" / "x.html")) == ""
        assert "Export failed" in viewer.view.status.text()
    finally:
        _close(viewer)


def test_sad_the_copy_printed_reads_no_file_itself(site, monkeypatch):
    """A QTextDocument of its own reads a local file an image names; the copy
    to print asks the view, as the page does."""
    view = MV.MarkdownView(MV.ImageSource(LocalFS(), str(site / "index.md")))
    view.resize(800, 600)
    view.show()
    try:
        view.render("![a](/etc/hostname) ![b](pic.png)\n")
        asked = []
        real = view.image
        monkeypatch.setattr(view, "image", lambda name: asked.append(name) or real(name))
        copy = view.print_document()
        copy.documentLayout()  # (laid out: its images asked for)
        copy.adjustSize()
        assert set(asked) >= {"/etc/hostname", "pic.png"}
        assert "#0969da" in copy.defaultStyleSheet()  # (the light colours: paper is white)
        copy.deleteLater()
    finally:
        view.deleteLater()
        pump()


# -- the view -----------------------------------------------------------------------------------

def test_happy_the_outline_names_long_headings_and_marks_the_one_being_read(site):
    long = "A heading far too long for the outline " * 4
    (site / "long.md").write_text(f"# {long}\n\n" + "".join(f"p {n}\n\n" for n in range(100))
                                  + "## End\n\n" + "".join(f"q {n}\n\n" for n in range(100)))
    viewer = _viewer(site / "long.md")
    try:
        outline = viewer.view.outline
        assert outline.item(0).toolTip() == long.strip()
        assert outline.horizontalScrollBarPolicy().name == "ScrollBarAlwaysOff"
        bar = viewer.view.browser.verticalScrollBar()
        bar.setValue(bar.maximum())
        assert wait_until(lambda: outline.currentRow() == 1)
        bar.setValue(0)
        assert wait_until(lambda: outline.currentRow() == 0)
    finally:
        _close(viewer)


def test_happy_the_text_keeps_a_readable_width_and_code_blocks_copy(site):
    viewer = _viewer(site / "index.md", width=2400)
    try:
        view = viewer.view
        assert wait_until(lambda: view.browser.margins()[0] > 200)  # (the view's margins: fit_text)
        position = view.browser.document().find("return 1").position()
        assert view.code_block_at(position) == "def f():\n    return 1\n"
        assert view.code_block_at(view.browser.document().find("para 3").position()) == ""
    finally:
        _close(viewer)


def test_happy_images_fit_the_width_as_it_changes_and_a_click_shows_one_whole(site):
    _png(site / "wide.png", 1500, 100)
    (site / "wide.md").write_text("# Wide\n\n![w](wide.png)\n")
    viewer = _viewer(site / "wide.md", width=600)
    try:
        view = viewer.view
        assert wait_until(lambda: isinstance(view.images.get("wide.png"), QImage)
                          and view.images["wide.png"].width() <= view.room())
        narrow = view.images["wide.png"].width()
        viewer.resize(1400, 600)
        assert wait_until(lambda: view.images["wide.png"].width() > narrow)
        assert view.images["wide.png"].width() <= view.room()
        zoom = view.zoom_image("wide.png")
        assert zoom.image.width() == 1500 and zoom.windowTitle().endswith("wide.png")
        zoom.zoom(2.0)
        assert zoom.label.pixmap().width() == 3000
        zoom.close()
        assert view.zoom_image("missing.png") is None
    finally:
        _close(viewer)


def test_happy_a_theme_chosen_since_is_taken(site):
    viewer = _viewer(site / "index.md")
    try:
        view = viewer.view
        light = QPalette(view.palette())  # (whatever palette an earlier test left: light first)
        light.setColor(QPalette.ColorRole.Base, QColor("#ffffff"))
        light.setColor(QPalette.ColorRole.Window, QColor("#f0f0f0"))
        light.setColor(QPalette.ColorRole.Text, QColor("#000000"))
        view.setPalette(light)
        assert wait_until(lambda: "#0969da" in view.browser.document().defaultStyleSheet())
        dark = QPalette(view.palette())
        dark.setColor(QPalette.ColorRole.Base, QColor("#101010"))
        dark.setColor(QPalette.ColorRole.Window, QColor("#202020"))
        dark.setColor(QPalette.ColorRole.Text, QColor("#eeeeee"))
        view.setPalette(dark)
        assert wait_until(lambda: "#4493f8" in view.browser.document().defaultStyleSheet())
    finally:
        _close(viewer)


def test_edge_the_cells_laid_out_at_once_follow_the_parser_that_lays_them_out():
    """Qt's own parser takes about twice as long a cell as markdown-it's
    HTML: its parts of a big table are smaller (ui.markdown_view.TABLE_CELLS)."""
    rows = MV.MD4C_TABLE_CELLS + 100
    table = "| a |\n|---|\n" + "".join(f"| {n} |\n" for n in range(rows))
    assert MV.renderable(table, rows + 1) == (table, "")
    part, why = MV.renderable(table, MV.MD4C_TABLE_CELLS)
    # (three parts, laid out one after the other: the first a quarter as long - the page's first part)
    assert not why and part.count(MV.CHUNK) == 2
    first, second = part.split(MV.CHUNK)[:2]
    assert first.count("\n| ") == (MV.MD4C_TABLE_CELLS - 1) // 4
    assert second.count("\n| ") == MV.MD4C_TABLE_CELLS - 1  # (a full part after it, its header again)


# -- keyboard -----------------------------------------------------------------------------------

def test_sad_enter_in_the_text_or_the_find_field_presses_no_button(site):
    """A QDialog presses its default button on Enter: in the text that
    toggled the outline (later: went Back), whatever was read."""
    from PyQt6.QtCore import Qt
    from PyQt6.QtTest import QTest
    from PyQt6.QtWidgets import QPushButton

    viewer = _viewer(site / "index.md")
    try:
        pressed = []
        for button in viewer.findChildren(QPushButton):
            button.clicked.connect(lambda _checked=False, b=button: pressed.append(b.text()))
        viewer.view.clicked(QUrl("#later"))
        where = _scroll(viewer)
        viewer.view.browser.setFocus()
        QTest.keyClick(viewer.view.browser, Qt.Key.Key_Return)
        viewer.find_field.setFocus()
        viewer.find_field.setText("para")
        QTest.keyClick(viewer.find_field, Qt.Key.Key_Return)
        pump(0.2)
        assert pressed == [] and viewer.outline_button.isChecked() and viewer.path == str(site / "index.md")
        assert _scroll(viewer) != 0 or where == 0
        assert not any(button.isDefault() or button.autoDefault() for button in viewer.findChildren(QPushButton))
    finally:
        _close(viewer)


def test_happy_the_text_has_the_focus_when_the_window_opens(site):
    """Space, Page Down, the arrows scroll the text at once (the focus was on
    a tool button: Space opened its menu)."""
    viewer = _viewer(site / "index.md")
    try:
        viewer.activateWindow()
        assert wait_until(lambda: QApplication.focusWidget() is viewer.view.browser)
    finally:
        _close(viewer)


# -- bounds -------------------------------------------------------------------------------------

def test_sad_zooming_an_image_never_makes_a_picture_of_gigapixels():
    image = QImage(4000, 3000, QImage.Format.Format_RGB32)
    image.fill(QColor("blue"))
    zoom = MV.ImageZoom(image, "big.png")
    try:
        for _step in range(12):
            zoom.zoom(1.25)
        pixmap = zoom.label.pixmap()
        assert pixmap.width() * pixmap.height() <= MV.ZOOM_PIXELS
        assert pixmap.width() > 4000  # (larger than its size: up to the bound)
    finally:
        zoom.deleteLater()
        pump()


def test_sad_an_image_of_a_given_size_is_read_too(site):
    """Qt lays out an image whose width and height are given without asking
    for it: it asked only when painting - after the rendering had read what
    was asked - and the image said "Reading…" for ever."""
    (site / "sized.md").write_text('<img src="pic.png" width="120" height="80">\n')
    viewer = _viewer(site / "sized.md")
    try:
        assert wait_until(lambda: isinstance(viewer.view.images.get("pic.png"), QImage)
                          and viewer.view.images["pic.png"].width() == 300)
    finally:
        _close(viewer)


def test_sad_an_html_image_asked_wider_than_the_view_fits_it(site):
    _png(site / "logo.png", 300, 100)
    (site / "logo.md").write_text('<p align="center"><img src="logo.png" width="2000" height="600"></p>\n\ntext\n')
    viewer = _viewer(site / "logo.md", width=700)
    try:
        view = viewer.view
        assert wait_until(lambda: isinstance(view.images.get("logo.png"), QImage))
        pump(0.3)
        assert view.browser.horizontalScrollBar().maximum() == 0
        widths = []
        block = view.browser.document().begin()
        while block.isValid():
            it = block.begin()
            while not it.atEnd():
                fmt = it.fragment().charFormat()
                if fmt.isImageFormat():
                    widths.append((fmt.toImageFormat().width(), fmt.toImageFormat().height()))
                it += 1
            block = block.next()
        assert widths and all(0 < w <= view.room() for w, _h in widths)
        assert abs(widths[0][0] / widths[0][1] - 2000 / 600) < 0.05  # (in proportion)
    finally:
        _close(viewer)


def test_happy_a_link_to_a_heading_is_copied_as_github_writes_it(site):
    (site / "dup.md").write_text("# Intro\n\n## Setup\n\n## Setup\n")
    viewer = _viewer(site / "dup.md")
    try:
        outline = viewer.view.outline
        links = [viewer.view.heading_link(outline.item(n)) for n in range(outline.count())]
        assert links == ["dup.md#intro", "dup.md#setup", "dup.md#setup-1"]
        viewer.follow(QUrl("dup.md#setup-1"))  # (the link copied leads there)
        assert viewer.back_list and viewer.path == str(site / "dup.md")
    finally:
        _close(viewer)
