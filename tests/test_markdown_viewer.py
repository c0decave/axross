"""The Markdown viewer (ui.markdown_view, ui.markdown_viewer): a .md file
rendered with its outline, footnotes, highlighted code and the images beside
it - ported from sandbox-ai's Files page.

Asked for: "integrate [sandbox-ai's Markdown reader] also into axross".
F3 and a double-click on a Markdown file open it rendered (F4 still edits
it), an archive's Markdown member too, and the editor shows the text
rendered beside it (View > Markdown Preview).

What the file holds is untrusted: no raw HTML (``GitHub | NoHTML`` lost
every bit on Python 3.11 - the flags are built by value and every ``<`` is
escaped first), nothing from the network, images only relative to the
file, regular files only, never a secret file, bounded in bytes, pixels and
count; links are routed by the window, never followed inside the view.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6 import sip  # noqa: E402
from PyQt6.QtCore import QCoreApplication, QEvent, QUrl  # noqa: E402
from PyQt6.QtGui import QColor, QImage  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from ui import markdown_view as MDV  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)


def wait_until(predicate, timeout: float = 5.0) -> bool:
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
def docs(tmp_path):
    folder = tmp_path / "docs"
    folder.mkdir()
    _png(folder / "pic.png")
    (folder / "other.md").write_text("# Other\n")
    (folder / "README.md").write_text(
        "# Title\n"
        "Intro with a note[^1] and <b>bold?</b> <img src=pic.png> <script>x()</script> end.\n\n"
        "## Code\n\n"
        "```python\nif a < b:  # comment\n    return \"s\"\n```\n\n"
        "| a | b |\n|---|---|\n| 1 | 2 |\n\n"
        "- [x] done\n- [ ] open\n\n"
        "~~gone~~ https://example.com\n\n"
        "![local](pic.png) ![remote](https://example.com/x.png) ![abs](/etc/hostname) "
        "![up](../docs/pic.png)\n\n"
        "[other](other.md) [web](https://example.com) [code](#code)\n\n"
        "## Title\n\n"
        "[^1]: The note.\n")
    return folder


def _viewer(path: Path, backend=None):
    from ui.markdown_viewer import MarkdownViewerDialog

    viewer = MarkdownViewerDialog(backend or LocalFS(), str(path))
    viewer.show()
    assert wait_until(lambda: viewer.loaded_once)
    return viewer


def _close(viewer) -> None:
    if not sip.isdeleted(viewer):
        viewer.close()
        viewer.deleteLater()
    pump()


# -- the pure parts -----------------------------------------------------------------------------

def test_markdown_files_are_known_by_their_names():
    for name in ("a.md", "B.MD", "c.markdown", "d.mdown", "e.mkd"):
        assert MDV.is_markdown(name)
    for name in ("a.txt", "md", "a.md.txt", "a.mdx"):
        assert not MDV.is_markdown(name)


def test_slugs_and_footnotes():
    assert MDV.slug("Hello, World!") == "hello-world"
    text, notes = MDV.with_footnotes("a[^x] b\n```\n[^y] stays\n```\n[^x]: the note\n")
    # (numbered in the order they are referred to, as markdown-it - test_markdown_reader_bugs5)
    assert notes == ["1"]
    assert "(#fn-1)" in text and "[^y] stays" in text
    assert text.rstrip().endswith("1\\. the note [↩](#fnref-1)")  # (and back: bugs7; "1." as GitHub's: bugs9)


def test_what_qt_cannot_lay_out_in_time_is_shown_as_written_and_said():
    items = "\n".join(f"- {i}" for i in range(MDV.LIST_ITEMS + 10))
    part, why = MDV.renderable("intro\n" + items)
    assert not why and part.count("\n- ") == MDV.LIST_ITEMS + 10  # (a long list: in parts, laid out whole)
    part, why = MDV.renderable("a " + "x" * MDV.LONG_RUN)
    assert why and "x" * 100 not in part
    assert MDV.renderable("# fine\n\ntext") == ("# fine\n\ntext", "")


def test_the_no_html_flags_keep_their_bits():
    from PyQt6.QtGui import QTextDocument

    feature = QTextDocument.MarkdownFeature
    assert MDV.FEATURES.value == feature.MarkdownDialectGitHub.value | feature.MarkdownNoHTML.value


def test_an_svg_that_names_other_files_is_not_decoded():
    inside = b'<svg xmlns="http://www.w3.org/2000/svg"><use href="#a"/></svg>'
    assert not MDV.svg_refers(inside)
    for hostile in (b'<svg><image href="/etc/passwd"/></svg>',
                    b'<svg><style>@import "x.css";</style></svg>',
                    b'<svg style="fill:url(file.svg#p)"></svg>',
                    b'<!DOCTYPE s [<!ENTITY x SYSTEM "/etc/passwd">]><svg>&x;</svg>',
                    b'<?xml version="1.0" encoding="UTF-16"?><svg/>'):
        assert MDV.svg_refers(hostile)
    image, why = MDV.decode(b'<svg xmlns="http://www.w3.org/2000/svg"><image href="/etc/x.png"/></svg>')
    assert image is None and why


def test_image_names_point_beside_the_file_only(tmp_path):
    source = MDV.ImageSource(LocalFS(), str(tmp_path / "docs" / "a.md"))
    assert source.kind("pic.png") == ("local", str(tmp_path / "docs" / "pic.png"))
    assert source.kind("img/p%20q.png") == ("local", str(tmp_path / "docs" / "img" / "p q.png"))
    assert source.kind("../up.png") == ("outside", "../up.png")  # (above the file's folder)
    assert source.kind("https://x.example/p.png")[0] == "remote"
    assert source.kind("//x.example/p.png")[0] == "remote"
    assert source.kind("data:image/png;base64,AAAA")[0] == "data"
    for outside in ("/etc/passwd", "file:///etc/passwd", "C:/x.png", "qrc:/x.png", "\\\\host\\x.png"):
        assert source.kind(outside)[0] == "outside", outside


def test_images_are_bounded_regular_files_and_never_secrets(tmp_path, monkeypatch):
    folder = tmp_path / "d"
    folder.mkdir()
    _png(folder / "ok.png")
    (folder / "big.png").write_bytes(b"\x89PNG" + b"\0" * (MDV.IMAGE_LIMIT + 10))
    os.mkfifo(folder / "fifo.png")
    source = MDV.ImageSource(LocalFS(), str(folder / "a.md"))
    from core import protected_places

    real = protected_places.read_refusal
    monkeypatch.setattr(protected_places, "read_refusal",
                        lambda path, **kw: "secret" if path.endswith("key.png") else real(path, **kw))
    _png(folder / "key.png")
    done = threading.Event()
    found = {}

    def run():
        found.update(source.read(["ok.png", "big.png", "fifo.png", "key.png", "missing.png"]))
        done.set()

    threading.Thread(target=run, daemon=True).start()
    assert done.wait(10), "a FIFO held up the image reader"
    assert isinstance(found["ok.png"], QImage) and found["ok.png"].width() == 40
    assert found["big.png"] == "too big"
    assert found["fifo.png"] == "not a file"
    assert "secret" in found["key.png"]
    assert isinstance(found["missing.png"], str)


def test_the_pixels_of_all_images_together_are_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(MDV, "IMAGES_PIXELS", 40 * 30 * 2)
    folder = tmp_path / "d"
    folder.mkdir()
    _png(folder / "p.png")
    source = MDV.ImageSource(LocalFS(), str(folder / "a.md"))
    found = source.read(["p.png", "./p.png", "p.png?x"])
    images = [v for v in found.values() if isinstance(v, QImage)]
    assert len(images) == 2 and list(found.values()).count("too big") == 1


# -- the view and the window --------------------------------------------------------------------

def test_happy_the_viewer_renders_outline_footnotes_code_and_images(docs):
    viewer = _viewer(docs / "README.md")
    try:
        view = viewer.view
        assert view.headings() == ["Title", "Code", "Title"]
        assert {"title", "code", "title-1"} <= set(view.anchors)
        # the footnote: markdown-it's anchors (fn1 / fnref1), else the md4c path's fn-1
        assert "fn1" in view.names if view.full else "fn-1" in view.anchors
        html = view.browser.document().toHtml()
        assert "<table" in html and "line-through" in html and 'href="https://example.com"' in html
        assert wait_until(lambda: isinstance(view.images.get("pic.png"), QImage)
                          and view.images["pic.png"].width() == 40)
        assert view.images["../docs/pic.png"].width() == 40
        # Placeholders (420 x 36) for what is never read.
        # A remote image is a chip in the line, never asked for; what is never
        # read a placeholder as tall as a line of text.
        assert "https://example.com/x.png" not in view.images and "▣ remote" in view.browser.toPlainText()  # (no emoji font needed: bugs7)
        assert view.images["/etc/hostname"].width() < 420 and view.images["/etc/hostname"].height() < 36
    finally:
        _close(viewer)


def test_sad_raw_html_is_shown_as_its_allowed_subset(docs):
    """markdown-it: <b> and <img> kept, the script gone with its text
    (tests/test_markdown_raw_html.py); Qt's own parser (md4c): all as text."""
    viewer = _viewer(docs / "README.md")
    try:
        text = viewer.view.browser.toPlainText()
        if viewer.view.full:
            assert "and bold? \ufffc end." in text and "x()" not in text and "<" not in text.split("if a")[0]
        else:
            assert "<b>bold?</b>" in text and "<img src=pic.png>" in text and "<script>x()</script>" in text
        assert "if a < b:" in text  # code keeps its "<"
        assert "\x01" not in text and "\\<" not in text  # the escape marks are gone
    finally:
        _close(viewer)


def test_happy_the_file_is_read_off_the_gui_thread(docs):
    gate = threading.Event()
    threads = []

    class Slow(LocalFS):
        def open_read(self, path):
            threads.append(threading.current_thread())
            gate.wait(10)
            return super().open_read(path)

    from ui.markdown_viewer import MarkdownViewerDialog

    viewer = MarkdownViewerDialog(Slow(), str(docs / "other.md"))
    viewer.show()
    try:
        assert wait_until(lambda: threads)
        assert threads[0] is not threading.main_thread()
        pump(0.1)  # the window is live meanwhile
        assert not viewer.loaded_once
        gate.set()
        assert wait_until(lambda: viewer.loaded_once)
        assert viewer.view.headings() == ["Other"]
    finally:
        gate.set()
        _close(viewer)


def test_sad_an_unreadable_file_is_said(tmp_path):
    from ui.markdown_viewer import MarkdownViewerDialog

    class Failing(LocalFS):
        def open_read(self, path):
            raise PermissionError(13, "Permission denied", path)

    (tmp_path / "x.md").write_text("# x")
    viewer = MarkdownViewerDialog(Failing(), str(tmp_path / "x.md"))
    try:
        assert wait_until(lambda: "Permission denied" in viewer.view.status.text())
        assert not viewer.loaded_once
    finally:
        _close(viewer)


def test_edge_a_fifo_named_md_is_not_opened(tmp_path):
    from ui.markdown_viewer import MarkdownViewerDialog

    os.mkfifo(tmp_path / "pipe.md")
    viewer = MarkdownViewerDialog(LocalFS(), str(tmp_path / "pipe.md"))
    try:
        assert wait_until(lambda: "not a regular file" in viewer.view.status.text())
    finally:
        _close(viewer)


def test_edge_a_big_file_is_cut_and_said(tmp_path, monkeypatch):
    monkeypatch.setattr(MDV, "TEXT_LIMIT", 1000)
    (tmp_path / "big.md").write_text("# Big\n" + "word " * 1000)
    viewer = _viewer(tmp_path / "big.md")
    try:
        assert viewer.cut and "first" in viewer.view.status.text()
    finally:
        _close(viewer)


def test_links_are_routed_by_the_window(docs, monkeypatch):
    viewer = _viewer(docs / "README.md")
    try:
        assert viewer.target_of(QUrl("other.md")) == ("markdown", str(docs / "other.md"), "")
        assert viewer.target_of(QUrl("other.md#part")) == ("markdown", str(docs / "other.md"), "part")
        assert viewer.target_of(QUrl("https://example.com/a"))[0] == "web"
        # (a file that is no Markdown is looked at: tests/test_markdown_viewer_window.py)
        assert viewer.target_of(QUrl("../x.txt")) == ("file", str(docs.parent / "x.txt"), "")
        assert viewer.target_of(QUrl("mailto:a@b.example"))[0] == "web"  # (asked about, as a web link)
        for refused in ("file:///etc/passwd", "/abs.md", "mailto:", "javascript:alert(1)", "//host/x.md"):
            assert viewer.target_of(QUrl(refused))[0] == "refused", refused
        # An anchor scrolls in the view and never reaches the window.
        reached = []
        viewer.view.link.connect(reached.append)
        viewer.view.clicked(QUrl("#code"))
        assert reached == []
        # A web link is asked about first; "no" opens nothing.
        from ui import markdown_safe

        opened = []
        monkeypatch.setattr(markdown_safe, "ask_open_link", lambda *_a, **_kw: False)
        monkeypatch.setattr("core.desktop_open.open_url", lambda url: opened.append(url))
        viewer.follow(QUrl("https://example.com/a"))
        assert opened == []
        monkeypatch.setattr(markdown_safe, "ask_open_link", lambda *_a, **_kw: True)
        viewer.follow(QUrl("https://example.com/a"))
        assert len(opened) == 1
        # Another Markdown file opens in this window; Back returns.
        viewer.follow(QUrl("other.md"))
        assert wait_until(lambda: viewer.path == str(docs / "other.md")
                          and viewer.view.headings() == ["Other"])
        assert viewer.back() and wait_until(lambda: viewer.view.headings() == ["Title", "Code", "Title"])
    finally:
        _close(viewer)


def test_sad_the_security_mode_without_external_viewers_opens_no_browser(docs, monkeypatch):
    from types import SimpleNamespace

    viewer = _viewer(docs / "README.md")
    try:
        monkeypatch.setattr("core.security_mode.current_policy",
                            lambda: SimpleNamespace(allow_external_viewer=False))
        asked = []
        monkeypatch.setattr("ui.markdown_safe.ask_open_link", lambda *a, **kw: asked.append(a) or True)
        viewer.follow(QUrl("https://example.com"))
        assert asked == [] and "security mode" in viewer.view.status.text()
    finally:
        _close(viewer)


def test_happy_find_and_zoom(docs):
    viewer = _viewer(docs / "README.md")
    try:
        viewer.find_field.setText("note")
        assert viewer.find_next()
        viewer.find_field.setText("nowhere-in-the-text")
        assert not viewer.find_next() and "Not found" in viewer.view.status.text()
        viewer.view.zoom_by(2)
        viewer.view.zoom_by(-1)
        assert viewer.view.zoom == 1
        viewer.view.zoom_by(0)
        assert viewer.view.zoom == 0
    finally:
        _close(viewer)


def test_happy_reload_reads_the_file_and_its_images_again(docs):
    viewer = _viewer(docs / "README.md")
    try:
        assert wait_until(lambda: isinstance(viewer.view.images.get("pic.png"), QImage)
                          and viewer.view.images["pic.png"].width() == 40)
        _png(docs / "pic.png", 60, 20)
        (docs / "README.md").write_text("# Changed\n\n![p](pic.png)\n")
        viewer.reload()
        assert wait_until(lambda: viewer.view.headings() == ["Changed"])
        assert wait_until(lambda: isinstance(viewer.view.images.get("pic.png"), QImage)
                          and viewer.view.images["pic.png"].width() == 60)
    finally:
        _close(viewer)


# -- where it opens -----------------------------------------------------------------------------

def test_happy_the_pane_opens_markdown_rendered_and_f4_still_edits(docs):
    FP = pytest.importorskip("ui.file_pane")  # (axross's file pane: not in an export)

    pane = mock.MagicMock()
    pane._backend = LocalFS()
    with mock.patch("ui.markdown_viewer.open_markdown_viewer") as opener:
        assert FP.FilePaneWidget._open_markdown_viewer(pane, str(docs / "README.md"), "README.md")
        assert not FP.FilePaneWidget._open_markdown_viewer(pane, str(docs / "pic.png"), "pic.png")
    opener.assert_called_once()
    assert opener.call_args.args[1] == str(docs / "README.md")
    source = Path(FP.__file__).read_text()
    view = source[source.index("def _view_selected"):source.index("def _looks_like_image")]
    activate = source[source.index("def _activate_file"):source.index("def _open_by_kind")]
    edit = source[source.index("def _edit_selected"):]
    edit = edit[:edit.index("\n    def ", 10)]
    assert "_open_markdown_viewer" in view and "_open_markdown_viewer" in activate
    assert "_open_markdown_viewer" not in edit


def test_happy_an_archive_member_opens_rendered(docs):
    FP = pytest.importorskip("ui.file_pane")  # (axross's file pane: not in an export)

    with mock.patch("ui.markdown_viewer.open_markdown_viewer") as opener:
        assert FP.open_local_file_in_viewer(None, str(docs / "README.md")) == "markdown"
    opener.assert_called_once()
    # (the Text View's dialog a stand-in: a real one, left reading, showed a modal error box after the
    # test - every test after it waited for ever). show_independent() lists the stand-in among the
    # open windows: a list of its own, else every later main window's close met a MagicMock there.
    VW = pytest.importorskip("ui.viewer_window")
    with mock.patch("ui.markdown_viewer.open_markdown_viewer") as opener, \
            mock.patch("ui.text_editor.TextEditorDialog") as text_dialog, \
            mock.patch.object(VW, "_INDEPENDENT", []) as shown:
        assert FP.open_local_file_in_viewer(None, str(docs / "README.md"), view="text") != "markdown"
    opener.assert_not_called()
    text_dialog.assert_called_once()
    assert shown == [text_dialog.return_value]


def test_happy_the_editor_shows_a_live_preview(docs, tmp_path):
    from ui.editor_window import EditorWindow

    with mock.patch("pathlib.Path.home", return_value=tmp_path):
        editor = EditorWindow()
    editor.show()
    try:
        editor.open_file(LocalFS(), str(docs / "other.md"))
        assert wait_until(lambda: editor.tabs.count() == 1)
        tab = editor.current_tab()
        assert not tab.previewing and not editor.preview_action.isChecked()
        editor.preview_action.setChecked(True)
        assert tab.previewing and tab.preview.headings() == ["Other"]
        tab.editor.setPlainText("# Typed\n\n## Live\n")
        assert wait_until(lambda: tab.preview.headings() == ["Typed", "Live"], timeout=5)
        editor.preview_action.setChecked(False)
        assert not tab.previewing
    finally:
        for tab in editor._tabs():
            tab.editor.document().setModified(False)
        editor.close()
        editor.deleteLater()
        pump()


def test_sad_edit_without_a_main_window_reads_in_the_background(docs):
    """Edit in a viewer opened without axross's window falls back to the
    plain editor dialog; it must read the file off the GUI thread (as the
    pane opens it), not block the window while a remote file arrives."""
    import ui.text_editor as TE

    seen = {}

    class FakeDialog:
        def __init__(self, backend, path, **kwargs):
            seen.update(kwargs)
            self.loaded = False

        def deleteLater(self):
            pass

    viewer = _viewer(docs / "README.md")
    try:
        with mock.patch.object(TE, "TextEditorDialog", FakeDialog), \
                mock.patch("ui.viewer_window.show_independent", lambda d: seen.setdefault("shown", True)):
            viewer.edit()
        assert seen.get("background") is True, seen
        assert seen.get("shown"), seen
    finally:
        viewer.close()
