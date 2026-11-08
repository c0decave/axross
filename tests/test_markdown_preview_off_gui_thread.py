"""Markdown Preview converts in the background and caps what it shows
(review round 3).

Before: the file was read in the background, but ``setMarkdown`` ran on
the GUI thread, and its time grows much faster than the file: a
40,000-row table (320 KB) froze the window for 27.5 s, a crafted 160 KB
``*a*a...`` line for 13 s. Now the Markdown is converted to HTML on the
worker thread, only the first part that the GUI thread can lay out
quickly is kept (with a note), and the view gets it with ``setHtml``.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def _load():
    spec = importlib.util.spec_from_file_location(
        "md_preview_budget", ROOT / "resources" / "extensions" / "markdown_preview.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Api:
    """Runs the work on a real worker thread, then times what the GUI
    thread does with the result."""

    gui_seconds = None

    def add_dock(self, title, widget, icon=None):
        self.widget = widget

    def on(self, event, callback):
        self.show = callback

    def run_in_background(self, work, on_done=None, on_error=None):
        box = {}
        worker = threading.Thread(target=lambda: box.update(value=work()))
        worker.start()
        worker.join(120)
        assert "value" in box, "the background work did not finish"
        started = time.monotonic()
        on_done(box["value"])
        QApplication.processEvents()
        self.gui_seconds = time.monotonic() - started


class Files:
    def __init__(self, text: str):
        self.data = text.encode()

    def join(self, *parts):
        return "/".join(parts)

    def open_read(self, path):
        import io

        return io.BytesIO(self.data)


def _preview(text: str):
    md = _load()
    api = Api()
    md.activate(api)
    api.widget.resize(600, 400)
    api.widget.show()
    api.show(SimpleNamespace(backend=Files(text), folder="/r",
                             items=[SimpleNamespace(name="big.md", is_dir=False)]))
    return api


def test_sad_a_long_table_does_not_freeze_the_window(app):
    """8,000 table rows (64 KB) took about 11 s on the GUI thread."""
    api = _preview("|a|b|c|\n|-|-|-|\n" + "|x|y|z|\n" * 8000)
    try:
        assert api.gui_seconds < 2.0, f"the GUI thread was busy {api.gui_seconds:.1f} s"
        shown = api.widget.toPlainText()
        assert shown.lstrip().startswith("a\nb\nc\nx\ny\nz")
        assert "Preview cut" in shown  # the note says only the beginning is shown
    finally:
        api.widget.close()


def test_sad_crafted_emphasis_does_not_freeze_the_window(app):
    """64 KB of ``*a*a...`` (one paragraph, 32,000 format runs) took 8 s."""
    api = _preview("*a" * 32000)
    try:
        assert api.gui_seconds < 2.0, f"the GUI thread was busy {api.gui_seconds:.1f} s"
        assert "Preview cut" in api.widget.toPlainText()
    finally:
        api.widget.close()


def test_happy_an_ordinary_file_is_shown_whole_without_a_note(app):
    text = "# Title\n\nSome *text* with a [link](https://example.org).\n\n" \
           "| k | v |\n|---|---|\n| 1 | 2 |\n\n- one\n- two\n\nThe end.\n"
    html, cut = _load().render_html(text)  # converted off the GUI thread
    assert not cut and "The end." in html
    api = _preview(text)
    try:
        shown = api.widget.toPlainText()
        assert shown.startswith("Title") and shown.rstrip().endswith("The end.")
        assert "Preview cut" not in shown
        assert api.widget.document().find("link").charFormat().isAnchor()
    finally:
        api.widget.close()


def test_edge_one_huge_plain_paragraph_is_cut_inside_not_dropped(app):
    """A cut lands inside an over-long paragraph; it is not left out."""
    md = _load()
    html, cut = md.render_html(("word " * 20 + "\n") * 10000)
    from PyQt6.QtGui import QTextDocument

    doc = QTextDocument()
    doc.setHtml(html)
    assert cut
    assert 10000 < len(doc.toPlainText()) < 1_000_000
