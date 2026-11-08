"""Markdown Preview never reads what a .md points at (review round 2).

Before: the preview was a plain QTextBrowser. ``setMarkdown`` loads every
image of the text at once, on the GUI thread, through
``QTextBrowser.loadResource`` (``QFile.readAll``): an untrusted
``![x](/path/to/a/fifo)`` froze the whole window for good, and
``![x](/dev/zero)`` filled the memory. Now the preview loads no resource:
the text is shown, its images are not.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

#: Selects one .md in a stand-in pane and prints the preview's text.
_SHOW = textwrap.dedent("""
    import importlib.util, io, sys
    from types import SimpleNamespace
    sys.path.insert(0, sys.argv[1])
    from PyQt6.QtWidgets import QApplication
    app = QApplication([])
    spec = importlib.util.spec_from_file_location(
        "md_preview_probe", sys.argv[1] + "/resources/extensions/markdown_preview.py")
    MD = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(MD)

    class Api:
        def add_dock(self, title, widget, icon=None):
            self.widget = widget
        def on(self, event, callback):
            self.show = callback
        def run_in_background(self, work, on_done=None, on_error=None):
            on_done(work())

    class Files:
        def join(self, *parts):
            return "/".join(parts)
        def open_read(self, path):
            return io.BytesIO(sys.argv[2].encode())

    api = Api()
    MD.activate(api)
    api.widget.show()
    api.show(SimpleNamespace(backend=Files(), folder="/r",
                             items=[SimpleNamespace(name="notes.md", is_dir=False)]))
    app.processEvents()
    print("SHOWN", api.widget.toPlainText().replace("\\n", " | "), flush=True)
""")


def _show(markdown: str, timeout: float = 30) -> str:
    proc = subprocess.run([sys.executable, "-c", _SHOW, str(ROOT), markdown],
                          capture_output=True, text=True, timeout=timeout,
                          env={**os.environ, "QT_QPA_PLATFORM": "offscreen"})
    assert proc.returncode == 0, proc.stderr
    return next(line for line in proc.stdout.splitlines() if line.startswith("SHOWN "))


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs a FIFO")
def test_sad_an_image_that_is_a_fifo_does_not_hang_the_window(tmp_path):
    fifo = tmp_path / "diagram.png"
    os.mkfifo(fifo)
    try:
        shown = _show(f"# Notes\n\nSee ![diagram]({fifo}) here.\n", timeout=30)
    except subprocess.TimeoutExpired:
        pytest.fail("the preview hung reading the FIFO an image link names")
    assert "Notes" in shown and "here." in shown


def test_edge_a_real_image_next_to_the_file_is_not_read_either(tmp_path):
    """No resource is read at all - not even one that would load fine."""
    from PyQt6.QtCore import QUrl
    from PyQt6.QtGui import QImage, QTextDocument
    from PyQt6.QtWidgets import QApplication

    import importlib.util

    app = QApplication.instance() or QApplication([])
    image = QImage(4, 4, QImage.Format.Format_RGB32)
    image.fill(0xFF0000)
    png = tmp_path / "a.png"
    assert image.save(str(png))
    spec = importlib.util.spec_from_file_location(
        "md_preview_no_resource", ROOT / "resources" / "extensions" / "markdown_preview.py")
    MD = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(MD)

    class Api:
        def add_dock(self, title, widget, icon=None):
            self.widget = widget

        def on(self, event, callback):
            self.show = callback

        def run_in_background(self, work, on_done=None, on_error=None):
            on_done(work())

    class Files:
        def join(self, *parts):
            return "/".join(parts)

        def open_read(self, path):
            import io

            return io.BytesIO(f"![a]({png})\n\ntext".encode())

    from types import SimpleNamespace

    api = Api()
    MD.activate(api)
    view = api.widget
    view.show()
    try:
        api.show(SimpleNamespace(backend=Files(), folder="/r",
                                 items=[SimpleNamespace(name="a.md", is_dir=False)]))
        app.processEvents()
        assert "text" in view.toPlainText()
        loaded = view.document().resource(QTextDocument.ResourceType.ImageResource,
                                          QUrl(str(png)))
        # The document holds a blank stand-in, never the 4 x 4 red file.
        size = loaded.size() if hasattr(loaded, "size") else None
        assert size is None or (size.width(), size.height()) != (4, 4)
    finally:
        view.close()
