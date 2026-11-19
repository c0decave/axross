"""A PDF page that could not be drawn is tried once more on the next visit.

A page whose drawing child hung or crashed (core.pdf_worker) stayed a
placeholder for as long as the viewer was open: a passing hiccup - the
child killed by the memory cap while another page was huge, a busy machine
past the time bound - could never be undone but by closing the viewer. Now
turning back to the page draws it again, once; a page that fails twice stays
a placeholder (no endless retries of a hostile page).
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import pdf_worker as PW  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.media_collect import PDF, MediaItem  # noqa: E402
from tests.media_testkit import requires_qtpdf, write_pdf  # noqa: E402

APP = QApplication.instance() or QApplication([])

pytestmark = requires_qtpdf

# A child whose page 2 (index 1) crashes while the marker file *counts* down.
_FLAKY = r'''
import os, signal
import PyQt6.QtPdf as _qtpdf
_COUNTER = {counter!r}
class _Doc(_qtpdf.QPdfDocument):
    def render(self, page, size, *rest):
        if page == 1:
            left = int(open(_COUNTER).read() or "0")
            if left > 0:
                open(_COUNTER, "w").write(str(left - 1))
                os.kill(os.getpid(), signal.SIGSEGV)
        return super().render(page, size, *rest)
_qtpdf.QPdfDocument = _Doc
'''


@pytest.fixture
def flaky(monkeypatch, tmp_path):
    """Page 2 crashes its child the next *n* times it is drawn."""

    def use(n: int) -> None:
        counter = tmp_path / "left"
        counter.write_text(str(n))
        script = tmp_path / "flaky.py"
        script.write_text(_FLAKY.format(counter=str(counter)) + PW._CHILD_SOURCE)
        real = PW.worker_argv
        monkeypatch.setattr(PW, "worker_argv", lambda seconds=PW.RENDER_SECONDS: [
            sys.executable, "-I", str(script), *real(seconds)[-3:]])
        PW.close_pool()

    yield use
    PW.close_pool()


def _wait(cond, seconds: float = 15.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return cond()


def _viewer(pdf: Path):
    from ui import media_viewer as MV

    st = pdf.stat()
    item = MediaItem(path=str(pdf), name=pdf.name, kind=PDF, size=st.st_size,
                     mtime=st.st_mtime, folder="")
    viewer = MV.MediaViewer(LocalFS())
    viewer.resize(640, 480)
    viewer.show()
    viewer.set_items([item], 0)
    return viewer


def _failed(viewer) -> bool:
    return (viewer.pages.currentWidget() is viewer.placeholder_label
            and "Cannot show page 2" in viewer.placeholder_text())


def test_happy_a_page_that_failed_once_is_drawn_on_the_next_visit(flaky, tmp_path):
    flaky(1)
    viewer = _viewer(write_pdf(tmp_path / "d.pdf", pages=3))
    try:
        assert _wait(lambda: viewer.mode == "pdf" and viewer.page_shown() == 0)
        viewer.next_page()
        assert _wait(lambda: _failed(viewer))
        viewer.next_page()
        assert _wait(lambda: viewer.page_shown() == 2)
        viewer.prev_page()  # back to page 2: drawn again
        assert _wait(lambda: viewer.page_shown() == 1), viewer.placeholder_text()
    finally:
        viewer.shutdown()


def test_sad_a_page_that_fails_twice_stays_a_placeholder(flaky, tmp_path):
    flaky(5)
    viewer = _viewer(write_pdf(tmp_path / "d.pdf", pages=3))
    try:
        assert _wait(lambda: viewer.mode == "pdf" and viewer.page_shown() == 0)
        viewer.next_page()
        assert _wait(lambda: _failed(viewer))
        viewer.prev_page()
        assert _wait(lambda: viewer.page_shown() == 0)
        viewer.next_page()  # the one retry
        assert _wait(lambda: _failed(viewer))
        left = int((tmp_path / "left").read_text())
        assert left == 3
        viewer.prev_page()
        assert _wait(lambda: viewer.page_shown() == 0)
        viewer.next_page()  # no third try
        assert _wait(lambda: _failed(viewer), 3)
        time.sleep(0.5)
        APP.processEvents()
        assert int((tmp_path / "left").read_text()) == 3
    finally:
        viewer.shutdown()


def test_edge_while_a_page_is_tried_again_the_old_page_is_not_shown_as_it(flaky, tmp_path):
    """The retry says it is loading: the page turned from does not stand
    for the page turned to."""
    flaky(1)
    viewer = _viewer(write_pdf(tmp_path / "d.pdf", pages=3))
    try:
        assert _wait(lambda: viewer.mode == "pdf" and viewer.page_shown() == 0)
        viewer.next_page()
        assert _wait(lambda: _failed(viewer))
        viewer.next_page()
        assert _wait(lambda: viewer.page_shown() == 2)
        viewer.prev_page()
        assert viewer.pages.currentWidget() in (viewer.loading_label, viewer._pdf_view)
        assert viewer.page_shown() in (-1, 1)
    finally:
        viewer.shutdown()
