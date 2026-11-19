"""PDFs are drawn in a killable child process (core.pdf_worker).

pdfium parsed every PDF inside axross: a PDF that kept it busy pinned the
viewer's or the thumbnails' thread for good, one that crashed it took the
program down. Now a child process opens and draws, the parent kills it past
its bound, and the viewer, the thumbnails and the media viewer's pages say
why. A hostile PDF is played here by a child whose QPdfDocument hangs or
crashes on one page - pdfium's own failures cannot be summoned on demand.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import media_load as ML  # noqa: E402
from core import pdf_worker as PW  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.media_collect import IMAGE, PDF, MediaItem  # noqa: E402
from tests.media_testkit import encrypted_pdf_bytes, requires_qtpdf, write_pdf  # noqa: E402

APP = QApplication.instance() or QApplication([])

pytestmark = requires_qtpdf

# A child whose QPdfDocument misbehaves on page 2 (index 1) or on open.
_HOSTILE = r'''
import os, signal, sys, time
import PyQt6.QtPdf as _qtpdf
_MODE = {mode!r}
class _Doc(_qtpdf.QPdfDocument):
    def load(self, path):
        if _MODE == "hang-open":
            time.sleep(1000)
        if _MODE == "crash-open":
            os.kill(os.getpid(), signal.SIGSEGV)
        return super().load(path)
    def render(self, page, size, *rest):
        if page == 1 and _MODE == "hang":
            time.sleep(1000)
        if page == 1 and _MODE == "crash":
            os.kill(os.getpid(), signal.SIGSEGV)
        return super().render(page, size, *rest)
_qtpdf.QPdfDocument = _Doc
'''


@pytest.fixture
def hostile(monkeypatch, tmp_path):
    """Make every PDF child misbehave as *mode* says; returns the setter."""

    def use(mode: str) -> None:
        script = tmp_path / f"hostile_{mode}.py"
        script.write_text(_HOSTILE.format(mode=mode) + PW._CHILD_SOURCE)
        real = PW.worker_argv

        def argv(seconds=PW.RENDER_SECONDS):
            return [sys.executable, "-I", str(script), *real(seconds)[-3:]]

        monkeypatch.setattr(PW, "worker_argv", argv)
        PW.close_pool()

    yield use
    PW.close_pool()


def _item(path: Path, kind: str) -> MediaItem:
    st = path.stat()
    return MediaItem(path=str(path), name=path.name, kind=kind, size=st.st_size,
                     mtime=st.st_mtime, folder="")


# -- the renderer ----------------------------------------------------------------


def test_happy_pages_are_drawn_in_another_process(tmp_path):
    pdf = write_pdf(tmp_path / "d.pdf", pages=3)
    with PW.PdfRenderer() as renderer:
        assert renderer.open(str(pdf)) == 3
        w, h = renderer.page_size(2)
        assert (round(w), round(h)) == (297, 420)  # A6 in points
        width, height, stride, data = renderer.render_edge(0, 400)
        assert height == 400 and 270 <= width <= 290
        assert len(data) == stride * height
        assert renderer.pid() not in (None, os.getpid())


def test_sad_a_page_that_hangs_kills_only_its_child_and_says_why(hostile, tmp_path):
    hostile("hang")
    pdf = write_pdf(tmp_path / "d.pdf", pages=3)
    with PW.PdfRenderer(seconds=2.0) as renderer:
        assert renderer.open(str(pdf)) == 3
        first = renderer.pid()
        started = time.monotonic()
        with pytest.raises(PW.PdfTooSlow) as caught:
            renderer.render_edge(1, 200)
        assert time.monotonic() - started < 6
        assert "page 2" in str(caught.value) and "longer than 2 s" in str(caught.value)
        assert not renderer.alive
        # the other pages: a fresh child opens the document again
        renderer.render_edge(2, 200)
        assert renderer.pid() != first


def test_sad_a_page_that_crashes_pdfium_leaves_axross_running(hostile, tmp_path):
    hostile("crash")
    pdf = write_pdf(tmp_path / "d.pdf", pages=2)
    with PW.PdfRenderer(seconds=10.0) as renderer:
        renderer.open(str(pdf))
        with pytest.raises(PW.PdfCrashed) as caught:
            renderer.render_edge(1, 200)
        assert "ended" in str(caught.value) and "signal 11" in str(caught.value)
        renderer.render_edge(0, 200)


def test_sad_an_encrypted_pdf_is_refused_with_its_reason(tmp_path):
    locked = tmp_path / "locked.pdf"
    locked.write_bytes(encrypted_pdf_bytes())
    with PW.PdfRenderer() as renderer, pytest.raises(PW.PdfError) as caught:
        renderer.open(str(locked))
    assert "password" in str(caught.value)


def test_edge_a_huge_page_size_is_clamped():
    w, h = PW.clamp_size(100_000, 100_000)
    assert w == h and w * h <= PW.MAX_PIXELS and w * h > 0.99 * PW.MAX_PIXELS
    w, h = PW.fit_size(1, 1_000_000, 50_000)
    assert h <= PW.MAX_EDGE and w >= 1


def test_edge_close_does_not_wait_for_a_hanging_page(hostile, tmp_path):
    hostile("hang")
    pdf = write_pdf(tmp_path / "d.pdf", pages=2)
    renderer = PW.PdfRenderer(seconds=60.0)
    renderer.open(str(pdf))
    errors = []

    def draw():
        try:
            renderer.render_edge(1, 200)
        except PW.PdfError as exc:
            errors.append(exc)

    thread = threading.Thread(target=draw)
    thread.start()
    time.sleep(1.0)
    started = time.monotonic()
    renderer.close()
    assert time.monotonic() - started < 2.5
    thread.join(5)
    assert not thread.is_alive() and errors


def test_happy_a_pooled_child_lets_go_of_the_file(tmp_path):
    pdf = write_pdf(tmp_path / "d.pdf", pages=1)
    with PW.borrowed() as renderer:
        renderer.open(str(pdf))
        renderer.render_edge(0, 64)
    assert renderer.path == "" and renderer.alive
    PW.close_pool()
    assert not renderer.alive


# -- media_load: thumbnails and the media viewer's pages -------------------------------


def test_sad_a_thumbnail_of_a_hanging_pdf_gives_up_with_a_reason(hostile, monkeypatch, tmp_path):
    monkeypatch.setattr(PW, "RENDER_SECONDS", 2.0)
    hostile("hang-open")
    pdf = write_pdf(tmp_path / "d.pdf", pages=1)
    started = time.monotonic()
    with pytest.raises(ML.MediaUnavailable) as caught:
        ML.thumbnail(LocalFS(), _item(pdf, PDF), cancel=threading.Event(), edge=64)
    assert time.monotonic() - started < 8
    assert "longer than" in str(caught.value)


def test_sad_a_pdf_named_like_a_picture_that_crashes_is_refused(hostile, tmp_path):
    hostile("crash-open")
    pdf = write_pdf(tmp_path / "d.pdf", pages=1)
    picture = tmp_path / "x.png"
    picture.write_bytes(pdf.read_bytes())
    with pytest.raises(ML.MediaUnavailable) as caught:
        ML.thumbnail(LocalFS(), _item(picture, IMAGE), cancel=threading.Event(), edge=64)
    assert "ended" in str(caught.value)
    with pytest.raises(ML.MediaUnavailable):
        ML.prepare(LocalFS(), _item(picture, IMAGE), cancel=threading.Event())


def test_happy_prepare_opens_the_pdf_in_a_child_kept_until_release(tmp_path):
    pdf = write_pdf(tmp_path / "d.pdf", pages=2)
    entry = ML.prepare(LocalFS(), _item(pdf, PDF), cancel=threading.Event())
    try:
        assert entry.page_count == 2
        assert entry.pdf is not None and entry.pdf.alive
        assert entry.image is not None and not entry.image.isNull()
        image = ML.render_page(entry.pdf, 1, 300, 400)
        assert (image.width(), image.height()) == (300, 400)
        assert image.pixelColor(150, 200).blue() > 200  # page 2 is blue
    finally:
        entry.release()
    assert not entry.pdf.alive


# -- the media viewer -------------------------------------------------------------


def _wait(cond, seconds: float = 15.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return cond()


def _viewer(items):
    from ui import media_viewer as MV

    viewer = MV.MediaViewer(LocalFS())
    viewer.resize(640, 480)
    viewer.show()
    viewer.set_items(items, 0)
    return viewer


def test_sad_the_viewer_says_why_a_page_hangs_and_keeps_the_others(hostile, monkeypatch,
                                                                  tmp_path):
    monkeypatch.setattr(PW, "RENDER_SECONDS", 2.0)
    hostile("hang")
    pdf = write_pdf(tmp_path / "d.pdf", pages=3)
    viewer = _viewer([_item(pdf, PDF)])
    try:
        assert _wait(lambda: viewer.mode == "pdf" and viewer.page_shown() == 0)
        viewer.next_page()
        assert _wait(lambda: "longer than" in viewer.placeholder_text(), 10)
        assert viewer.mode == "pdf" and viewer.page_bar.isVisible()
        assert viewer.pages.currentWidget() is viewer.placeholder_label
        viewer.next_page()
        assert _wait(lambda: viewer.page_shown() == 2)
        assert viewer.pages.currentWidget() is viewer._pdf_view
        viewer.prev_page()  # the failed page is tried once more (it hangs again) ...
        assert _wait(lambda: "longer than" in viewer.placeholder_text()
                     and viewer.pages.currentWidget() is viewer.placeholder_label, 10)
        viewer.next_page()
        assert _wait(lambda: viewer.page_shown() == 2)
        viewer.prev_page()  # ... and not a third time
        assert _wait(lambda: viewer.pages.currentWidget() is viewer.placeholder_label, 2)
    finally:
        viewer.shutdown()


def test_sad_a_pdf_that_crashes_on_open_is_a_placeholder_not_a_crash(hostile, tmp_path):
    hostile("crash-open")
    pdf = write_pdf(tmp_path / "d.pdf", pages=2)
    viewer = _viewer([_item(pdf, PDF)])
    try:
        assert _wait(lambda: viewer.mode == "placeholder")
        assert "ended" in viewer.placeholder_text()
    finally:
        viewer.shutdown()


def test_happy_zoom_draws_the_page_sharper(tmp_path):
    pdf = write_pdf(tmp_path / "d.pdf", pages=2)
    viewer = _viewer([_item(pdf, PDF)])
    try:
        assert _wait(lambda: viewer.mode == "pdf" and viewer.page_shown() == 0)
        viewer.actual_size()
        viewer.zoom_by(4.0)
        assert viewer.zoom_factor == pytest.approx(4.0)
        dpi = (viewer.screen().logicalDotsPerInch() if viewer.screen() else 96.0) / 72.0
        want = 297 * dpi * 4.0 * viewer.devicePixelRatioF()
        assert _wait(lambda: viewer._pdf_view.image_width() >= 0.95 * want)
        viewer.next_page()
        assert _wait(lambda: viewer.page_shown() == 1)
        assert viewer.zoom_factor == pytest.approx(4.0)
    finally:
        viewer.shutdown()
    assert all(not getattr(e, "pdf", None) or not e.pdf.alive
               for e in viewer._prepared.values())


# -- the child process ---------------------------------------------------------------


def test_edge_the_child_is_started_isolated_and_bounded(monkeypatch):
    argv = PW.worker_argv(3.0)
    assert argv[0] == sys.executable and argv[1:3] == ["-I", "-c"]
    assert argv[-3:] == [str(os.getpid()), str(PW.cpu_seconds_for(3.0)), str(PW.DATA_LIMIT)]
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert PW.worker_argv(3.0) == [sys.executable, "--pdf-worker", *argv[-3:]]
    main_source = (Path(__file__).resolve().parent.parent / "main.py").read_text()
    assert '["--pdf-worker"]' in main_source and "core.pdf_worker import _child_main" in main_source


def test_sad_a_child_under_a_launcher_draws_and_a_stray_one_does_not(tmp_path):
    """A one-file build's child runs under the build's own bootloader: a
    grandparent that is the program is the program; anything else ends it."""
    if not sys.platform.startswith("linux"):
        pytest.skip("the parent check is Linux's")
    import json
    import struct
    import subprocess

    pdf = write_pdf(tmp_path / "d.pdf", pages=1)
    request = json.dumps({"op": "open", "path": str(pdf)}).encode()
    data = struct.pack(">I", len(request)) + request
    command = PW.worker_argv()
    result = subprocess.run(["/bin/sh", "-c", '"$@"; exit $?', "sh", *command], input=data,
                            capture_output=True, timeout=60)
    assert result.returncode == 0 and b'"pages": 1' in result.stdout
    stranger = command[:-3] + ["1"] + command[-2:]
    result = subprocess.run(["/bin/sh", "-c", '"$@"; exit $?', "sh", *stranger], input=data,
                            capture_output=True, timeout=60)
    assert result.returncode == 1 and not result.stdout


def test_sad_pdf_metadata_without_pypdf_survives_a_crashing_pdfium(hostile, monkeypatch,
                                                                    tmp_path):
    """The metadata panel's QtPdf fallback (no pypdf) loaded the PDF in
    axross's own process."""
    from core import metadata_formats as MF

    monkeypatch.setattr(MF, "have_pypdf", lambda: False)
    hostile("crash-open")
    pdf = write_pdf(tmp_path / "d.pdf", pages=1)
    fields, error, _ = MF.pdf_fields(str(pdf))
    assert fields == [] and "ended" in error


def test_edge_a_renderer_dropped_without_close_ends_its_child(tmp_path):
    import gc

    pdf = write_pdf(tmp_path / "d.pdf", pages=1)
    renderer = PW.PdfRenderer()
    renderer.open(str(pdf))
    proc = renderer._proc
    del renderer
    gc.collect()
    proc.wait(timeout=10)
    assert proc.returncode is not None
