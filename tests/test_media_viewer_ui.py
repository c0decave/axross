"""The media viewer's widgets: options, background task runner, overview
grid and the full-window viewer (images, PDFs, videos, slideshow)."""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtGui import QImage  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QDialogButtonBox  # noqa: E402

from core import media_load as ML  # noqa: E402
from core import open_limits as OL  # noqa: E402
from core import security_mode  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.media_collect import IMAGE, PDF, VIDEO, MediaItem  # noqa: E402
from tests.media_testkit import (  # noqa: E402
    MemoryBackend,
    encrypted_pdf_bytes,
    video_bytes,
    write_image,
    write_pdf,
)
from ui import media_viewer as MV  # noqa: E402

APP = QApplication.instance() or QApplication([])
MIB = 1024 * 1024


def wait_until(cond, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.005)
    APP.processEvents()
    return cond()


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(OL, "SETTINGS_PATH", tmp_path / "settings.json")
    previous = security_mode.current_policy().name
    security_mode.set_policy("normal")
    yield
    security_mode.set_policy(previous)
    for w in QApplication.topLevelWidgets():
        if isinstance(w, MV.MediaViewerDialog):
            w.close()
    APP.processEvents()


@pytest.fixture
def folder(tmp_path) -> Path:
    root = tmp_path / "pics"
    write_image(root / "a.png", size=(80, 40), color=(255, 0, 0))
    write_image(root / "b.png", size=(40, 80), color=(0, 0, 255))
    write_image(root / "nested" / "c.jpg", size=(60, 60), color=(0, 255, 0))
    write_pdf(root / "doc.pdf", pages=2)
    (root / "notes.txt").write_text("not media")
    os.utime(root / "b.png", (1_000_000_000, 1_000_000_000))  # the oldest
    return root


def _opts(**kw) -> MV.MediaViewOptions:
    base = dict(kinds=frozenset({IMAGE, PDF}), recursive=False, start_mode=MV.START_OVERVIEW)
    base.update(kw)
    return MV.MediaViewOptions(**base)


def _dialog(backend, path, opts, **kw) -> MV.MediaViewerDialog:
    dlg = MV.MediaViewerDialog(backend, str(path), opts, **kw)
    dlg.resize(800, 600)
    dlg.show()
    dlg.start()
    assert wait_until(lambda: dlg.scan_finished)
    return dlg


def _item(path: Path, kind: str) -> MediaItem:
    return MediaItem(str(path), path.name, "", kind, path.stat().st_size, path.stat().st_mtime)


# -- task runner ----------------------------------------------------------------


def test_happy_runner_runs_work_off_the_gui_thread_and_delivers_in_it():
    runner = MV.TaskRunner(workers=2)
    got = []
    runner.finished.connect(
        lambda key, value, error: got.append((key, value, error, threading.current_thread()))
    )
    runner.submit("k", lambda cancel: threading.current_thread())
    assert wait_until(lambda: got)
    key, value, error, delivered_in = got[0]
    assert key == "k" and error is None
    assert value is not threading.main_thread()
    assert delivered_in is threading.main_thread()
    runner.shutdown()


def test_sad_runner_hands_an_exception_over_as_the_error():
    runner = MV.TaskRunner(workers=1)
    got = []
    runner.finished.connect(lambda key, value, error: got.append(error))

    def boom(cancel):
        raise ML.MediaUnavailable("nope")

    runner.submit("k", boom)
    assert wait_until(lambda: got)
    assert isinstance(got[0], ML.MediaUnavailable)
    assert not runner.active("k")
    runner.shutdown()


def test_edge_runner_drops_results_that_finish_after_a_reset():
    runner = MV.TaskRunner(workers=1)
    got = []
    runner.finished.connect(lambda key, value, error: got.append(key))
    gate = threading.Event()
    seen_cancel = []

    def slow(cancel):
        gate.wait(5)
        seen_cancel.append(cancel.is_set())
        return 1

    runner.submit("old", slow)
    assert wait_until(lambda: runner.running_count() == 1)
    runner.reset()
    gate.set()
    runner.submit("new", lambda cancel: 2)
    assert wait_until(lambda: "new" in got)
    wait_until(lambda: False, timeout=0.2)
    assert got == ["new"]
    assert seen_cancel == [True]  # the stale task was told to stop
    runner.shutdown()


def test_edge_runner_prefers_the_newest_request_and_bounds_the_queue():
    runner = MV.TaskRunner(workers=1, max_pending=3)
    order = []
    gate = threading.Event()
    runner.finished.connect(lambda key, value, error: order.append(key))
    runner.submit("block", lambda cancel: gate.wait(5))
    assert wait_until(lambda: runner.running_count() == 1)
    for key in ("q1", "q2", "q3", "q4"):
        assert runner.submit(key, lambda cancel: None)
    assert not runner.submit("q4", lambda cancel: None)  # already queued
    assert not runner.active("q1")  # dropped: the oldest beyond max_pending
    gate.set()
    assert wait_until(lambda: len(order) == 4)
    assert order == ["block", "q4", "q3", "q2"]
    runner.shutdown()


# -- options dialog -----------------------------------------------------------------


def test_happy_options_dialog_defaults_and_result():
    dlg = MV.MediaViewOptionsDialog()
    opts = dlg.options()
    assert IMAGE in opts.kinds and PDF in opts.kinds
    assert opts.start_mode == MV.START_OVERVIEW
    assert not opts.recursive
    dlg.recursive_box.setChecked(True)
    dlg.depth_spin.setValue(3)
    dlg.slideshow_radio.setChecked(True)
    dlg.pdf_box.setChecked(False)
    opts = dlg.options()
    assert opts.recursive and opts.max_depth == 3
    assert opts.start_mode == MV.START_SLIDESHOW
    assert PDF not in opts.kinds


def test_sad_options_dialog_cannot_be_accepted_without_a_type():
    dlg = MV.MediaViewOptionsDialog()
    ok = dlg.buttons.button(QDialogButtonBox.StandardButton.Ok)
    for box in (dlg.image_box, dlg.pdf_box, dlg.video_box):
        box.setChecked(False)
    assert not ok.isEnabled()
    dlg.pdf_box.setChecked(True)
    assert ok.isEnabled()


def test_edge_options_dialog_depth_only_with_recursion_and_video_when_supported(monkeypatch):
    dlg = MV.MediaViewOptionsDialog()
    assert not dlg.depth_spin.isEnabled()
    dlg.recursive_box.setChecked(True)
    assert dlg.depth_spin.isEnabled()
    monkeypatch.setattr(MV, "video_supported", lambda: False)
    dlg2 = MV.MediaViewOptionsDialog()
    assert not dlg2.video_box.isEnabled()
    assert VIDEO not in dlg2.options().kinds


# -- dialog: scan and overview ---------------------------------------------------------


def test_happy_overview_lists_the_folder_and_makes_thumbnails_off_the_gui_thread(
    folder, monkeypatch
):
    threads = []
    real = ML.thumbnail

    def spy(*a, **kw):
        threads.append(threading.current_thread())
        return real(*a, **kw)

    monkeypatch.setattr(ML, "thumbnail", spy)
    dlg = _dialog(LocalFS(), folder, _opts())
    assert dlg.overview.count() == 3  # a.png, b.png, doc.pdf
    assert dlg.stack.currentWidget() is dlg.overview
    assert wait_until(lambda: dlg.model.thumbnail_count() == 3)
    assert threads and all(t is not threading.main_thread() for t in threads)
    assert "3 items" in dlg.status_label.text()


def test_happy_recursive_scan_shows_the_folder_caption(folder):
    dlg = _dialog(LocalFS(), folder, _opts(recursive=True, kinds=frozenset({IMAGE})))
    texts = dlg.overview.display_texts()
    assert any(t.startswith("c.jpg") and "nested" in t for t in texts)
    assert len(texts) == 3


def test_happy_filter_and_sort(folder):
    dlg = _dialog(LocalFS(), folder, _opts(recursive=True))
    assert dlg.overview.count() == 4
    dlg.overview.filter_edit.setText("NEST")
    assert [i.name for i in dlg.overview.visible_items()] == ["c.jpg"]
    dlg.overview.filter_edit.setText("")
    dlg.overview.sort_combo.setCurrentIndex(dlg.overview.sort_combo.findData("date"))
    assert dlg.overview.visible_items()[0].name == "b.png"
    dlg.overview.sort_combo.setCurrentIndex(dlg.overview.sort_combo.findData("folder"))
    assert dlg.overview.visible_items()[-1].name == "c.jpg"
    dlg.overview.sort_combo.setCurrentIndex(dlg.overview.sort_combo.findData("name"))
    assert [i.name for i in dlg.overview.visible_items()] == ["a.png", "b.png", "c.jpg", "doc.pdf"]


def test_edge_size_slider_changes_the_tile_size(folder):
    dlg = _dialog(LocalFS(), folder, _opts())
    dlg.overview.size_slider.setValue(dlg.overview.size_slider.minimum())
    small = dlg.overview.view.iconSize().width()
    dlg.overview.size_slider.setValue(dlg.overview.size_slider.maximum())
    assert dlg.overview.view.iconSize().width() > small


def test_happy_enter_and_double_click_open_the_viewer_at_that_item(folder):
    dlg = _dialog(LocalFS(), folder, _opts())
    view = dlg.overview.view
    index = view.model().index(1, 0)
    view.setCurrentIndex(index)
    view.setFocus()
    QTest.keyClick(view, Qt.Key.Key_Return)
    assert dlg.stack.currentWidget() is dlg.viewer
    assert dlg.viewer.current_item().name == "b.png"
    QTest.keyClick(dlg.viewer, Qt.Key.Key_Escape)
    assert dlg.stack.currentWidget() is dlg.overview
    dlg.overview.open_requested.emit(2)
    assert dlg.viewer.current_item().name == "doc.pdf"


def test_edge_a_second_activation_of_the_shown_item_does_not_reload_it(folder):
    dlg = _dialog(LocalFS(), folder, _opts())
    dlg.overview.open_requested.emit(0)
    assert wait_until(lambda: dlg.viewer.mode == "image")
    dlg.overview.open_requested.emit(0)  # double-click = doubleClicked + activated
    assert dlg.viewer.mode == "image"


def test_edge_lazy_thumbnails_only_for_what_is_shown(tmp_path, monkeypatch):
    for n in range(120):
        write_image(tmp_path / f"{n:03}.png", size=(8, 8))
    asked = []
    monkeypatch.setattr(
        ML,
        "thumbnail",
        lambda b, item, **kw: asked.append(item.name) or QImage(8, 8, QImage.Format.Format_RGB32),
    )
    dlg = _dialog(LocalFS(), tmp_path, _opts(kinds=frozenset({IMAGE})))
    dlg.resize(300, 200)
    wait_until(lambda: False, timeout=0.5)
    assert 0 < len(asked) < 120


def test_edge_thumbnails_finishing_after_close_are_ignored(folder, monkeypatch):
    gate = threading.Event()

    def slow(*a, **kw):
        gate.wait(5)
        return QImage(4, 4, QImage.Format.Format_RGB32)

    monkeypatch.setattr(ML, "thumbnail", slow)
    dlg = _dialog(LocalFS(), folder, _opts())
    model = dlg.model
    assert wait_until(lambda: dlg.thumbs.running_count() > 0)
    dlg.close()
    gate.set()
    wait_until(lambda: False, timeout=0.3)
    assert model.thumbnail_count() == 0


def test_sad_an_empty_folder_says_so(tmp_path):
    (tmp_path / "x.txt").write_text("x")
    dlg = _dialog(LocalFS(), tmp_path, _opts())
    assert dlg.overview.count() == 0
    assert "No matching media" in dlg.status_label.text()


def test_sad_unreadable_folders_and_caps_show_in_the_status(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root reads every folder")
    write_image(tmp_path / "a.png")
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0)
    try:
        dlg = _dialog(LocalFS(), tmp_path, _opts(recursive=True))
    finally:
        locked.chmod(0o755)
    assert "1 unreadable folder" in dlg.status_label.text()


def test_edge_cancel_keeps_what_was_found(tmp_path, monkeypatch):
    from core import media_collect as MC

    write_image(tmp_path / "a.png")
    real = MC.collect_media

    def slow_collect(*a, cancel, **kw):
        while not cancel():
            time.sleep(0.01)
        return real(*a, cancel=lambda: False, **kw)

    monkeypatch.setattr(MC, "collect_media", slow_collect)
    dlg = MV.MediaViewerDialog(LocalFS(), str(tmp_path), _opts())
    dlg.show()
    dlg.start()
    assert dlg.scan_job.running
    dlg.busy.cancel_button.click()
    assert wait_until(lambda: dlg.scan_finished)
    assert "cancelled" in dlg.status_label.text()


def test_happy_start_mode_slideshow_opens_the_viewer_running(folder):
    dlg = _dialog(LocalFS(), folder, _opts(start_mode=MV.START_SLIDESHOW))
    assert dlg.stack.currentWidget() is dlg.viewer
    assert dlg.viewer.slideshow_active
    dlg2 = _dialog(LocalFS(), folder, _opts(start_mode=MV.START_BROWSE))
    assert dlg2.stack.currentWidget() is dlg2.viewer
    assert not dlg2.viewer.slideshow_active


# -- viewer ------------------------------------------------------------------------


def _viewer(backend, items, index=0) -> MV.MediaViewer:
    viewer = MV.MediaViewer(backend)
    viewer.resize(640, 480)
    viewer.show()
    viewer.set_items(items, index)
    return viewer


def _shown(viewer) -> bool:
    return viewer.mode != "loading"


@pytest.fixture
def three_images(tmp_path):
    return [_item(write_image(tmp_path / f"{n}.png", size=(50, 20)), IMAGE) for n in range(3)]


def test_happy_viewer_navigates_with_the_keyboard(three_images):
    viewer = _viewer(LocalFS(), three_images)
    assert wait_until(lambda: _shown(viewer))
    assert viewer.mode == "image"
    for key, expected in (
        (Qt.Key.Key_Right, 1),
        (Qt.Key.Key_Space, 2),
        (Qt.Key.Key_Left, 1),
        (Qt.Key.Key_PageDown, 2),
        (Qt.Key.Key_PageUp, 1),
        (Qt.Key.Key_Home, 0),
        (Qt.Key.Key_End, 2),
    ):
        QTest.keyClick(viewer, key)
        assert viewer.current_index == expected, key
    viewer.shutdown()


def test_edge_manual_navigation_stops_at_the_ends(three_images):
    viewer = _viewer(LocalFS(), three_images, index=2)
    QTest.keyClick(viewer, Qt.Key.Key_Right)
    assert viewer.current_index == 2
    assert "Last item" in viewer.status_text()
    viewer.show_index(0)
    QTest.keyClick(viewer, Qt.Key.Key_Left)
    assert viewer.current_index == 0
    assert "First item" in viewer.status_text()
    viewer.shutdown()


def test_happy_slideshow_advances_on_the_timer_and_wraps(three_images):
    viewer = _viewer(LocalFS(), three_images, index=1)
    viewer.interval_spin.setValue(2)
    viewer.start_slideshow()
    assert wait_until(lambda: _shown(viewer) and viewer.slideshow_timer.isActive())
    assert viewer.slideshow_timer.interval() == 2000
    viewer.slideshow_timer.timeout.emit()
    assert viewer.current_index == 2
    assert wait_until(lambda: _shown(viewer) and viewer.slideshow_timer.isActive())
    viewer.slideshow_timer.timeout.emit()
    assert viewer.current_index == 0  # the slideshow loops
    viewer.stop_slideshow()
    assert not viewer.slideshow_timer.isActive()
    assert not viewer.slideshow_active
    viewer.shutdown()


def test_edge_slideshow_really_fires_with_a_short_interval(three_images):
    viewer = _viewer(LocalFS(), three_images)
    viewer.start_slideshow(interval_ms=50)
    assert wait_until(lambda: viewer.current_index == 1, timeout=5)
    viewer.toggle_slideshow()
    assert not viewer.slideshow_active
    viewer.shutdown()


def test_happy_prefetch_prepares_the_next_item_in_the_background(three_images):
    viewer = _viewer(LocalFS(), three_images)
    assert wait_until(lambda: _shown(viewer))
    assert wait_until(lambda: viewer.is_prepared(1))
    viewer.shutdown()


def test_sad_corrupt_image_shows_a_placeholder(tmp_path):
    bad = tmp_path / "bad.png"
    bad.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
    viewer = _viewer(LocalFS(), [_item(bad, IMAGE)])
    assert wait_until(lambda: _shown(viewer))
    assert viewer.mode == "placeholder"
    assert "bad.png" in viewer.placeholder_text()
    viewer.shutdown()


def test_sad_huge_image_shows_a_size_placeholder(tmp_path):
    from core import previews as P

    huge = write_image(tmp_path / "huge.png", size=(P.MAX_DIMENSION + 1, 2))
    viewer = _viewer(LocalFS(), [_item(huge, IMAGE)])
    assert wait_until(lambda: _shown(viewer))
    assert viewer.mode == "placeholder"
    assert "too large" in viewer.placeholder_text()
    viewer.shutdown()


def test_sad_encrypted_pdf_shows_a_placeholder(tmp_path):
    locked = tmp_path / "locked.pdf"
    locked.write_bytes(encrypted_pdf_bytes())
    viewer = _viewer(LocalFS(), [_item(locked, PDF)])
    assert wait_until(lambda: _shown(viewer))
    assert viewer.mode == "placeholder"
    assert "password" in viewer.placeholder_text()
    viewer.shutdown()


def test_happy_pdf_pages_then_the_next_item(tmp_path):
    pdf = _item(write_pdf(tmp_path / "doc.pdf", pages=3), PDF)
    img = _item(write_image(tmp_path / "z.png"), IMAGE)
    viewer = _viewer(LocalFS(), [pdf, img])
    assert wait_until(lambda: _shown(viewer))
    assert viewer.mode == "pdf"
    assert viewer.current_page == 0 and viewer.page_count == 3
    QTest.keyClick(viewer, Qt.Key.Key_Right)
    assert (viewer.current_index, viewer.current_page) == (0, 1)
    QTest.keyClick(viewer, Qt.Key.Key_PageDown)
    assert (viewer.current_index, viewer.current_page) == (0, 2)
    QTest.keyClick(viewer, Qt.Key.Key_Right)  # past the last page
    assert viewer.current_index == 1
    assert wait_until(lambda: viewer.mode == "image")
    QTest.keyClick(viewer, Qt.Key.Key_Left)  # back into the PDF
    assert viewer.current_index == 0
    assert wait_until(lambda: viewer.mode == "pdf")
    QTest.keyClick(viewer, Qt.Key.Key_Left)
    assert viewer.current_page == 0
    viewer.shutdown()


def test_happy_zoom_and_rotate(tmp_path):
    item = _item(write_image(tmp_path / "w.png", size=(200, 100)), IMAGE)
    viewer = _viewer(LocalFS(), [item])
    assert wait_until(lambda: viewer.mode == "image")
    assert viewer.fit_mode
    QTest.keyClick(viewer, Qt.Key.Key_1)  # 100 %
    assert not viewer.fit_mode and viewer.zoom_factor == pytest.approx(1.0)
    QTest.keyClick(viewer, Qt.Key.Key_Plus)
    assert viewer.zoom_factor == pytest.approx(1.25)
    QTest.keyClick(viewer, Qt.Key.Key_Minus)
    assert viewer.zoom_factor == pytest.approx(1.0)
    QTest.keyClick(viewer, Qt.Key.Key_R)
    assert viewer.rotation == 90
    QTest.keyClick(viewer, Qt.Key.Key_F)
    assert viewer.fit_mode
    viewer.shutdown()


def test_edge_fullscreen_toggles_and_escape_leaves_it(three_images):
    dlg = MV.MediaViewerDialog(
        LocalFS(), str(Path(three_images[0].path).parent), _opts(start_mode=MV.START_BROWSE)
    )
    dlg.show()
    dlg.start()
    assert wait_until(lambda: dlg.scan_finished)
    QTest.keyClick(dlg.viewer, Qt.Key.Key_F11)
    assert dlg.isFullScreen()
    QTest.keyClick(dlg.viewer, Qt.Key.Key_F11)
    assert not dlg.isFullScreen()
    QTest.keyClick(dlg.viewer, Qt.Key.Key_F11)
    QTest.keyClick(dlg.viewer, Qt.Key.Key_Escape)
    assert not dlg.isFullScreen()
    assert dlg.stack.currentWidget() is dlg.overview


def test_sad_remote_item_over_the_limit_shows_a_placeholder_without_download(tmp_path):
    OL.set_max_open_mb(1)
    backend = MemoryBackend({"/r/big.pdf": b"%PDF"})
    item = MediaItem("/r/big.pdf", "big.pdf", "", PDF, 3 * MIB, 0.0)
    viewer = _viewer(backend, [item])
    assert wait_until(lambda: _shown(viewer))
    assert viewer.mode == "placeholder"
    assert "Open Size Limit" in viewer.placeholder_text()
    assert backend.reads == []
    viewer.shutdown()


def test_happy_remote_items_are_shown_and_their_copies_removed(tmp_path):
    png = write_image(tmp_path / "src.png", size=(30, 30)).read_bytes()
    pdf = write_pdf(tmp_path / "src.pdf", pages=1).read_bytes()
    backend = MemoryBackend({"/r/a.png": png, "/r/b.pdf": pdf})
    items = [
        MediaItem("/r/a.png", "a.png", "", IMAGE, len(png), 0.0),
        MediaItem("/r/b.pdf", "b.pdf", "", PDF, len(pdf), 0.0),
    ]
    viewer = _viewer(backend, items)
    assert wait_until(lambda: viewer.mode == "image")
    viewer.next_item()
    assert wait_until(lambda: viewer.mode == "pdf")
    copy_path = viewer.current_local_path()
    assert os.path.exists(copy_path) and copy_path != "/r/b.pdf"
    viewer.shutdown()
    assert not os.path.exists(copy_path)


def test_happy_video_plays_and_the_slideshow_moves_on_at_its_end(tmp_path):
    if not MV.video_supported():
        pytest.skip("QtMultimedia not available")
    clip = tmp_path / "clip.mp4"
    clip.write_bytes(video_bytes(frames=3))
    img = _item(write_image(tmp_path / "z.png"), IMAGE)
    viewer = _viewer(LocalFS(), [_item(clip, VIDEO), img])
    assert wait_until(lambda: viewer.mode == "video")
    viewer.start_slideshow()
    assert not viewer.slideshow_timer.isActive()  # a video runs to its end instead
    assert wait_until(lambda: viewer.current_index == 1, timeout=15)
    viewer.shutdown()


def test_sad_broken_video_shows_a_placeholder(tmp_path):
    if not MV.video_supported():
        pytest.skip("QtMultimedia not available")
    clip = tmp_path / "broken.mp4"
    clip.write_bytes(b"\x00\x01garbage" * 10)
    viewer = _viewer(LocalFS(), [_item(clip, VIDEO)])
    assert wait_until(lambda: viewer.mode == "placeholder", timeout=15)
    viewer.shutdown()
