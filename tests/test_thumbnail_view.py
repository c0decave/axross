"""A pane can show its folder as thumbnails: images, PDFs and videos as
small pictures, everything else as its icon.

Operator request: "ein thumbnail view für dirs mit bildern und videos wäre
auch super". The view is a second face of the same listing - same model,
same selection - so every pane action keeps working on what is selected.
"""

from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtGui import QColor, QImage  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


def wait_until(cond, timeout: float = 8.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.02)
    return cond()


def _png(path: Path, colour: str = "red", size=(80, 60)) -> Path:
    image = QImage(size[0], size[1], QImage.Format.Format_RGB32)
    image.fill(QColor(colour))
    assert image.save(str(path), "PNG")
    return path


@pytest.fixture
def folder(tmp_path) -> Path:
    root = tmp_path / "pics"
    root.mkdir()
    _png(root / "a.png", "red")
    _png(root / "b.png", "blue")
    (root / "broken.jpg").write_bytes(b"\xff\xd8\xff this is not a jpeg")
    (root / "notes.txt").write_text("hello")
    (root / "sub").mkdir()
    return root


@pytest.fixture
def pane(folder):
    from ui.file_pane import FilePaneWidget

    p = FilePaneWidget(LocalFS())
    p.resize(800, 600)
    p.show()
    p.navigate(str(folder))
    pump()
    yield p
    p.close()
    p.deleteLater()
    pump()


def _thumbs(pane):
    return pane.thumbnail_view


# --- happy -----------------------------------------------------------------


def test_happy_switching_shows_the_thumbnails_instead_of_the_table(pane, folder) -> None:
    assert pane.view_mode == "details"
    pane.set_view_mode("thumbnails")
    pump()
    assert pane.view_mode == "thumbnails"
    assert _thumbs(pane).isVisible()
    assert not pane._table.isVisible()
    view = _thumbs(pane)
    assert wait_until(lambda: view.thumbnail_state(str(folder / "a.png")) == "loaded")
    pix = view.thumbnail(str(folder / "a.png"))
    assert pix is not None and not pix.isNull()
    assert pix.toImage().pixelColor(pix.width() // 2, pix.height() // 2) == QColor("red")
    pane.set_view_mode("details")
    pump()
    assert pane._table.isVisible() and not view.isVisible()


def test_happy_a_selection_in_the_thumbnails_is_the_pane_selection(pane, folder) -> None:
    pane.set_view_mode("thumbnails")
    pump()
    view = _thumbs(pane)
    proxy = pane._proxy
    row = next(r for r in range(proxy.rowCount()) if proxy.index(r, 0).data() == "b.png")
    view.selectionModel().select(proxy.index(row, 0), view.selectionCommand(proxy.index(row, 0)))
    view.setCurrentIndex(proxy.index(row, 0))
    pump()
    assert pane.selected_items() == [str(folder / "b.png")]
    pane.set_view_mode("details")  # the selection survives the switch back
    assert pane.selected_items() == [str(folder / "b.png")]


def test_happy_double_click_on_a_folder_tile_opens_it(pane, folder) -> None:
    pane.set_view_mode("thumbnails")
    pump()
    proxy = pane._proxy
    row = next(r for r in range(proxy.rowCount()) if proxy.index(r, 0).data() == "sub")
    _thumbs(pane).doubleClicked.emit(proxy.index(row, 0))
    assert wait_until(lambda: pane.current_path == str(folder / "sub"))


def test_happy_the_view_menu_and_the_context_menu_switch_the_active_pane(folder) -> None:
    from ui.main_window import MainWindow

    win = MainWindow()
    try:
        win._reconnect_timer.stop()
        pane = win._active_pane
        pane.navigate(str(folder))
        action = win.thumbnail_view_action
        assert action.isCheckable() and not action.isChecked()
        assert action.shortcut().toString() == "Ctrl+Shift+G"
        action.trigger()
        assert pane.view_mode == "thumbnails"
        labels = [a.text() for a in pane._build_context_menu().actions()]
        assert "View as Details" in labels
        action.trigger()
        assert pane.view_mode == "details"
        assert "View as Thumbnails" in [a.text() for a in pane._build_context_menu().actions()]
    finally:
        win.close()
        win.deleteLater()
        pump()


# --- sad -------------------------------------------------------------------


def test_sad_a_broken_image_keeps_its_icon_and_is_not_retried(pane, folder) -> None:
    pane.set_view_mode("thumbnails")
    view = _thumbs(pane)
    path = str(folder / "broken.jpg")
    assert wait_until(lambda: view.thumbnail_state(path) == "failed")
    assert view.thumbnail(path) is None
    before = view.requests_made
    view.viewport().update()
    pump(0.3)
    assert view.thumbnail_state(path) == "failed"
    assert view.requests_made == before  # a failure is remembered, not re-read


def test_sad_files_without_a_picture_are_never_read(pane, folder) -> None:
    pane.set_view_mode("thumbnails")
    view = _thumbs(pane)
    assert wait_until(lambda: view.thumbnail_state(str(folder / "a.png")) == "loaded")
    assert view.thumbnail_state(str(folder / "notes.txt")) is None
    assert view.thumbnail_state(str(folder / "sub")) is None


def test_sad_the_security_mode_without_previews_reads_nothing(pane, folder, monkeypatch) -> None:
    from core import media_load

    def blocked():
        raise media_load.MediaUnavailable("blocked by the 'paranoid' security mode")

    monkeypatch.setattr(media_load, "_require_allowed", blocked)
    pane.set_view_mode("thumbnails")
    view = _thumbs(pane)
    assert wait_until(lambda: view.thumbnail_state(str(folder / "a.png")) == "failed")
    assert view.thumbnail(str(folder / "a.png")) is None


def test_sad_a_remote_read_that_fails_leaves_the_icon(tmp_path) -> None:
    from ui.file_pane import FilePaneWidget

    root = tmp_path / "remote"
    root.mkdir()
    _png(root / "a.png")

    class RemoteFS(LocalFS):
        """Looks remote to the media loader; every read fails."""

        def open_read(self, path):
            raise OSError("connection reset by peer")

    from core import file_analysis as file_access

    real = file_access.is_local_backend
    file_access_patch = pytest.MonkeyPatch()
    file_access_patch.setattr(
        file_access, "is_local_backend", lambda b: False if isinstance(b, RemoteFS) else real(b)
    )
    try:
        p = FilePaneWidget(RemoteFS())
        p.resize(600, 400)
        p.show()
        p.navigate(str(root))
        p.set_view_mode("thumbnails")
        view = p.thumbnail_view
        assert wait_until(lambda: view.thumbnail_state(str(root / "a.png")) == "failed")
        p.close()
        p.deleteLater()
        pump()
    finally:
        file_access_patch.undo()


# --- edge ------------------------------------------------------------------


def test_edge_navigating_away_drops_pending_thumbnails(pane, folder, tmp_path) -> None:
    other = tmp_path / "other"
    other.mkdir()
    _png(other / "c.png", "green")
    pane.set_view_mode("thumbnails")
    view = _thumbs(pane)
    pane.navigate(str(other))
    assert wait_until(lambda: view.thumbnail_state(str(other / "c.png")) == "loaded")
    assert view.thumbnail_state(str(folder / "a.png")) is None  # the old folder is forgotten


def test_edge_closing_the_pane_while_thumbnails_load_is_safe(folder) -> None:
    from ui.file_pane import FilePaneWidget

    for i in range(40):
        _png(folder / f"many{i:02}.png", "yellow", size=(400, 300))
    p = FilePaneWidget(LocalFS())
    p.resize(800, 600)
    p.show()
    p.navigate(str(folder))
    p.set_view_mode("thumbnails")
    pump(0.02)
    p.close()
    p.deleteLater()
    pump(0.5)  # late results must find nobody, without a crash


def test_edge_a_switch_in_an_empty_folder(tmp_path) -> None:
    from ui.file_pane import FilePaneWidget

    p = FilePaneWidget(LocalFS())
    p.show()
    p.navigate(str(tmp_path))
    p.set_view_mode("thumbnails")
    pump()
    assert p.view_mode == "thumbnails"
    with pytest.raises(ValueError):
        p.set_view_mode("mosaic")
    p.close()
    p.deleteLater()
    pump()


@pytest.mark.skipif(shutil.which("ffmpeg") is None, reason="ffmpeg not installed")
def test_edge_a_local_video_shows_a_frame(tmp_path) -> None:
    import subprocess

    from core import media_collect as MC
    from core import media_load

    video = tmp_path / "clip.mp4"
    subprocess.run(
        [
            "ffmpeg", "-v", "error", "-f", "lavfi", "-i", "color=c=blue:s=64x48:d=2",
            "-pix_fmt", "yuv420p", str(video),
        ],
        check=True,
        timeout=60,
    )
    import threading

    item = MC.MediaItem(
        path=str(video), name="clip.mp4", folder="", kind=MC.VIDEO,
        size=video.stat().st_size, mtime=video.stat().st_mtime,
    )
    image = media_load.thumbnail(LocalFS(), item, cancel=threading.Event(), edge=64)
    assert not image.isNull()
    colour = image.pixelColor(image.width() // 2, image.height() // 2)
    assert colour.blue() > 150 and colour.red() < 80, colour.name()


def test_sad_a_video_without_ffmpeg_has_no_frame(tmp_path, monkeypatch) -> None:
    import threading

    from core import media_collect as MC
    from core import media_load
    from core import metadata_formats as MF

    monkeypatch.setattr(MF, "ffmpeg_path", lambda: None)
    video = tmp_path / "clip.mp4"
    video.write_bytes(b"\x00" * 64)
    item = MC.MediaItem(
        path=str(video), name="clip.mp4", folder="", kind=MC.VIDEO, size=64, mtime=0.0
    )
    with pytest.raises(media_load.MediaUnavailable, match="ffmpeg"):
        media_load.thumbnail(LocalFS(), item, cancel=threading.Event(), edge=64)


def test_edge_a_garbage_video_is_unavailable_not_a_crash(tmp_path) -> None:
    import threading

    from core import media_collect as MC
    from core import media_load

    if shutil.which("ffmpeg") is None:
        pytest.skip("ffmpeg not installed")
    video = tmp_path / "clip.mp4"
    video.write_bytes(b"not a video at all" * 10)
    item = MC.MediaItem(
        path=str(video), name="clip.mp4", folder="", kind=MC.VIDEO, size=180, mtime=0.0
    )
    with pytest.raises(media_load.MediaUnavailable):
        media_load.thumbnail(LocalFS(), item, cancel=threading.Event(), edge=64)

