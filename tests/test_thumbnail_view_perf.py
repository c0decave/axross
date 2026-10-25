"""The thumbnail face stays cheap on the GUI thread in big folders.

Measured (2000 photos, 1280x900 pane, offscreen): every thumbnail that
arrived repainted the whole viewport, so each of the ~40 visible tiles was
painted again per arrival - 60,066 tile paints for 1,961 thumbnails while
scrolling through the folder. A tile is now repainted alone when its
picture arrives.

Also measured: going back to a folder made every picture again - for a
remote folder that is a new download of every image. The pictures of one
connection are now kept (bounded by MAX_CACHED) across folders, keyed by
path, size and time, so a changed file still gets a new picture. Failures
are still tried again after another folder (a remote read may work then).
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


def wait_until(cond, timeout: float = 10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.02)
    return cond()


def _png(path: Path, colour: str, size=(120, 90)) -> Path:
    image = QImage(size[0], size[1], QImage.Format.Format_RGB32)
    image.fill(QColor(colour))
    assert image.save(str(path), "PNG")
    return path


@pytest.fixture
def many(tmp_path) -> Path:
    root = tmp_path / "many"
    root.mkdir()
    colours = ("red", "green", "blue", "yellow", "magenta", "cyan")
    for i in range(60):
        _png(root / f"img{i:03}.png", colours[i % len(colours)])
    return root


def _pane(backend, folder: Path):
    from ui.file_pane import FilePaneWidget

    p = FilePaneWidget(backend)
    p.resize(800, 600)
    p.show()
    p.navigate(str(folder))
    pump()
    return p


def _close(p) -> None:
    p.close()
    p.deleteLater()
    pump()


@pytest.fixture
def paint_count(monkeypatch):
    """How many tiles the thumbnail delegate painted (a list of one int)."""
    import ui.thumbnail_view as TV

    count = [0]
    real = TV._TileDelegate.paint

    def counting(self, painter, option, index):
        count[0] += 1
        real(self, painter, option, index)

    monkeypatch.setattr(TV._TileDelegate, "paint", counting)
    return count


@pytest.fixture
def held(monkeypatch):
    """Thumbnails that never finish on their own: the test delivers them."""
    from core import media_load

    gate = threading.Event()

    def blocked(backend, item, *, cancel, edge):
        while not gate.wait(0.02):
            if cancel.is_set():
                break
        raise media_load.MediaUnavailable("held by the test")

    monkeypatch.setattr(media_load, "thumbnail", blocked)
    yield gate
    gate.set()


def _visible_rows(view) -> list[int]:
    rect = view.viewport().rect()
    model = view.model()
    return [
        row for row in range(model.rowCount())
        if view.visualRect(model.index(row, view.modelColumn())).intersects(rect)
    ]


def _image(colour: str) -> QImage:
    image = QImage(128, 96, QImage.Format.Format_RGB32)
    image.fill(QColor(colour))
    return image


# --- happy -------------------------------------------------------------------


def test_happy_an_arriving_thumbnail_repaints_its_tile_only(many, paint_count, held) -> None:
    p = _pane(LocalFS(), many)
    try:
        p.set_view_mode("thumbnails")
        view = p.thumbnail_view
        assert wait_until(lambda: len(view._pending) >= 8)
        pump(0.2)
        visible = len(_visible_rows(view))
        assert visible >= 8, visible
        key = next(iter(view._pending))
        paint_count[0] = 0
        view._on_loaded(key, _image("black"), None)
        pump(0.2)
        assert 1 <= paint_count[0] <= 2, (paint_count[0], visible)
        assert view.thumbnail_state(key[0]) == "loaded"
        assert view.thumbnail(key[0]).toImage().pixelColor(5, 5) == QColor("black")
    finally:
        _close(p)


def test_happy_e2e_a_folder_loads_with_tile_paints_in_proportion(many, paint_count) -> None:
    """Real thumbnails from real files: every visible tile gets its picture
    and the tiles are painted a few times each, not once per arrival."""
    p = _pane(LocalFS(), many)
    try:
        p.set_view_mode("thumbnails")
        view = p.thumbnail_view
        pump(0.2)
        rows = _visible_rows(view)
        model = view.model()
        media = [view._media_item(model.index(r, view.modelColumn())) for r in rows]
        paths = [m.path for m in media if m is not None]
        assert len(paths) >= 8
        assert wait_until(lambda: all(view.thumbnail_state(x) == "loaded" for x in paths))
        pump(0.2)
        # Before: about one full viewport per arrival (rows * rows).
        assert paint_count[0] <= 4 * len(rows) + 40, (paint_count[0], len(rows))
        pix = view.thumbnail(str(many / "img000.png"))
        assert pix.toImage().pixelColor(pix.width() // 2, pix.height() // 2) == QColor("red")
    finally:
        _close(p)


def test_happy_going_back_to_a_folder_reads_nothing_again(many, tmp_path) -> None:
    other = tmp_path / "other"
    other.mkdir()
    _png(other / "c.png", "green")
    p = _pane(LocalFS(), many)
    try:
        p.set_view_mode("thumbnails")
        view = p.thumbnail_view
        first = str(many / "img000.png")
        # Every tile asked for, not only the first: a picture still being
        # made when the folder is left is dropped (a new listing drops the
        # old one's queue) and asked for again on the way back - under load
        # 10 of 14 were still in flight when only the first was waited for.
        assert wait_until(lambda: view.thumbnail_state(first) == "loaded" and not view._pending)
        p.navigate(str(other))
        assert wait_until(lambda: view.thumbnail_state(str(other / "c.png")) == "loaded")
        before = view.requests_made
        p.navigate(str(many))
        pump(0.3)
        assert view.thumbnail_state(first) == "loaded"
        assert view.requests_made == before
    finally:
        _close(p)


# --- sad ---------------------------------------------------------------------


def test_sad_a_failed_thumbnail_repaints_its_tile_only_and_is_remembered(
    many, paint_count, held
) -> None:
    from core import media_load

    p = _pane(LocalFS(), many)
    try:
        p.set_view_mode("thumbnails")
        view = p.thumbnail_view
        assert wait_until(lambda: len(view._pending) >= 8)
        pump(0.2)
        key = next(iter(view._pending))
        paint_count[0] = 0
        view._on_loaded(key, None, media_load.MediaUnavailable("broken"))
        pump(0.2)
        assert paint_count[0] <= 2
        assert view.thumbnail_state(key[0]) == "failed"
    finally:
        _close(p)


def test_sad_another_connection_forgets_the_pictures(many) -> None:
    p = _pane(LocalFS(), many)
    try:
        p.set_view_mode("thumbnails")
        view = p.thumbnail_view
        first = str(many / "img000.png")
        assert wait_until(lambda: view.thumbnail_state(first) == "loaded")
        p._backend = LocalFS()  # the same path through another connection
        view._on_folder()
        assert view.thumbnail_state(first) is None
    finally:
        _close(p)


def test_sad_a_failure_is_tried_again_after_another_folder(many, tmp_path) -> None:
    other = tmp_path / "elsewhere"
    other.mkdir()
    broken = many / "zz_broken.jpg"
    broken.write_bytes(b"\xff\xd8\xff not a jpeg")
    p = _pane(LocalFS(), many)
    try:
        p.set_view_mode("thumbnails")
        view = p.thumbnail_view
        view.scrollTo(p._proxy.index(p._proxy.rowCount() - 1, 0))
        assert wait_until(lambda: view.thumbnail_state(str(broken)) == "failed")
        p.navigate(str(other))
        pump()
        before = view.requests_made
        p.navigate(str(many))
        view.scrollTo(p._proxy.index(p._proxy.rowCount() - 1, 0))
        assert wait_until(lambda: view.requests_made > before)
        assert wait_until(lambda: view.thumbnail_state(str(broken)) == "failed")
    finally:
        _close(p)


# --- edge --------------------------------------------------------------------


def test_edge_a_result_nobody_waits_for_is_dropped(many, paint_count, held) -> None:
    """A result asked for under an earlier listing (or never): no picture,
    no paint."""
    p = _pane(LocalFS(), many)
    try:
        p.set_view_mode("thumbnails")
        view = p.thumbnail_view
        assert wait_until(lambda: len(view._pending) >= 1)
        view._on_listing()  # a new listing: what was asked for is void
        pump(0.2)
        stale = (str(many / "gone.png"), 10, 1.0)
        paint_count[0] = 0
        view._on_loaded(stale, _image("black"), None)
        pump(0.1)
        assert view.thumbnail_state(stale[0]) is None
        assert paint_count[0] == 0
    finally:
        _close(p)


def test_edge_a_changed_file_gets_a_new_picture_after_going_back(many, tmp_path) -> None:
    other = tmp_path / "other2"
    other.mkdir()
    p = _pane(LocalFS(), many)
    try:
        p.set_view_mode("thumbnails")
        view = p.thumbnail_view
        first = many / "img000.png"
        assert wait_until(lambda: view.thumbnail_state(str(first)) == "loaded")
        p.navigate(str(other))
        pump()
        _png(first, "white", size=(140, 100))  # another size: another key
        os.utime(first, (time.time() + 5, time.time() + 5))
        p.navigate(str(many))

        def white() -> bool:
            pix = view.thumbnail(str(first))
            return pix is not None and pix.toImage().pixelColor(
                pix.width() // 2, pix.height() // 2) == QColor("white")

        assert wait_until(white)
    finally:
        _close(p)


def test_edge_the_kept_pictures_stay_bounded(monkeypatch, many) -> None:
    import ui.thumbnail_view as TV

    monkeypatch.setattr(TV, "MAX_CACHED", 5)
    p = _pane(LocalFS(), many)
    try:
        p.set_view_mode("thumbnails")
        view = p.thumbnail_view
        assert wait_until(lambda: view.requests_made >= 8)
        pump(1.0)
        assert len(view._pictures) <= 5
    finally:
        _close(p)


def test_edge_a_backend_without_weak_references_still_works(many) -> None:
    import weakref

    p = _pane(LocalFS(), many)
    real = p._backend
    try:
        p.set_view_mode("thumbnails")
        view = p.thumbnail_view
        first = str(many / "img000.png")
        assert wait_until(lambda: view.thumbnail_state(first) == "loaded")
        token = 12345678901  # an int takes no weak reference
        with pytest.raises(TypeError):
            weakref.ref(token)
        p._backend = token
        view._on_folder()  # another connection: forgotten
        assert not view._pictures
        view._pictures[("x", 1, 1.0)] = view.thumbnail(first) or None
        view._on_folder()  # the same one again: kept
        assert view._same_backend(token) and ("x", 1, 1.0) in view._pictures
    finally:
        p._backend = real
        _close(p)
