"""The media viewer decodes the item it shows before the one it prefetches.

Measured (8000x8000 pictures, local): opening the viewer took 450 ms for a
JPEG whose decode takes 200 ms, and 2.9 s for a PNG whose decode takes
1.5 s. The viewer asked for the shown item and then for the next one, and
its task runner serves the newest request first (right for thumbnails: the
tiles in view come first) - so the prefetch of the next item ran before the
item on screen, which waited for both. The same on every step to an item
that was not prepared yet.
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

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import media_load as ML  # noqa: E402
from core import open_limits as OL  # noqa: E402
from core import security_mode  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.media_collect import IMAGE, MediaItem  # noqa: E402
from tests.media_testkit import write_image  # noqa: E402
from ui import media_viewer as MV  # noqa: E402

APP = QApplication.instance() or QApplication([])


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


@pytest.fixture
def images(tmp_path):
    out = []
    for n in range(4):
        path = write_image(tmp_path / f"{n}.png", size=(50, 20))
        out.append(MediaItem(str(path), path.name, "", IMAGE, path.stat().st_size,
                             path.stat().st_mtime))
    return out


@pytest.fixture
def slow_prepare(monkeypatch):
    """Every decode takes 0.3 s; the names of the items in the order their
    decode started."""
    order: list[str] = []
    lock = threading.Lock()
    real = ML.prepare

    def slow(backend, item, *, cancel, **kw):
        with lock:
            order.append(item.name)
        time.sleep(0.3)
        return real(backend, item, cancel=cancel, **kw)

    monkeypatch.setattr(ML, "prepare", slow)
    return order


def _viewer(items, index=0) -> MV.MediaViewer:
    viewer = MV.MediaViewer(LocalFS())
    viewer.resize(640, 480)
    viewer.show()
    viewer.set_items(items, index)
    return viewer


# --- happy -------------------------------------------------------------------


def test_happy_the_shown_item_is_decoded_first_when_the_viewer_opens(images, slow_prepare):
    start = time.monotonic()
    viewer = _viewer(images, 1)
    try:
        assert wait_until(lambda: viewer.mode == "image")
        took = time.monotonic() - start
        assert slow_prepare[0] == "1.png", slow_prepare
        assert took < 0.55, f"the shown item waited {took:.2f} s (two decodes are 0.6 s)"
        assert wait_until(lambda: viewer.is_prepared(2))  # the prefetch follows
        assert slow_prepare[:2] == ["1.png", "2.png"]
    finally:
        viewer.shutdown()


def test_happy_e2e_a_step_to_an_unprepared_item_decodes_it_before_the_next(
    images, slow_prepare
) -> None:
    from PyQt6.QtCore import Qt
    from PyQt6.QtTest import QTest

    viewer = _viewer(images, 0)
    try:
        assert wait_until(lambda: viewer.mode == "image" and viewer.is_prepared(1))
        viewer.show_index(2)  # not prepared: 2 now, 3 as the prefetch
        assert wait_until(lambda: viewer.mode == "image")
        assert slow_prepare[2] == "2.png", slow_prepare
        assert wait_until(lambda: viewer.is_prepared(3))
        QTest.keyClick(viewer, Qt.Key.Key_Right)  # prefetched: shown at once
        assert viewer.current_index == 3 and viewer.mode == "image"
    finally:
        viewer.shutdown()


# --- sad ---------------------------------------------------------------------


def test_sad_a_broken_shown_item_still_comes_first_and_shows_why(tmp_path, images, slow_prepare):
    bad = tmp_path / "bad.png"
    bad.write_bytes(b"\x89PNG\r\n\x1a\n not a picture")
    items = [MediaItem(str(bad), "bad.png", "", IMAGE, bad.stat().st_size, 0.0), *images]
    viewer = _viewer(items, 0)
    try:
        assert wait_until(lambda: viewer.mode == "placeholder")
        assert slow_prepare[0] == "bad.png"
    finally:
        viewer.shutdown()


# --- edge --------------------------------------------------------------------


def test_edge_the_last_item_has_nothing_to_prefetch(images, slow_prepare):
    viewer = _viewer(images, 3)
    try:
        assert wait_until(lambda: viewer.mode == "image")
        time.sleep(0.4)
        APP.processEvents()
        assert slow_prepare == ["3.png"]
    finally:
        viewer.shutdown()


def test_edge_a_slideshow_on_the_last_item_prefetches_the_first(images, slow_prepare):
    viewer = _viewer(images, 3)
    try:
        assert wait_until(lambda: viewer.mode == "image")
        viewer.start_slideshow(interval_ms=60_000)
        assert wait_until(lambda: viewer.is_prepared(0))
        assert slow_prepare == ["3.png", "0.png"]
    finally:
        viewer.shutdown()
