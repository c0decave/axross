"""Both viewers: a Maximize button, Ctrl+M maximize <-> normal, F11
fullscreen, and the last normal geometry plus the maximized state
remembered per viewer in session.json (window.viewers), written on close
only. Offscreen cannot draw a title bar, so the flag and isMaximized() are
asserted instead."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QRect, QSize, Qt, QTimer  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QLayout  # noqa: E402

# Imported before any test patches i18n.SETTINGS_FILE: ui.viewer_window
# imports ui.main_window lazily, and MainWindow._SESSION_FILE is taken from
# i18n.SETTINGS_FILE when the class is built. Run alone, this file built it
# inside a test's monkeypatch and froze that test's temp path.
import ui.main_window  # noqa: E402,F401
from core import (
    i18n,  # noqa: E402
    security_mode,  # noqa: E402
)
from core.local_fs import LocalFS  # noqa: E402
from tests.media_testkit import write_image  # noqa: E402
from ui import media_viewer as MV  # noqa: E402
from ui import viewer_window as VW  # noqa: E402
from ui.image_viewer import ImageViewerDialog  # noqa: E402

APP = QApplication.instance() or QApplication([])
CTRL = Qt.KeyboardModifier.ControlModifier


def wait_until(cond, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.005)
    APP.processEvents()
    return cond()


@pytest.fixture(autouse=True, scope="module")
def _app_theme():
    # The app always styles the viewers with its theme; bare Fusion gives
    # every push button an 80 px minimum, which makes the image viewer
    # 856 px wide - wider than the 800 px offscreen screen. Run alone, this
    # file then failed; in a long run an earlier MainWindow had set it.
    from ui import themes

    # A restyle walks every widget; a garbage collection during it frees
    # widgets Qt still walks (segfault at this module's teardown in a long
    # run) - so the collector waits, as in MainWindow._apply_theme.
    before = APP.styleSheet()
    with themes.collection_paused():
        APP.setStyleSheet(themes.stylesheet_for(themes.DEFAULT_THEME, themes.system_scheme()))
    yield
    with themes.collection_paused():
        APP.setStyleSheet(before)


@pytest.fixture
def settings(tmp_path, monkeypatch) -> Path:
    path = tmp_path / "cfg" / "session.json"
    monkeypatch.setattr(i18n, "SETTINGS_FILE", path)
    return path


@pytest.fixture
def image(tmp_path) -> Path:
    return write_image(tmp_path / "pics" / "a.png", size=(60, 40))


def _show(dlg):
    dlg.show()
    dlg.activateWindow()
    assert wait_until(lambda: dlg.isVisible())
    APP.processEvents()
    return dlg


def _image_viewer(image: Path) -> ImageViewerDialog:
    return _show(ImageViewerDialog(LocalFS(), str(image), siblings=[str(image)]))


def _media_dialog(folder: Path) -> MV.MediaViewerDialog:
    options = MV.MediaViewOptions(kinds=frozenset({MV.MC.IMAGE}), recursive=False)
    dlg = MV.MediaViewerDialog(LocalFS(), str(folder), options)
    # The media layout's minimum width (959-974 px) exceeds the 800 px
    # offscreen screen; Qt then resizes the window to that minimum, and the
    # resize silently drops FullScreen. Unconstrained, the window fits the
    # virtual screen and the state under test is the only variable.
    dlg.layout().setSizeConstraint(QLayout.SizeConstraint.SetNoConstraint)
    dlg.setMinimumSize(0, 0)
    _show(dlg)
    dlg.start()
    assert wait_until(lambda: dlg.scan_finished)
    return dlg


def _key(widget, key, mods=Qt.KeyboardModifier.NoModifier) -> None:
    QTest.keyClick(widget, key, mods)
    APP.processEvents()


def _stored(settings: Path, name: str) -> dict:
    return json.loads(settings.read_text(encoding="utf-8"))["window"]["viewers"][name]


def _available() -> QRect:
    return APP.primaryScreen().availableGeometry()


# -- happy ------------------------------------------------------------------


def test_happy_both_viewers_carry_the_maximize_button_flag(settings, image):
    iv = _image_viewer(image)
    md = _media_dialog(image.parent)
    try:
        for dlg in (iv, md):
            assert dlg.windowFlags() & Qt.WindowType.WindowMaximizeButtonHint
            assert dlg.windowFlags() & Qt.WindowType.WindowCloseButtonHint
    finally:
        iv.reject()
        md.reject()


def test_happy_ctrl_m_maximizes_and_restores_the_image_viewer(settings, image):
    dlg = _image_viewer(image)
    normal = dlg.geometry()
    _key(dlg, Qt.Key.Key_M, CTRL)
    assert wait_until(dlg.isMaximized)
    _key(dlg, Qt.Key.Key_M, CTRL)
    assert wait_until(lambda: not dlg.isMaximized())
    assert dlg.geometry() == normal
    dlg.reject()


def test_happy_ctrl_m_works_on_the_media_overview_and_in_the_viewer(settings, image):
    dlg = _media_dialog(image.parent)
    _key(dlg.overview.view, Qt.Key.Key_M, CTRL)
    assert wait_until(dlg.isMaximized)
    dlg.open_viewer(0)
    _key(dlg.viewer, Qt.Key.Key_M, CTRL)
    assert wait_until(lambda: not dlg.isMaximized())
    assert dlg.stack.currentWidget() is dlg.viewer  # Ctrl+M is not a viewer key
    dlg.reject()


def test_happy_f11_toggles_fullscreen_in_the_image_viewer(settings, image):
    dlg = _image_viewer(image)
    _key(dlg, Qt.Key.Key_F11)
    assert wait_until(dlg.isFullScreen)
    _key(dlg, Qt.Key.Key_F11)
    assert wait_until(lambda: not dlg.isFullScreen())
    assert not dlg.isMaximized()
    dlg.reject()


def test_happy_the_help_lists_the_viewer_keys():
    from ui.shortcuts_dialog import SHORTCUTS

    viewer_keys = {k for section, keys, _d in SHORTCUTS if section == "Viewers" for k in keys}
    assert {VW.MAXIMIZE_KEY, VW.FULLSCREEN_KEY} <= viewer_keys


# -- sad --------------------------------------------------------------------


def test_sad_ctrl_m_in_fullscreen_leaves_fullscreen_to_maximized(settings, image):
    iv = _image_viewer(image)
    _key(iv, Qt.Key.Key_F11)
    assert wait_until(iv.isFullScreen)
    _key(iv, Qt.Key.Key_M, CTRL)
    assert wait_until(lambda: iv.isMaximized() and not iv.isFullScreen())
    iv.reject()

    md = _media_dialog(image.parent)
    md.open_viewer(0)
    _key(md.viewer, Qt.Key.Key_F11)
    assert wait_until(md.isFullScreen)
    _key(md.viewer, Qt.Key.Key_M, CTRL)
    assert wait_until(lambda: md.isMaximized() and not md.isFullScreen())
    md.reject()


def test_sad_escape_in_fullscreen_leaves_fullscreen_and_keeps_the_image_viewer(settings, image):
    dlg = _image_viewer(image)
    _key(dlg, Qt.Key.Key_F11)
    assert wait_until(dlg.isFullScreen)
    _key(dlg, Qt.Key.Key_Escape)
    assert wait_until(lambda: not dlg.isFullScreen())
    assert dlg.isVisible()
    _key(dlg, Qt.Key.Key_Escape)
    assert wait_until(lambda: not dlg.isVisible())


@pytest.mark.parametrize(
    "garbage",
    [
        "not json",
        json.dumps([1, 2]),
        json.dumps({"window": {"viewers": "x"}}),
        json.dumps({"window": {"viewers": {"image": {"width": "800", "height": 600}}}}),
        json.dumps(
            {"window": {"viewers": {"image": {"x": 0, "y": 0, "width": -5, "height": 600}}}}
        ),
        json.dumps(
            {"window": {"viewers": {"image": {"x": True, "y": 0, "width": 500, "height": 400}}}}
        ),
    ],
)
def test_sad_a_broken_stored_state_opens_at_the_default_size(settings, image, garbage):
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(garbage, encoding="utf-8")
    dlg = ImageViewerDialog(LocalFS(), str(image), siblings=[str(image)])
    assert dlg.size() == QSize(*VW.DEFAULT_SIZES["image"])
    assert not (dlg.windowState() & Qt.WindowState.WindowMaximized)
    _show(dlg)
    assert not dlg.isMaximized()
    dlg.reject()


def test_sad_a_viewer_that_never_showed_does_not_overwrite_the_state(settings, tmp_path, image):
    dlg = _image_viewer(image)
    dlg.setGeometry(QRect(30, 40, 500, 400))
    APP.processEvents()
    dlg.reject()
    before = _stored(settings, "image")
    broken = tmp_path / "pics" / "broken.png"
    broken.write_bytes(b"not a png")
    from unittest import mock

    with mock.patch("ui.image_viewer.QMessageBox.warning"):
        ImageViewerDialog(LocalFS(), str(broken), siblings=[str(broken)])
    assert _stored(settings, "image") == before


# -- edge -------------------------------------------------------------------


def _odd_geometry(dlg) -> QRect:
    """A normal geometry that is neither the default nor the screen: just
    above the layout's minimum width, so Qt keeps it as set."""
    width = dlg.minimumSizeHint().width() + 6
    assert width < _available().width() - 10, "the image viewer must fit the screen"
    return QRect(3, 7, width, 433)


def _as_entry(rect: QRect, maximized: bool) -> dict:
    return {
        "x": rect.x(),
        "y": rect.y(),
        "width": rect.width(),
        "height": rect.height(),
        "maximized": maximized,
    }


def test_edge_the_normal_geometry_survives_close_and_reopen(settings, image):
    dlg = _image_viewer(image)
    dlg.setGeometry(_odd_geometry(dlg))
    APP.processEvents()
    normal = dlg.geometry()
    assert normal.size() != QSize(*VW.DEFAULT_SIZES["image"])
    assert not settings.exists()  # a resize writes nothing
    dlg.reject()
    assert _stored(settings, "image") == _as_entry(normal, False)
    again = _image_viewer(image)
    assert again.geometry() == normal
    assert not again.isMaximized()
    again.reject()


def test_edge_the_maximized_state_survives_close_and_reopen(settings, image):
    dlg = _image_viewer(image)
    dlg.setGeometry(_odd_geometry(dlg))
    APP.processEvents()
    normal = dlg.geometry()
    _key(dlg, Qt.Key.Key_M, CTRL)
    assert wait_until(dlg.isMaximized)
    assert dlg.geometry() != normal
    dlg.reject()
    assert _stored(settings, "image") == _as_entry(normal, True)  # normal size, not the screen
    again = _image_viewer(image)
    assert wait_until(again.isMaximized)
    _key(again, Qt.Key.Key_M, CTRL)
    assert wait_until(lambda: not again.isMaximized())
    assert again.geometry() == normal
    again.reject()


def test_edge_media_viewer_state_is_its_own(settings, image):
    md = _media_dialog(image.parent)
    md.setGeometry(QRect(10, 20, 610, 470))
    APP.processEvents()
    normal = md.geometry()
    _key(md.overview.view, Qt.Key.Key_M, CTRL)
    assert wait_until(md.isMaximized)
    md.reject()
    assert _stored(settings, "media") == _as_entry(normal, True)
    assert "image" not in json.loads(settings.read_text())["window"]["viewers"]
    again = _media_dialog(image.parent)
    assert wait_until(again.isMaximized)
    again.reject()


def test_edge_fullscreen_at_close_remembers_the_state_before_it(settings, image):
    dlg = _image_viewer(image)
    _key(dlg, Qt.Key.Key_M, CTRL)
    assert wait_until(dlg.isMaximized)
    _key(dlg, Qt.Key.Key_F11)
    assert wait_until(dlg.isFullScreen)
    _key(dlg, Qt.Key.Key_F11)  # back to maximized, not to normal
    assert wait_until(lambda: dlg.isMaximized() and not dlg.isFullScreen())
    _key(dlg, Qt.Key.Key_F11)
    assert wait_until(dlg.isFullScreen)
    dlg.reject()
    assert _stored(settings, "image")["maximized"] is True
    again = _image_viewer(image)
    assert wait_until(again.isMaximized)
    assert not again.isFullScreen()  # never reopens fullscreen
    again.reject()


def test_edge_f11_from_maximized_returns_to_maximized_in_the_media_viewer(settings, image):
    md = _media_dialog(image.parent)
    md.open_viewer(0)
    _key(md.viewer, Qt.Key.Key_M, CTRL)
    assert wait_until(md.isMaximized)
    _key(md.viewer, Qt.Key.Key_F11)
    assert wait_until(md.isFullScreen)
    _key(md.viewer, Qt.Key.Key_Escape)  # leaves fullscreen the same way
    assert wait_until(lambda: md.isMaximized() and not md.isFullScreen())
    md.reject()


def _store(settings: Path, name: str, **entry) -> None:
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps({"window": {"viewers": {name: entry}}}), encoding="utf-8")


def test_edge_clamp_to_screen_shrinks_and_moves_inside_the_available_area():
    a = _available()
    # larger than the screen: exactly the available area
    assert VW.clamp_to_screen(QRect(a.x(), a.y(), a.width() * 3, a.height() * 3)) == a
    # off-screen bottom-left, fits: same size, pinned to the nearest edges
    assert VW.clamp_to_screen(QRect(-40_000, 90_000, 300, 200)) == QRect(
        a.left(), a.top() + a.height() - 200, 300, 200
    )
    # off-screen top-right
    assert VW.clamp_to_screen(QRect(90_000, -90_000, 300, 200)) == QRect(
        a.left() + a.width() - 300, a.top(), 300, 200
    )
    # already inside: untouched
    inside = QRect(a.x() + 5, a.y() + 5, 100, 80)
    assert VW.clamp_to_screen(inside) == inside


def test_edge_a_geometry_larger_than_the_screen_is_clamped(settings, image):
    avail = _available()
    _store(settings, "image", x=0, y=0, width=avail.width() * 3, height=avail.height() * 3)
    dlg = _image_viewer(image)
    assert dlg.width() <= avail.width() and dlg.height() <= avail.height()
    assert avail.contains(dlg.geometry().center())
    assert not dlg.isMaximized()
    dlg.reject()


def test_edge_an_off_screen_position_is_moved_onto_the_screen(settings, image):
    avail = _available()
    _store(settings, "image", x=-40_000, y=90_000, width=600, height=300, maximized=False)
    dlg = _image_viewer(image)
    assert dlg.height() == 300
    assert dlg.width() <= avail.width()
    assert avail.contains(dlg.geometry().center())
    assert dlg.y() > avail.center().y()  # pinned to the bottom edge it was near
    dlg.reject()


def test_edge_saving_keeps_the_rest_of_session_json(settings, image):
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(
        json.dumps(
            {
                "window": {"language": "de", "width": 1000, "viewers": {"media": {"x": 1}}},
                "splitter": {"type": "splitter", "children": []},
            }
        ),
        encoding="utf-8",
    )
    dlg = _image_viewer(image)
    dlg.reject()
    data = json.loads(settings.read_text(encoding="utf-8"))
    assert data["window"]["language"] == "de"
    assert data["window"]["width"] == 1000
    assert data["window"]["viewers"]["media"] == {"x": 1}
    assert data["splitter"] == {"type": "splitter", "children": []}
    assert "image" in data["window"]["viewers"]
    assert settings.stat().st_mode & 0o777 == 0o600


def test_edge_the_viewers_use_the_main_windows_session_file():
    from ui.main_window import MainWindow

    assert Path(i18n.SETTINGS_FILE) == Path(MainWindow._SESSION_FILE)
    # One source, not two copies of Path.home(): a test that imported
    # main_window under a patched home froze a second, different path.
    assert MainWindow._SESSION_FILE is i18n.SETTINGS_FILE


# -- end to end through the real MainWindow ---------------------------------


@pytest.fixture
def window(settings, monkeypatch):
    from ui.main_window import MainWindow

    monkeypatch.setattr(MainWindow, "_SESSION_FILE", settings)
    previous = security_mode.current_policy().name
    security_mode.set_policy("normal")
    win = MainWindow()
    win.resize(1000, 700)
    win.show()
    APP.processEvents()
    yield win
    for w in QApplication.topLevelWidgets():
        if isinstance(w, MV.MediaViewerDialog | ImageViewerDialog) and w.isVisible():
            w.reject()
    win.close()
    APP.processEvents()
    security_mode.set_policy(previous)


def _pane_at(window, path: Path):
    pane = window._active_pane
    pane.navigate(str(path))
    assert wait_until(lambda: pane.current_path == str(path))
    return pane


def _open_image_from_pane(pane, name: str, drive) -> dict:
    """Select *name* in the pane, press Return (the viewer opens as a window
    of its own), run *drive(dialog)* on it and close it."""
    seen: dict = {}

    def viewers():
        return [w for w in QApplication.topLevelWidgets()
                if isinstance(w, ImageViewerDialog) and w.isVisible()]

    proxy = pane._proxy
    row = next(r for r in range(proxy.rowCount()) if proxy.data(proxy.index(r, 0)) == name)
    pane._table.setCurrentIndex(proxy.index(row, 0))
    pane._table.selectRow(row)
    _key(pane._table, Qt.Key.Key_Return)
    assert wait_until(lambda: len(viewers()) == 1)
    dlg = viewers()[0]
    try:
        drive(dlg, seen)
    finally:
        dlg.reject()
    APP.processEvents()
    return seen


def test_e2e_image_viewer_from_a_pane_remembers_maximized(window, image):
    pane = _pane_at(window, image.parent)
    assert wait_until(lambda: pane._proxy.rowCount() >= 1)

    def first(dlg, seen):
        assert wait_until(dlg.isVisible)
        seen["normal_flag"] = bool(dlg.windowFlags() & Qt.WindowType.WindowMaximizeButtonHint)
        _key(dlg, Qt.Key.Key_M, CTRL)
        seen["maximized"] = wait_until(dlg.isMaximized)

    seen = _open_image_from_pane(pane, "a.png", first)
    assert seen == {"normal_flag": True, "maximized": True}

    def second(dlg, seen):
        seen["restored"] = wait_until(dlg.isMaximized)
        _key(dlg, Qt.Key.Key_M, CTRL)
        seen["normal"] = wait_until(lambda: not dlg.isMaximized())

    seen = _open_image_from_pane(pane, "a.png", second)
    assert seen == {"restored": True, "normal": True}
    assert _stored(Path(i18n.SETTINGS_FILE), "image")["maximized"] is False


def test_e2e_view_media_from_the_window_remembers_maximized(window, image):
    _pane_at(window, image.parent)

    def answer() -> None:
        dlg = QApplication.activeModalWidget()
        if not isinstance(dlg, MV.MediaViewOptionsDialog):
            QTimer.singleShot(10, answer)
            return
        dlg.video_box.setChecked(False)
        dlg.overview_radio.setChecked(True)
        dlg.accept()

    def media_dialogs():
        return [
            w
            for w in QApplication.topLevelWidgets()
            if isinstance(w, MV.MediaViewerDialog) and w.isVisible()
        ]

    QTimer.singleShot(0, answer)
    window._view_media_action.trigger()
    assert wait_until(lambda: len(media_dialogs()) == 1)
    dlg = media_dialogs()[0]
    assert wait_until(lambda: dlg.scan_finished)
    dlg.activateWindow()
    APP.processEvents()
    _key(dlg.overview.view, Qt.Key.Key_M, CTRL)
    assert wait_until(dlg.isMaximized)
    _key(dlg.overview.view, Qt.Key.Key_Escape)
    assert wait_until(lambda: not media_dialogs())
    assert _stored(Path(i18n.SETTINGS_FILE), "media")["maximized"] is True

    QTimer.singleShot(0, answer)
    window._view_media_action.trigger()
    assert wait_until(lambda: len(media_dialogs()) == 1)
    again = media_dialogs()[0]
    assert wait_until(again.isMaximized)
    again.reject()
