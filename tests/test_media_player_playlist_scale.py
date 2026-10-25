"""A track change costs the same in a long playlist as in a short one.

Measured (offscreen, 2000 tracks): a track change took 16.5 ms in
_set_current plus about 20 ms in the next event-loop pass, against 0.5 and
4 ms with 20 tracks. Cause: the playlist is a QListWidget without uniform
item sizes, and any change to one row - the playing row's bold font and
icon, its length once the tags are read, even a value under UserRole - makes
QListView lay out every row again, asking the delegate for the size of each
(15.5 ms for 2000 rows; 0.14 ms with uniform sizes). The rows are now
uniform: a title longer than the list is cut with "…" (its full text is the
tooltip's) instead of widening every row for a sideways scroll.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtMultimedia", reason="QtMultimedia not installed")

from PyQt6.QtCore import QObject, Qt, pyqtSignal  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import extensions as EX  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _load():
    path = EX.bundled_dir() / "media_player.py"
    spec = importlib.util.spec_from_file_location("media_player_playlist_scale", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MP = _load()


class FakeEngine(QObject):
    finished_playing = pyqtSignal()
    changed = pyqtSignal()
    failed = pyqtSignal(str)

    def __init__(self) -> None:
        super().__init__()
        self.state, self.error, self.finished, self.loaded, self.path = (
            "stopped", "", False, False, "")
        self.loads: list[str] = []

    def load(self, path):
        self.path, self.loaded = path, True
        self.loads.append(path)

    def play(self):
        self.state = "playing"
        self.changed.emit()

    def pause(self):
        self.state = "paused"

    def stop(self):
        self.state = "stopped"

    def seek(self, ms):
        pass

    def set_volume(self, v):
        pass

    def set_gains(self, gains):
        pass

    def set_eq_enabled(self, on):
        pass

    def position_ms(self):
        return 0

    def duration_ms(self):
        return 0

    def current_bars(self, n=32):
        return None

    def current_samples(self):
        return None


class CountingDelegate(MP.PlaylistDelegate):
    """The playlist's delegate, counting how often the view asks for a
    row's size: once per row on every full layout."""

    def __init__(self, parent) -> None:
        super().__init__(parent)
        self.size_hints = 0

    def sizeHint(self, option, index):  # noqa: N802 - Qt
        self.size_hints += 1
        return super().sizeHint(option, index)


def _panel(tmp_path, count: int, title_len: int = 30):
    folder = tmp_path / f"music{count}"
    folder.mkdir()
    for i in range(count):
        (folder / f"{i:05d} {'x' * title_len}.mp3").write_bytes(b"")
    panel = MP.PlayerPanel(engine=FakeEngine())
    panel.resize(700, 500)
    panel.show()
    panel.add_collected(*MP.collect_local([str(folder)]))
    delegate = CountingDelegate(panel.playlist)
    panel.playlist.setItemDelegate(delegate)
    for _ in range(5):
        APP.processEvents()
    return panel, delegate


def _change_tracks(panel, rows) -> None:
    for row in rows:
        panel.play_item(panel.playlist.item(row))
        for _ in range(3):
            APP.processEvents()


# --- happy -------------------------------------------------------------------


def test_happy_a_track_change_does_not_lay_out_every_row(tmp_path) -> None:
    panel, delegate = _panel(tmp_path, 2000)
    try:
        delegate.size_hints = 0
        _change_tracks(panel, (10, 1500, 700, 1999, 3))
        # Before: every row's size per change (thousands); now a handful.
        assert delegate.size_hints < 200, delegate.size_hints
        assert panel.current_row() == 3
    finally:
        panel.shutdown()
        panel.deleteLater()


def test_happy_e2e_the_playing_row_is_marked_shown_and_played(tmp_path) -> None:
    panel, _delegate = _panel(tmp_path, 300)
    try:
        playlist = panel.playlist
        item = playlist.item(250)
        rect = playlist.visualItemRect(item)
        playlist.scrollToItem(item)
        for _ in range(3):
            APP.processEvents()
        # What a window system delivers: press, double click, release (QTest's
        # mouseDClick alone has no press before it).
        pos = playlist.visualItemRect(item).center()
        QTest.mousePress(playlist.viewport(), Qt.MouseButton.LeftButton, pos=pos)
        QTest.mouseDClick(playlist.viewport(), Qt.MouseButton.LeftButton, pos=pos)
        QTest.mouseRelease(playlist.viewport(), Qt.MouseButton.LeftButton, pos=pos)
        for _ in range(5):
            APP.processEvents()
        assert panel.current_row() == 250
        assert panel.engine.loads[-1] == item.data(MP._PATH_ROLE)
        assert item.font().bold()
        assert not item.icon().isNull()
        shown = playlist.visualItemRect(item)
        assert playlist.viewport().rect().contains(shown.center())
        assert shown.height() == rect.height()  # bold and the icon: the same row height
        assert shown.height() >= playlist.iconSize().height()
    finally:
        panel.shutdown()
        panel.deleteLater()


# --- sad ---------------------------------------------------------------------


def test_sad_a_title_longer_than_the_list_is_cut_not_scrolled(tmp_path) -> None:
    panel, _delegate = _panel(tmp_path, 5, title_len=200)
    panel.resize(300, 500)
    for _ in range(3):
        APP.processEvents()
    try:
        playlist = panel.playlist
        assert playlist.horizontalScrollBar().maximum() == 0
        assert playlist.textElideMode() == Qt.TextElideMode.ElideRight
        item = playlist.item(0)
        assert playlist.visualItemRect(item).width() <= playlist.viewport().width()
        panel.resize(500, 500)  # wider again: the row follows
        for _ in range(3):
            APP.processEvents()
        assert playlist.visualItemRect(item).width() == playlist.viewport().width()
        assert item.toolTip()  # the whole path stays readable
    finally:
        panel.shutdown()
        panel.deleteLater()


# --- edge --------------------------------------------------------------------


def test_edge_a_short_list_and_an_emptied_list_still_lay_out(tmp_path) -> None:
    panel, _delegate = _panel(tmp_path, 1)
    try:
        playlist = panel.playlist
        _change_tracks(panel, (0,))
        assert playlist.visualItemRect(playlist.item(0)).height() > 0
        panel.clear_playlist()
        APP.processEvents()
        assert playlist.count() == 0
        panel.add_collected([(str(tmp_path / "music1" / os.listdir(tmp_path / "music1")[0]),
                              "a title")])
        APP.processEvents()
        assert playlist.visualItemRect(playlist.item(0)).height() > 0
    finally:
        panel.shutdown()
        panel.deleteLater()
