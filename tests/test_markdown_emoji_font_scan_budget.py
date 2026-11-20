"""Opening a Markdown file must not hold the window while the installed fonts
are searched for emoji. Before: on a machine where no font has every emoji,
``emoji_fonts`` asked each of hundreds of font families for every emoji, on
the GUI thread, and a double-click on a README froze axross for minutes (a
user's Ctrl+C traceback ended in ``emoji_fonts``). Now each family is asked
only for what is still missing and the search ends after a fixed time."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6 import QtGui  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])

from ui import markdown_view as MV  # noqa: E402


class _SlowNoEmojiMetrics:
    """A font that has no emoji and takes a moment to load, like one of the
    hundreds of families a desktop has installed."""

    def __init__(self, _font):
        time.sleep(0.005)

    def inFontUcs4(self, _sign):
        return False


def test_sad_hundreds_of_fonts_without_emoji_do_not_hold_the_window(monkeypatch):
    monkeypatch.setattr(MV, "_EMOJI_DRAWN", [])
    monkeypatch.setattr(MV, "_EMOJI_FAMILY", [])
    monkeypatch.setattr(QtGui.QFontDatabase, "families",
                        staticmethod(lambda *a: [f"Family {n}" for n in range(2000)]))
    monkeypatch.setattr(QtGui, "QFontMetrics", _SlowNoEmojiMetrics)
    start = time.monotonic()
    MV.emoji_fonts()
    took = time.monotonic() - start
    assert took < MV.EMOJI_SCAN_SECONDS + 1.0, took   # 2000 fonts at 5 ms: 10 s before
    assert MV._EMOJI_DRAWN == [frozenset()]           # nothing found: all stay as written
    assert MV._EMOJI_FAMILY == [""]


class _OneFamilyHasAll:
    def __init__(self, font):
        self.has = font.family() == "Noto Color Emoji"

    def inFontUcs4(self, _sign):
        return self.has


def test_happy_the_emoji_font_is_found_and_the_search_stops_there(monkeypatch):
    monkeypatch.setattr(MV, "_EMOJI_DRAWN", [])
    monkeypatch.setattr(MV, "_EMOJI_FAMILY", [])
    monkeypatch.setattr(QtGui.QFontDatabase, "families",
                        staticmethod(lambda *a: ["DejaVu Sans", "Noto Color Emoji", "Zed Mono"]))
    monkeypatch.setattr(QtGui, "QFontMetrics", _OneFamilyHasAll)
    MV.emoji_fonts()
    assert MV._EMOJI_DRAWN == [None]                  # every short code drawn
    assert MV._EMOJI_FAMILY == ["Noto Color Emoji"]


def test_sad_opening_a_markdown_file_does_not_hold_the_window_with_slow_fonts(
        tmp_path, monkeypatch):
    """The whole path a double-click takes - the viewer window built, the
    file read and shown - stays within a second and a half on a machine with
    2000 slow fonts and no emoji font (it held the window for minutes)."""
    from core.local_fs import LocalFS
    from ui.markdown_viewer import open_markdown_viewer

    monkeypatch.setattr(MV, "_EMOJI_DRAWN", [])
    monkeypatch.setattr(MV, "_EMOJI_FAMILY", [])
    monkeypatch.setattr(QtGui.QFontDatabase, "families",
                        staticmethod(lambda *a: [f"Family {n}" for n in range(2000)]))
    monkeypatch.setattr(QtGui, "QFontMetrics", _SlowNoEmojiMetrics)
    page = tmp_path / "README.md"
    page.write_text("# Title :smile:\n\nText with :rocket: and :tada:.\n")
    start = time.monotonic()
    dialog = open_markdown_viewer(LocalFS(), str(page))
    took = time.monotonic() - start
    try:
        assert took < 1.5, took
    finally:
        dialog.close()
        dialog.deleteLater()
