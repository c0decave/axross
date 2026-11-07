"""The Media Player shows a track's name and tags as text.

A file's name and its tags (title, artist, album) come with the file -
from a remote server, a download, an archive. The player showed them in
its "now playing" label, in that label's tooltip and in the dock title's
tooltip, and named the file in its notes - all with Qt's rich-text guess:
a title ``<img width=4000 height=4000 src=x>`` laid the panel out
4000 pixels wide, and markup could restyle the text around it.
"""

from __future__ import annotations

import importlib.util
import math
import os
import struct
import sys
import time
import wave
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import audio_route as AR  # noqa: E402

APP = QApplication.instance() or QApplication([])

_spec = importlib.util.spec_from_file_location(
    "bundled_media_player_untrusted", ROOT / "resources" / "extensions" / "media_player.py")
MP = importlib.util.module_from_spec(_spec)
sys.modules["bundled_media_player_untrusted"] = MP
_spec.loader.exec_module(MP)

#: A name that lays a rich-text label out huge.
WIDE = "<img width=4000 height=4000 src=x>"


@pytest.fixture
def panel(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    AR.forget()
    sink = MP.MemorySink()
    p = MP.PlayerPanel(engine=MP.EqEngine(sink_factory=lambda fmt: sink),
                       output_lister=list, open_mixer=lambda: None)
    p.show()
    yield p
    p.close()
    p.deleteLater()
    AR.forget()


@pytest.fixture
def idle_panel(tmp_path, monkeypatch):
    """A panel that plays nothing (no numpy, no sound card needed)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    AR.forget()
    p = MP.PlayerPanel(engine=MP.PendingEngine(), output_lister=list, open_mixer=lambda: None)
    p.show()
    yield p
    p.close()
    p.deleteLater()
    AR.forget()


def tone_wav(path: Path, seconds: float = 0.5) -> Path:
    rate = 44100
    with wave.open(str(path), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(b"".join(struct.pack("<h", int(8000 * math.sin(i / 20)))
                               for i in range(int(rate * seconds))))
    return path


def wait(cond, seconds: float) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return bool(cond())


def test_sad_a_markup_file_name_is_shown_as_text(panel, tmp_path):
    track = tone_wav(tmp_path / f"{WIDE}.wav")
    assert panel.add_files([str(track)]) == 1
    panel.toggle_play()
    assert wait(lambda: WIDE in panel.now_playing.text(), 10)
    assert panel.now_playing.textFormat() == Qt.TextFormat.PlainText
    assert panel.now_playing.sizeHint().width() < 2000
    tip = panel.now_playing.toolTip()
    assert "<img" not in tip and "&lt;img" in tip


def test_sad_notes_naming_a_file_are_plain(panel):
    assert panel.note.textFormat() == Qt.TextFormat.PlainText


def test_happy_the_tooltip_shows_the_title_as_it_is():
    from tests.markup_probe import shown

    assert MP.plain_tooltip("") == ""
    for text in ("AC/DC — T.N.T.", "a <b> & c", f"{WIDE}\nCannot play:  x"):
        assert shown(MP.plain_tooltip(text)) == text


def test_sad_a_markup_file_name_is_text_in_the_playlist_tooltip(idle_panel, tmp_path):
    """A playlist row's tooltip is the track's path: set as it is, Qt
    rendered a file named like markup as rich text (0.15.57 escaped only
    the now-playing tooltips)."""
    from tests.markup_probe import BOLD_FILE, shown, tooltip_width

    for name in (WIDE, BOLD_FILE):
        track = tone_wav(tmp_path / f"{name}.wav")
        item = idle_panel._append(str(track))
        assert shown(item.toolTip()) == str(track)
    assert tooltip_width(idle_panel.playlist.item(0).toolTip()) < 2000


def test_sad_a_track_that_cannot_play_keeps_its_path_as_text(idle_panel, tmp_path):
    from tests.markup_probe import shown, tooltip_width

    bad = tmp_path / f"{WIDE}.wav"
    bad.write_bytes(b"not a wav")
    item = idle_panel._append(str(bad))
    idle_panel._current = item
    idle_panel._track_failed("no audio")
    tip = item.toolTip()
    assert shown(tip) == f"{bad}\n{MP.tr('Cannot play')}: no audio"
    assert tooltip_width(tip) < 2000
