"""The standalone Media Player keeps the command line's order (review
round 2).

Before: ``add_arguments`` added every stream URL first and the files
after them, whatever the order they were named in, and played the first
item: ``axross-media-player song.mp3 https://radio/live`` started the
radio. Now files and streams go into the playlist in the order given
(consecutive local paths collected together) and the first one plays.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

RADIO = "https://radio.example.org/live"


def test_sad_a_file_named_before_a_stream_plays_first(tmp_path):
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    from tests.test_media_player_review_fixes import MP, FakeEngine
    from ui import media_player_app as A

    for name in ("song.mp3", "later.ogg"):
        (tmp_path / name).write_bytes(b"x")
    engine = FakeEngine()
    panel = MP.PlayerPanel(engine=engine, state_path=str(tmp_path / "s.json"))
    try:
        count = A.add_arguments(panel, [str(tmp_path / "song.mp3"), RADIO,
                                        str(tmp_path / "later.ogg")])
        app.processEvents()
        assert count == 3
        paths = [panel.playlist.item(i).data(MP._PATH_ROLE)
                 for i in range(panel.playlist.count())]
        assert paths == [str(tmp_path / "song.mp3"), RADIO, str(tmp_path / "later.ogg")]
        assert engine.state == "playing" and engine.path == str(tmp_path / "song.mp3")
    finally:
        panel.shutdown()
        panel.deleteLater()
