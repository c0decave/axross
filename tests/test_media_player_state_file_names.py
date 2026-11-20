"""The player's state file keeps every track whose name a file system can
hold. Before: ``restore_state`` refused any path that ``str.isprintable``
refused, which included the surrogate escapes the player writes itself for a
file name that is no UTF-8, and a no-break space - such tracks were saved and
then dropped at the next start."""
from __future__ import annotations

import importlib.util
import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

pytest.importorskip("PyQt6.QtWidgets")
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])

_spec = importlib.util.spec_from_file_location(
    "media_player_state_names_ext", ROOT / "resources" / "extensions" / "media_player.py")
MP = importlib.util.module_from_spec(_spec)
sys.modules["media_player_state_names_ext"] = MP
_spec.loader.exec_module(MP)

from tests.test_media_player_review_fixes import FakeEngine  # noqa: E402


@pytest.mark.parametrize("path,ok", [
    ("/music/a.mp3", True),
    ("/music/caf\udce9.mp3", True),          # Latin-1 name, as os.fsdecode gives it
    ("/music/a\u00a0b.mp3", True),           # no-break space
    ("/music/\u200bzero.mp3", True),         # zero-width space
    ("https://radio.example.org/live", True),
    ("", False),
    ("/music/a\nb.mp3", False),
    ("/music/a\x1b[31m.mp3", False),
    ("/music/a\x85.mp3", False),             # C1 control
    ("/music/a\ud800.mp3", False),           # a surrogate no file name holds
])
def test_edge_which_saved_paths_come_back(path, ok):
    assert MP._restorable_path(path) is ok


@pytest.mark.skipif(sys.platform == "win32", reason="byte file names are POSIX")
def test_happy_a_track_with_a_non_utf8_name_survives_a_restart(tmp_path):
    name = os.fsdecode(b"caf\xe9.wav")
    track = tmp_path / name
    track.write_bytes(b"RIFF")
    state = tmp_path / "s.json"
    MP.write_state(str(state), {"tracks": [{"path": str(track), "title": "x"}],
                                "current": -1})
    panel = MP.PlayerPanel(engine=FakeEngine(), state_path=str(state))
    try:
        panel.restore_state()
        end = time.monotonic() + 5
        while panel.playlist.count() == 0 and time.monotonic() < end:
            APP.processEvents()
            time.sleep(0.01)
        paths = {panel.playlist.item(n).data(MP._PATH_ROLE)
                 for n in range(panel.playlist.count())}
        assert paths == {str(track)}
    finally:
        panel.shutdown()
        panel.deleteLater()
