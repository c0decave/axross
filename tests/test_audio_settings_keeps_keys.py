"""audio.json is shared with axross-amp, which writes keys of its own (its
output device, ``amp_output``). Before: every save in axross (the Audio
page, the Mixer, the equalizer, a Bluetooth output) wrote only axross's own
fields, so each of them dropped what axross-amp had stored. Now a save keeps
every key it does not know and writes its own values over the rest."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import audio_route as AR  # noqa: E402
from core import audio_settings as AS  # noqa: E402

APP = QApplication.instance() or QApplication([])

AMP = {"amp_output": "alsa_output.usb-dac", "amp_window": {"w": 640, "h": 480}}


def _write(path: Path, data) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


def test_happy_a_save_keeps_the_keys_axross_amp_wrote(tmp_path):
    path = tmp_path / "audio.json"
    _write(path, {"version": 1, "output_volume": 70, **AMP})
    settings = AS.AudioSettings.load(path)
    settings.set("eq_preset", "Rock")
    settings.save(path)
    saved = json.loads(path.read_text())
    assert saved["amp_output"] == AMP["amp_output"]
    assert saved["amp_window"] == AMP["amp_window"]
    assert saved["eq_preset"] == "Rock"
    assert saved["output_volume"] == 70
    assert saved["version"] == 1


def test_happy_audio_route_update_keeps_them_too(tmp_path):
    path = tmp_path / "audio.json"
    _write(path, {"version": 1, **AMP})
    AR.update(path, media_volume=40)
    saved = json.loads(path.read_text())
    assert saved["amp_output"] == AMP["amp_output"]
    assert saved["media_volume"] == 40


def test_edge_axross_own_values_win_over_the_file(tmp_path):
    # A key axross knows is axross's: its value replaces the file's, also
    # one the file held invalid.
    path = tmp_path / "audio.json"
    _write(path, {"version": 7, "output_volume": "loud", "eq_enabled": True, **AMP})
    settings = AS.AudioSettings.load(path)
    settings.set("eq_enabled", False)
    settings.save(path)
    saved = json.loads(path.read_text())
    assert saved["output_volume"] == 100
    assert saved["eq_enabled"] is False
    assert saved["version"] == 1
    assert saved["amp_output"] == AMP["amp_output"]


def test_edge_a_key_written_after_the_load_is_kept(tmp_path):
    # axross-amp saves while axross holds the settings: merged at save time.
    path = tmp_path / "audio.json"
    _write(path, {"version": 1})
    settings = AS.AudioSettings.load(path)
    _write(path, {"version": 1, **AMP})
    settings.set("output_volume", 55)
    settings.save(path)
    saved = json.loads(path.read_text())
    assert saved["amp_output"] == AMP["amp_output"]
    assert saved["output_volume"] == 55


def test_sad_a_missing_broken_or_non_object_file_still_saves(tmp_path):
    for content in (None, b"{not json", b"[1, 2]", b'"text"', b"\xff\xfe"):
        path = tmp_path / "audio.json"
        if path.exists():
            path.unlink()
        if content is not None:
            path.write_bytes(content)
        AS.AudioSettings(output_volume=30).save(path)
        saved = json.loads(path.read_text())
        assert saved == AS.AudioSettings(output_volume=30).to_dict()
