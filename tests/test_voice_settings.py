"""Voice settings (core.voice_settings): a small typed API, one JSON file.

Every value is reachable through get/set with validation, so a matrix
test can set each one and see its effect without the UI.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import voice_settings as VS  # noqa: E402


def test_happy_defaults_are_the_operator_decisions():
    s = VS.VoiceSettings()
    assert s.input_mode == "push_to_talk"
    assert s.after_recognition == "insert"
    assert s.language == "auto"
    assert s.output_enabled is False
    assert s.gender in ("male", "female")
    assert VS.FIELDS.keys() == set(s.to_dict()) - {"version"}


@pytest.mark.parametrize("name,value", [
    ("output_enabled", True), ("language", "de"), ("language", "en"), ("gender", "female"),
    ("input_mode", "toggle"), ("input_mode", "conversation"), ("after_recognition", "send"),
    ("hotkey", "Ctrl+Shift+V"), ("hotkey", "F8"), ("silence_seconds", 2.5),
])
def test_happy_every_value_round_trips_through_set_get_save_load(tmp_path, name, value):
    path = tmp_path / "voice.json"
    s = VS.VoiceSettings()
    s.set(name, value)
    assert s.get(name) == value
    s.save(path)
    assert VS.VoiceSettings.load(path).get(name) == value


@pytest.mark.parametrize("name,value", [
    ("output_enabled", "yes"), ("language", "fr"), ("gender", "robot"),
    ("input_mode", "always"), ("after_recognition", "print"), ("hotkey", ""),
    ("hotkey", "A"), ("hotkey", "Ctrl+"), ("hotkey", "Ctrl+Nope"), ("silence_seconds", 0.1),
    ("silence_seconds", 99), ("silence_seconds", True),
])
def test_sad_invalid_values_are_refused(name, value):
    s = VS.VoiceSettings()
    before = s.get(name)
    with pytest.raises(ValueError):
        s.set(name, value)
    assert s.get(name) == before


def test_sad_unknown_setting_is_refused():
    with pytest.raises(KeyError):
        VS.VoiceSettings().set("volume", 3)
    with pytest.raises(KeyError):
        VS.VoiceSettings().get("volume")


def test_sad_a_broken_file_gives_defaults(tmp_path):
    path = tmp_path / "voice.json"
    path.write_text("{not json", encoding="utf-8")
    assert VS.VoiceSettings.load(path) == VS.VoiceSettings()
    path.write_text(json.dumps([1, 2]), encoding="utf-8")
    assert VS.VoiceSettings.load(path) == VS.VoiceSettings()


def test_edge_invalid_values_in_the_file_take_their_default(tmp_path):
    path = tmp_path / "voice.json"
    path.write_text(json.dumps({"language": "xx", "gender": "female", "silence_seconds": "x"}),
                    encoding="utf-8")
    s = VS.VoiceSettings.load(path)
    assert s.language == "auto" and s.gender == "female" and s.silence_seconds == 1.2


def test_edge_the_file_is_private_and_written_atomically(tmp_path):
    path = tmp_path / "sub" / "voice.json"
    VS.VoiceSettings().save(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert not list(path.parent.glob("*.tmp"))


def test_happy_the_default_file_lives_with_the_agent_settings():
    assert VS.settings_file().parent.name == "agent"
    assert VS.settings_file().name == "voice.json"


# -- which voice, which language ----------------------------------------------------------


@pytest.mark.parametrize("lang,gender,voice", [
    ("de", "male", "piper-de-thorsten"), ("de", "female", "piper-de-kerstin"),
    ("en", "male", "piper-en-ryan"), ("en", "female", "piper-en-lessac"),
])
def test_happy_language_and_gender_pick_the_voice(lang, gender, voice):
    assert VS.voice_for(lang, gender) == voice


def test_sad_unknown_language_or_gender_falls_back():
    assert VS.voice_for("fr", "male") == "piper-en-ryan"
    assert VS.voice_for("de", "x") == VS.voice_for("de", "male")


def test_happy_spoken_language_follows_the_setting_or_the_answer():
    assert VS.spoken_language("de", "The file is there.") == "de"
    assert VS.spoken_language("en", "Die Datei ist da.") == "en"
    assert VS.spoken_language("auto", "Die Datei ist da und gut.") == "de"
    assert VS.spoken_language("auto", "The file is there and fine.") == "en"


def test_edge_phrase_language_without_an_answer_follows_the_ui():
    assert VS.phrase_language("auto", ui_language="de") == "de"
    assert VS.phrase_language("auto", ui_language="pl") == "en"
    assert VS.phrase_language("en", ui_language="de") == "en"
