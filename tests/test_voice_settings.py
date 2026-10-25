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
    assert (s.voice_de, s.voice_en, s.tuning) == ("piper-de-thorsten", "piper-en-ryan", {})
    assert "gender" not in s.to_dict()  # the voice of each language replaced it
    assert VS.FIELDS.keys() == set(s.to_dict()) - {"version"}


@pytest.mark.parametrize("name,value", [
    ("output_enabled", True), ("language", "de"), ("language", "en"),
    ("voice_de", "piper-de-kerstin"), ("voice_en", "piper-en-lessac"),
    ("tuning", {"piper-en-ryan": {**VS.default_tuning(), "speed": 1.5, "pitch": -2.5}}),
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
    ("output_enabled", "yes"), ("language", "fr"), ("voice_de", "piper-en-ryan"),
    ("voice_en", "nope"), ("voice_de", "whisper-base"), ("voice_en", None),
    ("tuning", "x"), ("tuning", {"nope": {}}), ("tuning", {"piper-en-ryan": {"speed": 9}}),
    ("tuning", {"piper-en-ryan": {"loudness": 1.0}}),
    ("tuning", {"piper-en-ryan": {"speed": True}}),
    ("tuning", {"piper-en-ryan": "fast"}), ("tuning", {"whisper-base": {"speed": 1.5}}),
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
        VS.VoiceSettings().set("loudness", 3)
    with pytest.raises(KeyError):
        VS.VoiceSettings().get("gender")


def test_sad_a_broken_file_gives_defaults(tmp_path):
    path = tmp_path / "voice.json"
    path.write_text("{not json", encoding="utf-8")
    assert VS.VoiceSettings.load(path) == VS.VoiceSettings()
    path.write_text(json.dumps([1, 2]), encoding="utf-8")
    assert VS.VoiceSettings.load(path) == VS.VoiceSettings()


def test_edge_invalid_values_in_the_file_take_their_default(tmp_path):
    path = tmp_path / "voice.json"
    path.write_text(json.dumps({"language": "xx", "voice_de": "piper-en-ryan",
                                "silence_seconds": "x"}), encoding="utf-8")
    s = VS.VoiceSettings.load(path)
    assert s.language == "auto" and s.voice_de == "piper-de-thorsten" and s.silence_seconds == 1.2


def test_edge_an_old_file_with_a_gender_chooses_both_voices(tmp_path):
    """Before 0.13.134 one gender chose the voice of every language."""
    path = tmp_path / "voice.json"
    path.write_text(json.dumps({"gender": "female"}), encoding="utf-8")
    s = VS.VoiceSettings.load(path)
    assert (s.voice_de, s.voice_en) == ("piper-de-kerstin", "piper-en-lessac")
    path.write_text(json.dumps({"gender": "female", "voice_en": "piper-en-ryan"}),
                    encoding="utf-8")
    s = VS.VoiceSettings.load(path)  # a voice of its own wins over the old gender
    assert (s.voice_de, s.voice_en) == ("piper-de-kerstin", "piper-en-ryan")
    path.write_text(json.dumps({"gender": "robot"}), encoding="utf-8")
    assert VS.VoiceSettings.load(path) == VS.VoiceSettings()


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


def test_happy_each_language_has_its_own_voice():
    s = VS.VoiceSettings(voice_de="piper-de-kerstin", voice_en="piper-en-ryan")
    assert (s.voice("de"), s.voice("en")) == ("piper-de-kerstin", "piper-en-ryan")
    assert s.voice("fr") == "piper-en-ryan"  # a language without voices speaks English


def test_happy_every_pinned_voice_is_offered_in_its_language():
    from core import voice_models as VM

    pinned = {m.id: m.language for m in VM.MODELS if m.kind == "voice"}
    assert {v: lang for lang, ids in VS.VOICES.items() for v in ids} == pinned
    for field, lang in (("voice_de", "de"), ("voice_en", "en")):
        assert VS.VoiceSettings().get(field) in VS.VOICES[lang]


# -- how a voice speaks -------------------------------------------------------------------


def test_happy_the_tuning_ranges_hold_their_defaults():
    assert set(VS.TUNING) == {"speed", "pitch", "expressiveness", "rhythm", "volume", "pause"}
    for name, t in VS.TUNING.items():
        assert t.low < t.high and t.low <= t.default <= t.high, name
        for value in (t.low, t.default, t.high):  # whole steps: a slider shows them exactly
            assert abs(value / t.step - round(value / t.step)) < 1e-9, (name, value)
        assert VS.tuning_value_ok(name, t.low) and VS.tuning_value_ok(name, t.high)
    assert VS.default_tuning() == {n: t.default for n, t in VS.TUNING.items()}
    assert VS.TUNING["speed"].default == 1.0 and VS.TUNING["pitch"].default == 0.0


def test_happy_tuning_for_a_voice_fills_in_the_defaults():
    s = VS.VoiceSettings()
    assert s.tuning_for("piper-de-thorsten") == VS.default_tuning()
    s.set("tuning", {"piper-de-thorsten": {"speed": 1.25}})
    assert s.tuning_for("piper-de-thorsten") == {**VS.default_tuning(), "speed": 1.25}
    assert s.tuning == {"piper-de-thorsten": {**VS.default_tuning(), "speed": 1.25}}
    assert s.tuning_for("piper-en-ryan") == VS.default_tuning()  # each voice its own


def test_edge_a_voice_at_its_defaults_is_not_stored():
    s = VS.VoiceSettings()
    s.set("tuning", {"piper-de-thorsten": VS.default_tuning(), "piper-en-ryan": {"pitch": 1.0}})
    assert list(s.tuning) == ["piper-en-ryan"]
    assert s.to_dict()["tuning"] == {"piper-en-ryan": {**VS.default_tuning(), "pitch": 1.0}}


@pytest.mark.parametrize("name", ["speed", "pitch", "expressiveness", "rhythm", "volume",
                                  "pause"])
def test_sad_a_value_outside_its_range_is_refused(name):
    t = VS.TUNING[name]
    for bad in (t.low - t.step, t.high + t.step, float("nan"), float("inf"), "1", None, True):
        assert not VS.tuning_value_ok(name, bad), bad
        with pytest.raises(ValueError):
            VS.VoiceSettings().set("tuning", {"piper-en-ryan": {name: bad}})
    assert not VS.tuning_value_ok("loudness", 1.0)


def test_edge_a_hand_edited_tuning_keeps_what_is_valid(tmp_path):
    path = tmp_path / "voice.json"
    path.write_text(json.dumps({"tuning": {
        "piper-en-ryan": {"speed": 1.5, "pitch": 99, "loudness": 3},
        "piper-de-kerstin": "fast", "nope": {"speed": 1.5}, "whisper-base": {"speed": 1.5},
        "piper-de-thorsten": {"pitch": "high"},
    }}), encoding="utf-8")
    s = VS.VoiceSettings.load(path)
    assert s.tuning == {"piper-en-ryan": {**VS.default_tuning(), "speed": 1.5}}
    path.write_text(json.dumps({"tuning": [1, 2]}), encoding="utf-8")
    assert VS.VoiceSettings.load(path).tuning == {}


def test_edge_the_stored_tuning_is_a_copy():
    s = VS.VoiceSettings()
    given = {"piper-en-ryan": {"speed": 1.5}}
    s.set("tuning", given)
    given["piper-en-ryan"]["speed"] = 0.5
    s.tuning_for("piper-en-ryan")["speed"] = 0.7
    assert s.tuning_for("piper-en-ryan")["speed"] == 1.5
