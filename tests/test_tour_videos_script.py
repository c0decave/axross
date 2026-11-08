"""scripts/tour_videos.py: how narration becomes speech input.

The tour videos speak German narration with the German Piper voice, but
every IT term in braces - ``{Transfer Dock}`` - with English phonemes, so
the terms keep their English pronunciation in one voice. These are the pure
parts of that pipeline (no Piper, no ffmpeg, no Qt).
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("tour_videos", ROOT / "scripts" / "tour_videos.py")
TV = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(TV)


def _fake_phonemes(lang: str, text: str) -> str:
    return f"<{lang}:{text}>"


def test_happy_german_text_splits_into_german_and_english_parts():
    parts = TV.speech_parts("Zieh sie in den {Transfer Dock}, dann {Retry Failed}.", "de")
    assert parts == [("native", "Zieh sie in den "), ("english", "Transfer Dock"),
                     ("native", ", dann "), ("english", "Retry Failed"), ("native", ".")]


def test_happy_english_parts_become_raw_phonemes_for_the_german_voice():
    text = TV.piper_input("Das {Pane} zeigt den {Server}.", "de", _fake_phonemes)
    assert text == "Das [[ <en-us:Pane> ]] zeigt den [[ <en-us:Server> ]]."


def test_edge_english_narration_is_read_as_it_is():
    assert TV.speech_parts("Drag it to the transfer dock.", "en") == [
        ("native", "Drag it to the transfer dock.")]
    assert TV.piper_input("Drag it.", "en", _fake_phonemes) == "Drag it."


def test_edge_subtitles_drop_the_pronunciation_marks():
    assert TV.plain_text("Im {Transfer Dock} {Retry Failed} wählen.") == \
        "Im Transfer Dock Retry Failed wählen."


def test_happy_known_words_are_respelt_for_the_german_voice():
    spelt = {"pane": "Pejn", "server": "Sörwer"}
    text = TV.piper_input("Das {Pane} zeigt den {Server}.", "de", _fake_phonemes, spelt)
    assert text == "Das Pejn zeigt den Sörwer."


def test_edge_unknown_words_of_a_term_fall_back_to_phonemes():
    spelt = {"retry": "Ritrei"}
    text = TV.piper_input("Dann {Retry Failed Items}, fertig.", "de", _fake_phonemes, spelt)
    assert text == "Dann Ritrei [[ <en-us:Failed Items> ]], fertig."


def test_edge_hyphenated_terms_are_respelt_word_by_word():
    spelt = TV.load_respellings("de")
    assert TV.piper_input("Ein {One-File-Build}.", "de", _fake_phonemes, spelt) == \
        "Ein Wann Fail Bild."


def test_happy_every_narration_text_turns_into_speech_input():
    """Every German text of the shipped narration is speech input without a
    brace left, and every English word in it has a respelling - a new term
    in the narration needs one in scripts/tour_pronunciation.json (or it is
    read as English phonemes, which came out less clear)."""
    narration = json.loads((ROOT / "scripts" / "tour_narration.json").read_text("utf-8"))
    spelt = TV.load_respellings("de")
    missing = set()
    for tour in narration["tours"].values():
        texts = [tour["intro"], tour["outro"], *tour["steps"].values()]
        for text in texts:
            spoken = TV.piper_input(text["de"], "de", _fake_phonemes, spelt)
            assert "{" not in spoken and "}" not in spoken
            for _kind, term in TV.speech_parts(text["de"], "de"):
                missing |= {w for k, w in TV.english_words(term, spelt) if k == "english"} \
                    if _kind == "english" else set()
            without = TV.piper_input(text["de"], "de", _fake_phonemes)
            assert without.count("[[") == text["de"].count("{")
    assert not missing, f"no respelling for: {sorted(missing)}"


def test_happy_the_manifest_pins_every_rendered_video(tmp_path):
    import hashlib

    for lang, tour in (("en", "connect"), ("de", "connect")):
        (tmp_path / lang).mkdir(exist_ok=True)
        (tmp_path / lang / f"{tour}.mp4").write_bytes(f"{lang}-{tour}".encode())
    target = tmp_path / "tour_videos.json"
    data = TV.write_manifest(tmp_path, "tour-videos-9", target)
    assert data["tag"] == "tour-videos-9"
    pin = data["videos"]["de/connect"]
    assert pin == {"file": "axross-tour-de-connect.mp4", "size": len(b"de-connect"),
                   "sha256": hashlib.sha256(b"de-connect").hexdigest()}
    assert (tmp_path / "release" / "axross-tour-de-connect.mp4").read_bytes() == b"de-connect"
    assert json.loads(target.read_text("utf-8")) == data


def test_edge_a_second_run_does_not_pin_its_own_release_copies(tmp_path):
    (tmp_path / "en").mkdir()
    (tmp_path / "en" / "connect.mp4").write_bytes(b"x")
    target = tmp_path / "m.json"
    TV.write_manifest(tmp_path, "t-1", target)
    assert list(TV.write_manifest(tmp_path, "t-1", target)["videos"]) == ["en/connect"]
