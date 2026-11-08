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


def test_happy_every_narration_text_turns_into_speech_input():
    """Every German text of the shipped narration yields raw-phoneme blocks
    only for its braced parts, and no brace is left over."""
    narration = json.loads((ROOT / "resources" / "tour_narration.json").read_text("utf-8"))
    for tour in narration["tours"].values():
        texts = [tour["intro"], tour["outro"], *tour["steps"].values()]
        for text in texts:
            spoken = TV.piper_input(text["de"], "de", _fake_phonemes)
            assert "{" not in spoken and "}" not in spoken
            assert spoken.count("[[") == text["de"].count("{")
