"""The handbook (en, de, es) explains talking with the Agent dock - and
holds what it says to the code: the default hold key, the pip extra, the
store, the Settings page."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import voice_settings as VS  # noqa: E402

HEADINGS = {"USAGE.md": "### Talking with the agent", "USAGE_de.md": "### Mit dem Agenten sprechen",
            "USAGE_es.md": "### Hablar con el agente"}


def _section(name: str) -> str:
    text = (ROOT / "docs" / name).read_text(encoding="utf-8")
    start = text.index(HEADINGS[name])
    end = text.index("\n## ", start)
    return text[start:end]


def _path(name: str, *labels: str) -> str:
    """A menu path as the guide's reader sees it: the German guide names
    the German labels, joined by "→" (it wrote "Settings > Voice" and
    "Help > Features…" where the window shows "Einstellungen" and "Hilfe →
    Funktionen…")."""
    if name == "USAGE_de.md":
        german = json.loads((ROOT / "resources/i18n/de.json").read_text(encoding="utf-8"))
        return " → ".join(german.get(label, label) for label in labels)
    return " > ".join(labels)


@pytest.mark.parametrize("name", HEADINGS)
def test_happy_each_handbook_explains_talking_to_the_agent(name):
    section = _section(name)
    assert f"**{VS.VoiceSettings().hotkey}**" in section  # the default hold key
    for needle in ("axross[voice]", _path(name, "Settings", "Voice"),
                   _path(name, "Help", "Features…"), "Whisper", "Piper",
                   "~/.local/share/axross/voice/", "/audio/transcriptions"):
        assert needle in section, needle


@pytest.mark.parametrize("name", HEADINGS)
def test_happy_the_settings_table_and_the_store_are_listed(name):
    text = (ROOT / "docs" / name).read_text(encoding="utf-8")
    assert re.search(r"^\| Voice \| ", text, re.M)
    assert "~/.config/axross/agent/voice.json" in text


@pytest.mark.parametrize("name", HEADINGS)
def test_sad_nothing_about_a_hidden_reply(name):
    low = (ROOT / "docs" / name).read_text(encoding="utf-8").lower()
    for word in ("pod bay", "podbay", "dave", " hal ", "hal."):
        assert word not in low, word


@pytest.mark.parametrize("name", HEADINGS)
def test_happy_each_handbook_explains_the_voices_and_how_they_speak(name):
    """The labels of the Voice page's voice tabs (English in every handbook,
    as on screen) and what Listen and Download do."""
    from ui.voice_settings_page import TUNING_LABELS

    section = _section(name)
    for label, _tip in TUNING_LABELS.values():
        assert f"*{label}*" in section, label
    for needle in ("**Listen**", "**Download**", "*Reset*", "*Reset All*",
                   _path(name, "Settings", "Audio")):
        assert needle in section, needle


@pytest.mark.parametrize("name", HEADINGS)
def test_happy_the_settings_table_names_listen_and_the_tuning(name):
    text = (ROOT / "docs" / name).read_text(encoding="utf-8")
    row = re.search(r"^\| Voice \| (.*)$", text, re.M).group(1)
    assert "Listen" in row and "Download" in row
