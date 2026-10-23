"""The handbook (en, de, es) explains talking with the Agent dock - and
holds what it says to the code: the default hold key, the pip extra, the
store, the Settings page."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import voice_settings as VS  # noqa: E402

HEADINGS = {"USAGE.md": "### Talking with the agent", "USAGE_de.md": "### Mit dem Agent sprechen",
            "USAGE_es.md": "### Hablar con el agente"}


def _section(name: str) -> str:
    text = (ROOT / "docs" / name).read_text(encoding="utf-8")
    start = text.index(HEADINGS[name])
    end = text.index("\n## ", start)
    return text[start:end]


@pytest.mark.parametrize("name", HEADINGS)
def test_happy_each_handbook_explains_talking_to_the_agent(name):
    section = _section(name)
    assert f"**{VS.VoiceSettings().hotkey}**" in section  # the default hold key
    for needle in ("axross[voice]", "Settings > Voice", "Help > Features…", "Whisper", "Piper",
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
