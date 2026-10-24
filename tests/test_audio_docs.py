"""The user docs know the Audio settings page (Edit > Settings… > Audio) and
the Media Player's way out when audio is off - and hold what they say to
the code: the page's title, its store, its buttons."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

GUIDES = ("docs/USAGE.md", "docs/USAGE_de.md", "docs/USAGE_es.md")
READMES = ("README.md", "README_de.md", "README_es.md")


def _text(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def _settings_table(text: str) -> list[str]:
    return re.findall(r"^\| ([^|]+?) \| ", text, re.M)


@pytest.mark.parametrize("name", GUIDES)
def test_happy_each_guide_lists_the_audio_page_in_the_settings_table(name):
    from ui.settings_dialog import _BUILTIN, CATEGORY_ORDER

    text = _text(name)
    row = re.search(r"^\| Audio \| (.+) \|$", text, re.M)
    assert row, "no Audio row in the settings table"
    for needle in ("PipeWire", "PulseAudio"):
        assert needle in row.group(1), needle
    assert _BUILTIN["audio"][0] == "Audio"
    # The table's order is the dialog's: Agent, Voice (its slot), Audio.
    rows = _settings_table(text)
    assert rows.index("Agent") < rows.index("Voice") < rows.index("Audio")
    assert CATEGORY_ORDER.index("agent") < CATEGORY_ORDER.index("voice") \
        < CATEGORY_ORDER.index("audio")


@pytest.mark.parametrize("name", GUIDES)
def test_happy_each_guide_names_the_store_and_the_media_players_way_out(name):
    from core import audio_settings as AS

    text = _text(name)
    assert "~/.config/axross/" + AS.settings_file().name in text
    assert "*Try Again*" in text and "*Audio Settings…*" in text


@pytest.mark.parametrize("name", READMES)
def test_happy_each_readme_names_the_audio_page(name):
    assert "Edit → Settings… → Audio" in _text(name)


def test_happy_the_extensions_doc_and_the_handbook_name_it():
    assert "*Try Again*" in _text("docs/EXTENSIONS.md")
    assert "*Audio Settings…*" in _text("docs/EXTENSIONS.md")
    handbook = _text("docs/HANDBUCH.md")
    assert "### Audio" in handbook and "Edit → Settings… → Audio" in handbook
    assert "PipeWire" in handbook and "PulseAudio" in handbook


def test_sad_the_buttons_the_docs_name_exist():
    """The docs' button names are the code's (a renamed button fails here)."""
    page = _text("ui/audio_settings_page.py")
    player = _text("resources/extensions/media_player.py")
    for label in ("Play Test Tone", "Test Microphone", "Record 3 s and Play Back",
                  "Check Audio Again"):
        assert f'tr("{label}")' in page, label
        assert f"*{label}*" in _text("docs/USAGE.md"), label
    for label in ("Try Again", "Audio Settings…"):
        assert f'tr("{label}")' in player, label


def test_edge_no_german_label_for_an_it_term_in_the_german_guide():
    """KEINE EINDEUTSCHUNGEN: the German guide says Backend, Device, Volume
    as the page does."""
    row = re.search(r"^\| Audio \| (.+) \|$", _text("docs/USAGE_de.md"), re.M).group(1)
    for word in ("Gerät", "Lautstärke", "Hintergrundprogramm"):
        assert word not in row, word
