"""The handbook (en, de, es) explains agent profiles - and holds what it
says to the code: every preset with its categories as the code has them,
the menu entries as they are on screen, the settings keys."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import agent_profiles as AP  # noqa: E402

HEADINGS = {"USAGE.md": "**Agent profiles**", "USAGE_de.md": "**Agent-Profile**",
            "USAGE_es.md": "**perfiles de agente**"}


def _section(name: str) -> str:
    text = (ROOT / "docs" / name).read_text(encoding="utf-8")
    start = text.index(HEADINGS[name])
    end = text.index("**Sandboxes**", start)
    return text[start:end]


@pytest.mark.parametrize("name", HEADINGS)
def test_happy_every_preset_is_in_the_table_with_its_categories(name):
    section = _section(name)
    for preset in AP.presets():
        row = next((line for line in section.splitlines()
                    if line.startswith(f"| {preset.name} |")), None)
        assert row is not None, preset.name
        for category in preset.mcp_categories:
            assert f"*{category}*" in row, (preset.name, category)
        for server in preset.mcp_servers:
            assert f"*{server}*" in row, (preset.name, server)


@pytest.mark.parametrize("name", HEADINGS)
def test_happy_the_menu_entries_and_the_store_are_named_as_on_screen(name):
    section = " ".join(_section(name).split())  # a phrase may wrap
    for needle in ("New Tab from Profile", "Apply Profile…", "Edit Agent Profiles…",
                   "Install from Catalog…", "Tools > New Agent Tab from Profile",
                   "Agent Settings > **Profiles**", "*(preset)*", "*Copy*",
                   "~/.config/axross/agent/settings.json", "`agent_profiles`",
                   "`agent_profile`", "Agent Settings > Access", "*Category*"):
        assert needle in section, needle


@pytest.mark.parametrize("name", HEADINGS)
def test_sad_no_preset_or_category_is_named_that_the_code_does_not_have(name):
    section = _section(name)
    names = {p.name for p in AP.presets()}
    rows = [line.split("|")[1].strip() for line in section.splitlines()
            if line.startswith("| ") and not line.startswith("| Preset")]
    assert set(rows) == names
    for word in section.split("*"):
        if word.startswith("Security: "):
            assert word in AP.HUB_CATEGORIES, word


def test_edge_the_german_handbook_keeps_the_it_terms():
    section = _section("USAGE_de.md")
    for term in ("Preset", "Settings", "Catalog", "Sandbox", "Tool-Gruppen", "Mode"):
        assert term in section, term
    for german in ("Voreinstellung", "Vorlage", "Katalog", "Werkzeug"):
        assert german not in section, german
