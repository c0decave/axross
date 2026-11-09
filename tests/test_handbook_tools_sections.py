"""The handbook documents the tools and bundled extensions the window has.

Found in the feature/icon/menu audit (2026-11-08): docs/USAGE.md - the
in-app Handbook that F1 opens - had no word on Arcade, Folder Treemap,
Entropy Heatmap, Backup Repositories, Image Batch, Disk Usage, Scheduled
Jobs, Recovery Scan, Diagnostics or the Scripting Guide, and never linked
docs/EXTENSIONS.md. The Media Player and Bluetooth paragraphs still sent
readers to Extensions > Manage Extensions… although the toolbar button and
Tools > Bluetooth switch them on now. A tool without a heading also has no
place for F1 to open, so each one gets a section, in every language.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"

#: English heading -> (German, Spanish) heading at the same place.
SECTIONS = {
    "## Tools": ("## Werkzeuge", "## Herramientas"),
    # German names since UX review round 9 (the menus' "Duplikatsuche…" and
    # "Speicherbelegung…").
    "### Duplicate Finder": ("### Duplikatsuche", "### Duplicate Finder"),
    "### Disk Usage": ("### Speicherbelegung", "### Disk Usage"),
    "### Scheduled Jobs": ("### Geplante Jobs", "### Scheduled Jobs"),
    "### Diagnostics and Recovery Scan": ("### Diagnose und Recovery-Scan",
                                          "### Diagnóstico y Recovery Scan"),
    "## Bundled extensions": ("## Mitgelieferte Extensions", "## Extensiones incluidas"),
    "### Arcade": ("### Arcade", "### Arcade"),
    "### Folder Treemap": ("### Ordner-Treemap", "### Folder Treemap"),
    "### Entropy Heatmap": ("### Entropy Heatmap", "### Entropy Heatmap"),
    "### Backup Repositories": ("### Backup Repositories", "### Backup Repositories"),
    "### Image Batch": ("### Image Batch", "### Image Batch"),
    "### System Information": ("### Systeminformationen", "### System Information"),
}
GUIDES = ("USAGE.md", "USAGE_de.md", "USAGE_es.md")


def _text(name: str) -> str:
    return (DOCS / name).read_text(encoding="utf-8")


def _headings(text: str) -> list[str]:
    out, fenced = [], False
    for line in text.splitlines():
        if line.startswith("```"):
            fenced = not fenced
        elif not fenced and re.match(r"#{2,3} ", line):
            out.append(line.strip())
    return out


def _section(text: str, heading: str) -> str:
    """The body of *heading* up to the next heading of any level."""
    lines = text.splitlines()
    start = lines.index(heading) + 1
    end = next((i for i in range(start, len(lines)) if re.match(r"#{2,3} ", lines[i])),
               len(lines))
    return "\n".join(lines[start:end])


def test_happy_every_tool_has_its_section_in_each_language():
    english = _headings(_text("USAGE.md"))
    for column, name in enumerate(GUIDES[1:]):
        translated = _headings(_text(name))
        for heading, translations in SECTIONS.items():
            assert heading in english, heading
            # the same place of the outline: F1 finds a translated section so
            want = translations[column]
            assert translated[english.index(heading)] == want, (name, heading, want)


@pytest.mark.parametrize("name", GUIDES)
def test_happy_each_section_says_where_the_tool_is(name):
    text = _text(name)
    english = _headings(_text("USAGE.md"))
    own = _headings(text)
    where = {
        "### Duplicate Finder": "Duplicate Finder…",
        "### Disk Usage": "Disk Usage…",
        "### Arcade": "Extensions → Arcade…",
        "### Entropy Heatmap": "Entropy Heatmap…",
        "### Backup Repositories": "Backup Repository Info…",
        "### Image Batch": "Resize / Convert Images…",
    }
    # The German handbook names each tool by its German label (de.json).
    german = json.loads((Path(__file__).resolve().parents[1] / "resources/i18n/de.json")
                        .read_text(encoding="utf-8"))
    # The menu entries' catalogue keys carry their letter.
    menu_keys = {"Duplicate Finder…": "&Duplicate Finder…", "Disk Usage…": "Dis&k Usage…"}
    for heading, needle in where.items():
        if name == "USAGE_de.md":
            needle = german.get(menu_keys.get(needle, needle), needle).replace("&", "")
        body = " ".join(_section(text, own[english.index(heading)]).split())
        assert needle in body, (name, heading, needle)
    assert "Scheduled Jobs…" in text or "Geplante Jobs…" in text, name
    assert "Recovery Scan…" in text or "Recovery-Scan…" in text, name
    assert "Run Active Pane Diagnostics…" in text or "Diagnose für aktives Pane…" in text, name
    assert ("Help → Scripting Guide" in text or "Hilfe → Scripting-Leitfaden" in text), name


@pytest.mark.parametrize("name", GUIDES)
def test_happy_the_handbook_links_the_extensions_guide(name):
    assert "](EXTENSIONS.md)" in _text(name), name


@pytest.mark.parametrize("name", GUIDES)
def test_sad_media_player_and_bluetooth_name_the_way_they_are_switched_on(name):
    """Not Extensions > Manage Extensions… - the toolbar button and Tools >
    Bluetooth offer to switch them on (MainWindow._switch_on_extension)."""
    text = " ".join(_text(name).split())
    for tool in ("Media Player", "Bluetooth"):
        m = re.search(r"- \*\*%s\*\* \(([^)]*)\)" % tool, text)
        assert m, (name, tool)
        assert "verwalten" not in m.group(1) and "Manage" not in m.group(1), (name, m.group(0))
    assert "Tools → Bluetooth" in text and "Extensions → Media Player" in text, name


def test_edge_the_named_menu_entries_exist_in_the_code():
    """The English menu labels the new sections name are the window's own."""
    source = (ROOT / "ui" / "main_window.py").read_text(encoding="utf-8")
    labels = {re.sub(r"&(?!&)", "", s).replace("&&", "&")
              for s in re.findall(r'tr\("([^"]+)"\)', source)}
    for label in ("Duplicate Finder…", "Duplicate Index & History…", "Disk Usage…",
                  "Scheduled Jobs…", "Run Active Pane Diagnostics…", "Recovery Scan…",
                  "Scripting Guide", "Bluetooth", "System Information…"):
        assert label in labels, label
    arcade = (ROOT / "resources" / "extensions" / "arcade.py").read_text(encoding="utf-8")
    assert 'add_menu_action(tr("Arcade…")' in arcade
    english = _text("USAGE.md")
    for path in ("View → Duplicate Index & History…", "View → Disk Usage…",
                 "View → Scheduled Jobs…", "Tools → Run Active Pane Diagnostics…",
                 "Tools → Recovery Scan…", "Help → Scripting Guide"):
        assert path in " ".join(english.split()), path
