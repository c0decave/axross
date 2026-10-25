"""The user docs know the Analysis (sift) settings page and hold what they
say to the code: its title, its place in the list, its store, its button."""

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


def _row(text: str) -> str:
    row = re.search(r"^\| Analysis \(sift\) \| (.+) \|$", text, re.M)
    assert row, "no Analysis (sift) row in the settings table"
    return row.group(1)


@pytest.mark.parametrize("name", GUIDES)
def test_happy_each_guide_lists_the_page_where_the_dialog_has_it(name):
    from ui.settings_dialog import _BUILTIN, CATEGORY_ORDER

    text = _text(name)
    _row(text)
    assert _BUILTIN["analysis"][0] == "Analysis (sift)"
    rows = re.findall(r"^\| ([^|]+?) \| ", text, re.M)
    place = rows.index("Analysis (sift)")
    assert rows.index("LLM Profiles") + 1 == place == rows.index("Agent") - 1
    assert CATEGORY_ORDER.index("llm") + 1 == CATEGORY_ORDER.index("analysis") \
        == CATEGORY_ORDER.index("agent") - 1


@pytest.mark.parametrize("name", GUIDES)
def test_happy_each_guide_names_the_store_the_cache_and_the_button(name):
    from core import analysis_settings as AS

    text = _text(name)
    row = _row(text)
    assert "*Clear Cache*" in row
    assert "~/.config/axross/" + AS.settings_file().name in text
    assert "~/.cache/axross/sift" in text


@pytest.mark.parametrize("name", READMES)
def test_happy_each_readme_names_the_page(name):
    # The README and its slideshow (where the Analysis screenshot moved) are one text.
    slideshow = name.replace("README", "slideshow")
    assert "Edit → Settings… → Analysis (sift)" in _text(name) + _text(slideshow)


def test_sad_the_button_the_docs_name_exists():
    assert 'tr("Clear Cache")' in _text("ui/analysis_settings_page.py")


def test_edge_no_german_label_for_an_it_term_in_the_german_guide():
    """KEINE EINDEUTSCHUNGEN: the German guide says Cache, Tags, Vision as
    the page does."""
    row = _row(_text("docs/USAGE_de.md"))
    for word in ("Zwischenspeicher", "Schlagwörter", "Bilderkennung"):
        assert word not in row, word
    for word in ("Cache", "Tags", "Vision"):
        assert word in row, word
