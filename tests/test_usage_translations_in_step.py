"""docs/USAGE_de.md and docs/USAGE_es.md keep the sections of docs/USAGE.md.

The translations had fallen behind: no Find Files, offline index or sift
sections (in English since 0.12.106) and four of the scripting subsections
missing. Each translation has as many ``##`` and ``###`` headings as the
English guide, in the same nesting, and the command lines and API names in
its code blocks are the English ones.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

DOCS = Path(__file__).resolve().parents[1] / "docs"
TRANSLATIONS = ("USAGE_de.md", "USAGE_es.md")


def _outline(text: str) -> list[str]:
    """The heading levels in order ("##", "###"), outside fenced code."""
    levels, fenced = [], False
    for line in text.splitlines():
        if line.startswith("```"):
            fenced = not fenced
            continue
        if not fenced and re.match(r"#{2,3} ", line):
            levels.append(line.split(" ", 1)[0])
    return levels


def _python_calls(text: str) -> set[str]:
    """The ``axross.<name>`` names used in the document."""
    return set(re.findall(r"axross\.([a-z_]+)\(", text))


@pytest.mark.parametrize("name", TRANSLATIONS)
def test_happy_a_translation_has_the_english_outline(name):
    english = _outline((DOCS / "USAGE.md").read_text(encoding="utf-8"))
    translated = _outline((DOCS / name).read_text(encoding="utf-8"))
    assert translated == english, (
        f"{name}: {translated.count('##')} H2 / {translated.count('###')} H3 against "
        f"{english.count('##')} / {english.count('###')} in USAGE.md - a section is missing")


@pytest.mark.parametrize("name", TRANSLATIONS)
def test_happy_a_translation_names_the_same_api_calls(name):
    english = _python_calls((DOCS / "USAGE.md").read_text(encoding="utf-8"))
    translated = _python_calls((DOCS / name).read_text(encoding="utf-8"))
    assert english - translated == set(), f"{name} lacks {sorted(english - translated)}"
