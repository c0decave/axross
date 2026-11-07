"""docs/SCRIPTING_de.md and docs/SCRIPTING_es.md keep the sections of
docs/SCRIPTING.md.

The translations had two of the ten API subsections (no Open / connect, File
I/O, ... Duplicate index), referred to the English file for the table of
example scripts, wrote German without umlauts ("fuer", "oeffentliche") and
Spanish without accents ("publica", "estan"), and still advised
``axross --script resources/scripts/<name>.py`` - which prints nothing, since
an example only defines functions (the English guide says how to run one).
Same checks as tests/test_usage_translations_in_step.py: the outline, the
API calls, and here also the table of example scripts.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.test_usage_translations_in_step import _outline, _python_calls

DOCS = Path(__file__).resolve().parents[1] / "docs"
TRANSLATIONS = ("SCRIPTING_de.md", "SCRIPTING_es.md")

#: Transliterations that stand for a letter the language has.
ASCII_SPELLINGS = {
    "SCRIPTING_de.md": re.compile(
        r"\b(fuer|oeffentlich\w*|ueber|koennen|muessen|groesse\w*|aender\w*|schliess\w*|"
        r"loesch\w*|Schluessel\w*|zurueck|ausfuehr\w*)\b", re.IGNORECASE),
    "SCRIPTING_es.md": re.compile(
        r"\b(publica|estan|modulos|explicito|codigo|funcion|version|despues|tambien)\b"),
}


def _text(name: str) -> str:
    return (DOCS / name).read_text(encoding="utf-8")


def _example_scripts(text: str) -> list[str]:
    return re.findall(r"^\| `(\w+\.py)` \|", text, re.M)


@pytest.mark.parametrize("name", TRANSLATIONS)
def test_happy_a_translation_has_the_english_outline(name):
    english = _outline(_text("SCRIPTING.md"))
    translated = _outline(_text(name))
    assert english.count("###") == 10
    assert translated == english, (
        f"{name}: {translated.count('##')} H2 / {translated.count('###')} H3 against "
        f"{english.count('##')} / {english.count('###')} in SCRIPTING.md - a section is missing")


@pytest.mark.parametrize("name", TRANSLATIONS)
def test_happy_a_translation_names_the_same_api_calls(name):
    english = _python_calls(_text("SCRIPTING.md"))
    assert {"duplicates", "dedupe", "duplicate_scans", "move"} <= english
    missing = english - _python_calls(_text(name))
    assert missing == set(), f"{name} lacks {sorted(missing)}"


@pytest.mark.parametrize("name", TRANSLATIONS)
def test_happy_a_translation_lists_every_example_script(name):
    english = _example_scripts(_text("SCRIPTING.md"))
    assert len(english) >= 20
    assert _example_scripts(_text(name)) == english


@pytest.mark.parametrize("name", TRANSLATIONS)
def test_sad_no_ascii_spelling_of_a_letter_the_language_has(name):
    text = _text(name)
    hits = sorted(set(ASCII_SPELLINGS[name].findall(text)))
    assert hits == [], f"{name}: {hits}"


@pytest.mark.parametrize("name", ("SCRIPTING.md", *TRANSLATIONS))
def test_sad_no_guide_runs_an_example_file_that_only_defines_functions(name):
    assert "--script resources/scripts/" not in _text(name)
