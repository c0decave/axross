"""scripts/tour_narration.json: the spoken text of the tour videos.

Each step of a guided tour (ui.tours.TOURS) gets a short video: a screenshot
with the tour's highlight and callout, and a Piper voice reading this text
(German "Thorsten", English "Ryan"). The voice reads what is written, so the
file is held to what reads well aloud. Covered here, and why:

- **Complete and exact.** Every tour has an intro, an outro and a text for
  each step, keyed by the English step title of ui/tours.py, in English and
  German - and nothing else: a renamed step or a dropped tour fails here
  instead of leaving a silent video segment.
- **Nothing a voice reads badly.** No tour symbols, no paths, no brackets,
  no ellipses, no dashes as separators, no "e.g." - each would be read out
  as a character name or garbled.
- **English terms in German.** The German voice speaks a part in curly
  braces with English pronunciation: braces balance and do not nest, the
  English text has none, and every common IT term in a German text sits
  inside braces.
- **Short.** A step is about 15-30 seconds spoken; a text far longer than
  that is a paragraph, not narration.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from ui.tours import TOURS  # noqa: E402

NARRATION = ROOT / "scripts" / "tour_narration.json"
LANGS = ("en", "de")

#: Characters a TTS voice reads badly or not at all.
FORBIDDEN = "◎↑⌂☆↻◉→~/()…<>[]+&*;–—"
#: Written forms that read badly: separator dashes, option dashes, "e.g.", "...".
FORBIDDEN_SEQUENCES = (" - ", "--", "e.g.", "...")

#: IT terms the German text keeps in English; each must be in braces.
IT_TERMS = (
    "Agent", "API", "Bookmark", "Build", "Bytes", "Client", "Connection Manager",
    "Console", "Countdown", "Dock", "Download", "Drag and Drop", "Extension",
    "Feature", "Fingerprint", "Host", "Job", "Keyring", "Layout", "Login", "Pack",
    "Pane", "Plugin", "Profile", "Prompt", "Proxies", "Proxy", "Release", "Remote",
    "Script", "Server", "Shortcut", "Sync", "Tab", "Tag", "Task", "Tool", "Tooltip",
    "Transfer", "Trash", "Upload", "Workspace", "Escape", "Enter", "Python", "axross",
)

MAX_STEP_CHARS = 520
MAX_FRAME_CHARS = 260  # intro and outro
MIN_CHARS = 20


def _load() -> dict:
    return json.loads(NARRATION.read_text(encoding="utf-8"))


def _texts():
    """(where, kind, lang, text) for every text in the file."""
    for tour_id, entry in _load()["tours"].items():
        for kind in ("intro", "outro"):
            for lang, text in entry[kind].items():
                yield f"{tour_id}/{kind}", kind, lang, text
        for title, langs in entry["steps"].items():
            for lang, text in langs.items():
                yield f"{tour_id}/{title}", "step", lang, text


def _outside_braces(text: str) -> str:
    return re.sub(r"\{[^{}]*\}", " ", text)


def _unbraced_terms(text: str) -> list[str]:
    rest = _outside_braces(text)
    return [term for term in IT_TERMS
            if re.search(rf"(?i)\b{re.escape(term)}(s|es|en|n)?\b", rest)]


def _braces_ok(text: str) -> bool:
    depth = 0
    for char in text:
        if char == "{":
            depth += 1
            if depth > 1:
                return False
        elif char == "}":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


# ---------------------------------------------------------------------------
# Complete and exact
# ---------------------------------------------------------------------------

def test_happy_file_has_version_and_every_tour():
    data = _load()
    assert data["version"] == 1
    assert set(data["tours"]) == {t.id for t in TOURS}


def test_happy_every_step_is_narrated_in_both_languages():
    tours = _load()["tours"]
    for t in TOURS:
        entry = tours[t.id]
        assert set(entry) == {"intro", "steps", "outro"}, t.id
        assert set(entry["steps"]) == {s.title for s in t.steps}, t.id
        for kind in ("intro", "outro"):
            assert set(entry[kind]) == set(LANGS), (t.id, kind)
        for title, langs in entry["steps"].items():
            assert set(langs) == set(LANGS), (t.id, title)


def test_happy_every_text_is_a_non_empty_string():
    for where, _kind, lang, text in _texts():
        assert isinstance(text, str) and text.strip() == text and text, (where, lang)


def test_sad_unknown_step_titles_are_found():
    """The completeness check above would see a step that is not in TOURS."""
    first = TOURS[0]
    narrated = set(_load()["tours"][first.id]["steps"]) | {"A step that is not there"}
    assert narrated != {s.title for s in first.steps}


# ---------------------------------------------------------------------------
# Nothing a voice reads badly
# ---------------------------------------------------------------------------

def test_happy_no_forbidden_characters():
    for where, _kind, lang, text in _texts():
        bad = sorted({c for c in text if c in FORBIDDEN})
        assert not bad, (where, lang, bad)


def test_happy_no_forbidden_sequences():
    for where, _kind, lang, text in _texts():
        for seq in FORBIDDEN_SEQUENCES:
            assert seq not in text, (where, lang, seq)


def test_happy_no_written_shortcuts():
    """Ctrl+X, Strg+X, Esc and Del are spelled out for the voice."""
    for where, _kind, lang, text in _texts():
        assert not re.search(r"\b(Ctrl|Strg|Esc|Del|Entf|PgUp|PgDown)\b", text), (where, lang)


# ---------------------------------------------------------------------------
# English terms in German
# ---------------------------------------------------------------------------

def test_happy_german_braces_balanced_and_flat():
    for where, _kind, lang, text in _texts():
        if lang == "de":
            assert _braces_ok(text), where
            assert "{}" not in text, where


def test_happy_english_has_no_braces():
    for where, _kind, lang, text in _texts():
        if lang == "en":
            assert "{" not in text and "}" not in text, where


def test_happy_german_it_terms_are_braced():
    for where, _kind, lang, text in _texts():
        if lang == "de":
            assert not _unbraced_terms(text), (where, _unbraced_terms(text))


def test_sad_unbraced_term_is_found():
    assert _unbraced_terms("Zieh die Dateien in das Pane.") == ["Pane"]
    assert _unbraced_terms("Die Server-Verbindung steht.") == ["Server"]
    assert _unbraced_terms("Klick auf die Tabs.") == ["Tab"]


def test_sad_unbalanced_or_nested_braces_are_found():
    assert not _braces_ok("Das {Pane ist offen.")
    assert not _braces_ok("Das Pane} ist offen.")
    assert not _braces_ok("Ein {Server {Proxy}}.")
    assert _braces_ok("Ein {Server} und ein {Proxy}.")


def test_edge_term_inside_braces_or_german_word_is_fine():
    assert _unbraced_terms("Das {Ziel-Pane} und die {Server}-Verbindung.") == []
    # German words that only begin like a term are not terms.
    assert _unbraced_terms("Wir synchronisieren die Tabelle am Tage.") == []


# ---------------------------------------------------------------------------
# Short
# ---------------------------------------------------------------------------

def test_happy_texts_have_a_sane_length():
    for where, kind, lang, text in _texts():
        limit = MAX_STEP_CHARS if kind == "step" else MAX_FRAME_CHARS
        assert MIN_CHARS <= len(text) <= limit, (where, lang, len(text))


def test_edge_outro_is_one_sentence():
    for where, kind, lang, text in _texts():
        if kind == "outro":
            assert text.endswith(".") and text.count(". ") == 0, (where, lang)
