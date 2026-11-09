"""The German handbook names the labels the German window shows.

UX review of 0.15.177, item 5: docs/USAGE_de.md - the German handbook, the
one F1 shows - emphasized some 220 English UI labels: *Connect to Server*,
**New Workspace**, *Open*, *Reveal in Pane*, *Try Again* ... for a window
that reads *Mit Server verbinden*, *Neuer Workspace*, *Öffnen*, *Im Pane
zeigen*, *Erneut versuchen*.

The authority is resources/i18n/de.json (its keys are the English source
strings): an emphasized span - *x*, **x**, or a segment of a menu path in
one (split on →, ▸ and >) - that is a key of the catalogue whose German
text differs from it must be written as the German text. Where the German
window keeps the English word (the catalogue maps it to itself) the
handbook keeps it too.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
GUIDE = ROOT / "docs" / "USAGE_de.md"
CATALOGUE = ROOT / "resources" / "i18n" / "de.json"

#: Emphasized spans that are a catalogue key but not a label of the window
#: in the place the handbook uses them - reviewed one by one.
ALLOWED: dict[str, str] = {
    "High": "the name of the built-in sandbox profile (core.agent_sandbox), shown as named",
    "Save As…": "the Text Editor's File menu entry \"Save &As…\" has no German entry yet, "
                "so the German editor shows it in English",
    "memory": "the name of an MCP server (the Research preset), not a label",
    "zoom": "a word typed into the settings search, which finds Zoom in German too",
}


def _norm(text: str) -> str:
    """A label as shown and compared: mnemonic "&" gone ("&&", and "&"
    before a space, is one "&"), no shortcut after a tab, "..." written "…",
    whitespace runs one space."""
    text = text.split("\t")[0]
    text = re.sub(r"&(?=\S)", "", text.replace("&&", "\0")).replace("\0", "&")
    return " ".join(text.replace("...", "…").split())


def key_index(catalogue: dict[str, str]) -> dict[str, set[str]]:
    """Normalised English key -> the normalised German texts it has."""
    index: dict[str, set[str]] = {}
    for key, value in catalogue.items():
        if isinstance(value, str) and value:
            key, value = _norm(key), _norm(value)
            index.setdefault(key, set()).add(value)
            # A field label: the handbook writes "*Filter*" for "Filter:".
            if key.endswith(":") and value.endswith(":"):
                index.setdefault(key[:-1].rstrip(), set()).add(value[:-1].rstrip())
    return index


def _prose(text: str) -> str:
    """*text* without fenced code blocks and `inline code`, its lines joined
    (an emphasized label may wrap)."""
    lines, fenced = [], False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if not fenced:
            lines.append(line)
    return re.sub(r"`[^`]*`", " ", " ".join(lines))


STRONG = re.compile(r"\*\*(?=\S)(.+?)(?<=\S)\*\*")
EMPHASIS = re.compile(r"(?<![\*\w])\*(?=[^\s*])([^*]+?)(?<=[^\s*])\*(?![\*\w])")
PATH_SEPARATOR = re.compile(r"\s*(?:→|▸|>)\s*")


def spans(text: str) -> list[str]:
    """Every emphasized span of the Markdown *text* and every segment of a
    menu path inside one."""
    prose = _prose(text)
    found = [m.group(1) for m in STRONG.finditer(prose)]
    found += [m.group(1) for m in EMPHASIS.finditer(STRONG.sub(" ", prose))]
    out: list[str] = []
    for span in found:
        span = " ".join(span.split())
        out.append(span)
        parts = [p for p in PATH_SEPARATOR.split(span) if p]
        if len(parts) > 1:
            out.extend(parts)
    return out


def english_labels(text: str, catalogue: dict[str, str],
                   allowed: dict[str, str] | None = None) -> list[str]:
    """The emphasized spans of *text* that are an English catalogue key the
    German window shows differently."""
    index = key_index(catalogue)
    # A text the German window shows somewhere is German there, even when it
    # is an English key too ("Profile" is German for "Profiles").
    shown = set().union(*index.values()) if index else set()
    allowed = ALLOWED if allowed is None else allowed
    bad: list[str] = []
    for span in spans(text):
        label = _norm(span).strip(" .,:;")
        if not label or label in allowed or label in shown:
            continue
        # The span as written decides; "Settings" also finds "Settings…".
        for candidate in (label, label + "…"):
            german = index.get(candidate)
            if german:
                if candidate not in german:
                    bad.append(span)
                break
    return bad


def _catalogue() -> dict[str, str]:
    return json.loads(CATALOGUE.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------


def test_happy_the_german_handbook_shows_no_english_ui_label():
    bad = english_labels(GUIDE.read_text(encoding="utf-8"), _catalogue())
    assert bad == [], f"{len(bad)} English labels: {sorted(set(bad))}"


def test_happy_german_labels_and_kept_english_words_pass():
    catalogue = {"&Open": "Ö&ffnen", "Workspace": "Workspace",
                 "Connect to Server": "Mit Server verbinden"}
    text = "Wähle *Öffnen* im *Workspace*, oder **Mit Server verbinden**."
    assert english_labels(text, catalogue, allowed={}) == []


def test_sad_an_english_label_is_reported():
    catalogue = {"Reveal in Pane": "Im Pane zeigen", "Try &Again": "&Erneut versuchen",
                 "Settings…": "Einstellungen…", "&Edit": "&Bearbeiten"}
    text = ("Ein Klick auf *Reveal in Pane* zeigt sie; **Try Again**\n"
            "versucht es noch einmal. *Bearbeiten → Settings...* öffnet sie.")
    assert english_labels(text, catalogue, allowed={}) == [
        "Try Again", "Reveal in Pane", "Settings..."]
    # Each segment of a menu path, whatever the arrow.
    for path in ("*Edit ▸ Einstellungen…*", "**Bearbeiten > Settings**", "*Edit → Settings…*"):
        assert english_labels(path, catalogue, allowed={}), path
    assert english_labels("*Bearbeiten ▸ Einstellungen…*", catalogue, allowed={}) == []


def test_sad_the_old_handbook_is_caught():
    """The handbook of 0.15.177 (before this fix) fails the check."""
    try:
        old = subprocess.run(["git", "show", "660a69d:docs/USAGE_de.md"], cwd=ROOT,
                             capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("no git history here")
    bad = english_labels(old, _catalogue())
    assert len(bad) > 100, bad
    assert "Connect to Server" in bad and "Reveal in Pane" in bad


def test_edge_code_mnemonics_ellipses_and_wrapped_spans():
    catalogue = {"&Settings...": "&Einstellungen…", "Move to Tr&ash": "In den Tr&ash verschieben",
                 "Open": "Öffnen"}
    # In code the English word is a name, not a label.
    assert english_labels("Setze `*Open*` oder\n```\n*Open*\n```\n", catalogue, allowed={}) == []
    # "..." and "…", with and without the ellipsis, a label wrapped over two lines.
    assert english_labels("*Settings*, *Settings...*, *Move to\n  Trash*", catalogue,
                          allowed={}) == ["Settings", "Settings...", "Move to Trash"]
    # A reviewed span is let through.
    assert english_labels("*Open*", catalogue, allowed={"Open": "a file name"}) == []
    # Bullets, multiplication and stray stars are no emphasis.
    assert spans("- a\n* b\n2 * 3 * 4\n") == []


def test_edge_every_allowed_span_has_a_reason_and_is_still_used():
    text = GUIDE.read_text(encoding="utf-8")
    used = {_norm(s).strip(" .,:;") for s in spans(text)}
    for span, reason in ALLOWED.items():
        assert reason.strip(), span
        assert span in used, f"{span!r} is allowed but the handbook no longer uses it"
