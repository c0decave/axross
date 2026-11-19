"""Second security review: sanitize_for_display let invisible characters
through - a zero width space makes two names look the same, a line or
paragraph separator breaks the line a name is shown in. They are shown as
U+FFFD now. What right-to-left names need stays: the directional marks
(U+200E, U+200F, U+061C) only place neutral characters and digits and
cannot reverse a name the way the overrides do; ZWNJ and ZWJ join or part
Persian, Indic and emoji. (The characters are written as escapes: no
invisible character is in this file.)"""

from __future__ import annotations

import pytest

from core.remote_name import sanitize_for_display

R = "\ufffd"


@pytest.mark.parametrize("char", [
    "\u200b",   # zero width space
    "\u2028",   # line separator
    "\u2029",   # paragraph separator
    "\u2060",   # word joiner
    "\u2061",   # invisible operator
    "\u2064",   # invisible operator
    "\u206a",   # deprecated format character
    "\u206f",   # deprecated format character
    "\ufeff",   # zero width no-break space
    "\u180e",   # Mongolian vowel separator
    "\u00ad",   # soft hyphen
    "\u3164",   # Hangul filler
    "\uffa0",   # halfwidth Hangul filler
    "\U000e0001",   # tag
    "\U000e0041",   # tag
    "\U000e007f",   # tag
])
def test_sad_an_invisible_character_is_shown(char):
    assert sanitize_for_display(f"rep{char}ort.pdf") == f"rep{R}ort.pdf"


@pytest.mark.parametrize("name", [
    "\u05d3\u05d5\u05d7\u200f 2024.pdf",   # Hebrew with RLM
    "\u062a\u0642\u0631\u064a\u0631\u061c 2024.txt",   # Arabic with ALM
    "report \u200e\u05d3\u05d5\u05d7.txt",   # LRM
    "\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645.txt",   # Persian with ZWNJ
    "family \U0001f468\u200d\U0001f469\u200d\U0001f467.png",   # ZWJ emoji
    "\u2764\ufe0f.txt",   # variation selector
    "\u0627\u0644\u0639\u0631\u0628\u064a\u0629.docx",   # Arabic
])
def test_happy_right_to_left_and_joined_names_display_unchanged(name):
    assert sanitize_for_display(name) == name


def test_sad_the_overrides_and_controls_stay_replaced():
    assert sanitize_for_display("invoice\u202efdp.exe") == f"invoice{R}fdp.exe"
    assert sanitize_for_display("a\nb\x00c") == f"a{R}b{R}c"
