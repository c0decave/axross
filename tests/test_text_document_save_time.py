"""Saving a text file never spends long working out its line endings.

Review: Ctrl+A, paste and Ctrl+S on a Markdown file of a few hundred
paragraphs hung the editor for minutes. TextDocument.encode ran difflib's
SequenceMatcher (autojunk=False; every blank line is the same line) over
all lines to give each the ending it had, although the file used LF only.

Now a file with one line-ending style skips the matcher (every line gets
that ending), and for a file that mixes them the matcher only sees a
changed middle small enough to be quick; a larger one keeps each line's
ending by position when the line count is the same, else gets the most
common ending.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.text_document import TextDocument  # noqa: E402


def _doc(text: str) -> TextDocument:
    doc = TextDocument(None, "")
    doc._remember(text)
    return doc


def _prose(word: str, n: int, sep: str = "\n\n") -> str:
    return sep.join(f"{word} {i}: the quick brown fox jumps over the lazy dog." for i in range(n))


def test_perf_happy_a_file_with_one_ending_saves_at_once_after_every_line_changed():
    old = _prose("Paragraph", 400) + "\n"
    new = _prose("Absatz", 400) + "\n"
    doc = _doc(old)
    started = time.monotonic()
    out = doc.encode(TextDocument.blocks_of(new))
    assert time.monotonic() - started < 1.0
    assert out == new.encode()


def test_perf_edge_a_file_mixing_endings_saves_quickly_after_every_line_changed():
    old = "".join(f"line {i}" + ("\r\n" if i % 2 else "\n") + "\n" for i in range(600))
    new_blocks = [x for i in range(450) for x in (f"Zeile {i}", "")] + [""]
    doc = _doc(old)
    started = time.monotonic()
    out = doc.encode(new_blocks).decode()
    assert time.monotonic() - started < 1.0
    assert TextDocument.blocks_of(out) == new_blocks


def test_happy_a_mixed_file_rewritten_line_for_line_keeps_each_ending():
    endings = ["\r\n" if i % 3 else "\n" for i in range(1200)]
    old = "".join(("" if i % 2 else f"value_{i} = 1") + e for i, e in enumerate(endings))
    doc = _doc(old)
    new_blocks = [b.replace("value", "item") for b in TextDocument.blocks_of(old)]
    started = time.monotonic()
    out = doc.encode(new_blocks).decode()
    assert time.monotonic() - started < 1.0
    assert out == "".join(("" if i % 2 else f"item_{i} = 1") + e for i, e in enumerate(endings))


def test_happy_a_small_edit_in_a_mixed_file_keeps_the_other_endings():
    old = "a\r\nb\nc\r\nd\n"
    doc = _doc(old)
    out = doc.encode(["a", "b", "new", "c", "d", ""]).decode()
    assert out == "a\r\nb\nnew\r\nc\r\nd\n"
