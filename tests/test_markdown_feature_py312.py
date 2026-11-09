"""The release-notes Markdown flags build on Python 3.12 too.

Python 3.12's enum refuses MarkdownFeature(value) for a value that is no
member; 3.11 returned a member with fewer bits. The table-less flag set
(GitHub dialect without 0x100) is such a value, and the main window
failed to start on 3.12 - caught by the cross-platform smoke job.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtGui")

from PyQt6.QtGui import QTextDocument  # noqa: E402

from ui import update_ui as U  # noqa: E402


def test_sad_a_non_member_value_is_built_by_hand_when_the_enum_refuses_it(monkeypatch):
    members = {m.value for m in QTextDocument.MarkdownFeature}
    real = U._feature_member

    def strict(value):
        """Behaves like 3.12: a value that is no member raises ValueError."""
        if value not in members:
            raise ValueError(f"{value!r} is not a valid MarkdownFeature")
        return real(value)

    monkeypatch.setattr(U, "_feature_member", strict)
    union = U._markdown_feature(U.NOTES_MARKDOWN.value & ~0x100)
    assert union.value == U.NOTES_MARKDOWN.value & ~0x100


def test_happy_the_two_flag_sets_keep_their_bits():
    assert U.NOTES_MARKDOWN_NO_TABLES.value == U.NOTES_MARKDOWN.value & ~0x100
    assert U.NOTES_MARKDOWN.value & 0x100
