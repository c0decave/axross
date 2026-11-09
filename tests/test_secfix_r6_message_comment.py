"""Round-6 Low finding: formatting-only spoof in message boxes
(ui/markup_guard.py defuse_message).

A message box shows its text as rich text when it looks like markup. An
archive member named ``report.pdf - <b>scan finished: no threats.</b> Safe
to open.<!--`` in "Could not open {member}:\\n{error}" loaded nothing and
held no link, so it was left as rich text: the comment hid the real error
and the user read the name's own verdict. A message box text with an HTML
comment in it is now shown as written; axross' own message texts hold none.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtGui import QTextDocument  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

import ui  # noqa: E402,F401 - installs the guard
from ui import markup_guard as MG  # noqa: E402

APP = QApplication.instance() or QApplication([])

MEMBER = "report.pdf - <b>scan finished: no threats.</b> Safe to open.<!--"
TEXT = f"Could not open {MEMBER}:\nPermissionError: unexpected executable payload"


def _reads(text: str) -> str:
    """What the user reads of *text* in a message box."""
    if not Qt.mightBeRichText(text):
        return text
    doc = QTextDocument()
    doc.setHtml(text)
    return doc.toPlainText()


def test_sad_a_comment_cannot_hide_the_rest_of_a_message():
    shown = MG.defuse_message(TEXT)
    assert shown != TEXT
    assert "PermissionError" in _reads(shown)
    assert "<!--" in _reads(shown)          # the name shows as it is written


def test_e2e_a_message_box_shows_the_error_after_a_hostile_name():
    box = QMessageBox(QMessageBox.Icon.Warning, "Open Archive", TEXT)
    assert "unexpected executable payload" in _reads(box.text())
    box.setText(f"cannot read {MEMBER}")
    assert "<b>" in _reads(box.text())
    box.setInformativeText(TEXT)
    assert "PermissionError" in _reads(box.informativeText())


def test_happy_our_own_rich_message_text_is_left_as_it_is():
    for text in ("<b>Bold</b> and plain", "Delete 3 items?", "a <!-- b without markup"):
        assert MG.defuse_message(text) == text


def test_edge_a_defused_text_is_not_defused_twice():
    once = MG.defuse_message(TEXT)
    assert MG.defuse_message(once) == once
