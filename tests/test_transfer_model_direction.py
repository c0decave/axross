"""The Direction column never needs a glyph that fonts rarely carry.

A move was marked with U+2700 (BLACK SAFETY SCISSORS, Unicode 7.0). No
font on the test host carries it (``fc-list ':charset=2700'`` lists none),
so the transfer dock drew a replacement box after the arrow. A move now
reads "<arrow> move"; the arrows themselves are in every common font.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from PyQt6.QtCore import Qt  # noqa: E402

from core.transfer_worker import TransferDirection, TransferJob  # noqa: E402
from models.transfer_model import COL_DIR, TransferModel  # noqa: E402

# Arrows block (U+2190-U+21FF) plus ASCII: what the column may contain.
_SAFE = {chr(c) for c in range(0x20, 0x7F)} | {chr(c) for c in range(0x2190, 0x2200)}


def _direction(direction: TransferDirection, move: bool) -> str:
    model = TransferModel()
    model.add_job(TransferJob(direction=direction, move=move, filename="f"))
    return model.data(model.index(0, COL_DIR), Qt.ItemDataRole.DisplayRole)


# --- happy ----------------------------------------------------------------


def test_happy_a_move_says_move_after_its_arrow():
    assert _direction(TransferDirection.UPLOAD, move=True) == "↑ move"
    assert _direction(TransferDirection.DOWNLOAD, move=True) == "↓ move"


def test_happy_a_copy_is_the_arrow_alone():
    assert _direction(TransferDirection.UPLOAD, move=False) == "↑"
    assert _direction(TransferDirection.DOWNLOAD, move=False) == "↓"


# --- sad ------------------------------------------------------------------


def test_sad_no_direction_text_uses_a_rare_symbol():
    texts = [_direction(d, m) for d in TransferDirection for m in (False, True)]
    assert all(set(t) <= _SAFE for t in texts), texts
    assert not any("✀" in t for t in texts)


# --- edge -----------------------------------------------------------------


@pytest.mark.parametrize("move", [False, True])
def test_edge_a_relay_keeps_its_two_way_arrow(move):
    text = _direction(TransferDirection.RELAY, move=move)
    assert text.startswith("⇄")
    assert text.endswith(" move") == move
