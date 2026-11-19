"""``[~x~]`` - a single-tilde strike inside a link label - crashed every
view with markdown-it 4.3 ("inline rule didn't increment state.pos") and
looped for ever with 4.2 (the released 0.16.0 binaries hung): the rule did
not move the position when markdown-it scanned the label silently."""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402

from core import markdown_doc as MD  # noqa: E402

CASES = ["See [~approx~ value] here.\n", "[~x~]\n", "[a ~b~ c](http://example.com)\n",
         "[~x~][ref]\n\n[ref]: http://example.com\n", "![~alt~](pic.png)\n"]


def _bounded(fn, *args, seconds=10):
    out = {}

    def run():
        try:
            out["v"] = fn(*args)
        except BaseException as exc:  # noqa: BLE001 - reported below
            out["e"] = exc

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(seconds)
    assert not t.is_alive(), "parsing hung"
    if "e" in out:
        raise out["e"]
    return out["v"]


@pytest.mark.parametrize("text", CASES)
def test_sad_a_single_tilde_inside_a_link_label_neither_raises_nor_hangs(text):
    pytest.importorskip("markdown_it")
    md = MD.make_parser()
    tokens = _bounded(md.parse, text)
    flat = [c.type for t in tokens for c in (t.children or [])]
    assert "s_open" in flat or "image" in flat


def test_happy_the_strike_inside_the_label_is_drawn_as_a_strike():
    pytest.importorskip("markdown_it")
    html = _bounded(MD.make_parser().render, "See [~approx~ value] here.\n")
    assert "<s>approx</s>" in html
