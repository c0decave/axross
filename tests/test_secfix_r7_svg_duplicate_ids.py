"""Round-7 finding L1: the SVG ``<use>`` cap was bypassed with duplicate ids
(core/previews.py _svg_expansion).

The gate worked out what a reference draws from the element an id names
*first* (``ids.setdefault``); QtSvg draws the *last* one. Every id declared
twice - an empty ``<g id="aN"/>`` first, the real fan-out group last - and
a 1780-byte file drew 1,000,000 elements (9.4 s), 2551 bytes 10^9. Ids
name one element each: a file that gives two elements the same id is
refused and gets no thumbnail.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import previews as P  # noqa: E402

HEAD = (b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"'
        b' width="100" height="100">')
LEAF = b'<path d="M0 0L100 100L0 100Z" fill="red"/>'


def dupid(levels: int, fan: int, dummies_first: bool = True) -> bytes:
    """The report's file (pt-rev7-sec/content/svg/svg_variants.py dupid)."""
    dummies = b"".join(b'<g id="a%d"/>' % i for i in range(1, levels + 1))
    real = b'<g id="a0">' + LEAF + b"</g>" + b"".join(
        b'<g id="a%d">' % i + b'<use xlink:href="#a%d"/>' % (i - 1) * fan + b"</g>"
        for i in range(1, levels + 1))
    body = dummies + real if dummies_first else real + dummies
    return HEAD + b"<defs>" + body + b'</defs><use xlink:href="#a%d"/></svg>' % levels


def test_sad_an_id_declared_twice_is_refused():
    for levels in (6, 9):
        data = dupid(levels, 10)
        started = time.monotonic()
        reason = P.svg_refusal(data)
        assert reason is not None and "same id" in reason, reason
        assert time.monotonic() - started < 1.0
    assert P.svg_refusal(dupid(6, 10, dummies_first=False)) is not None


def test_edge_id_and_xml_id_and_a_namespaced_id_count_alike():
    assert P.svg_refusal(HEAD + b'<g id="x"/><g xml:id="x"/></svg>') is not None
    assert P.svg_refusal(HEAD + b'<g id="x"/><circle id="x" r="1"/></svg>') is not None


def test_happy_distinct_ids_and_reuse_are_drawn():
    data = (HEAD + b'<defs><g id="dot"><circle r="2"/></g><g id="row">'
            + b'<use href="#dot"/>' * 5 + b"</g></defs>"
            + b'<use href="#row"/><use href="#row"/><g id="other"/></svg>')
    assert P.svg_refusal(data) is None


def test_e2e_the_dupid_file_gets_no_thumbnail(tmp_path):
    import pytest

    path = tmp_path / "dupid.svg"
    path.write_bytes(dupid(6, 10))
    started = time.monotonic()
    with pytest.raises(P.PreviewNotAvailable) as caught:
        P._render_svg(str(path), 128)
    assert "same id" in str(caught.value)
    assert time.monotonic() - started < 2.0
