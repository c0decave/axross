"""Round-6 finding L2: an SVG ``<use>`` fan-out pinned the thumbnail worker
(core/previews.py svg_refusal / _render_svg).

Each ``<use>`` draws its target again, its target's references included:
ten levels of ten references - a 2.4 KB file - drew a billion paths (10^6
took 12.6 s), and svg_refusal let it through. Now a streaming parse works
out what the references draw before QtSvg sees the file; past
MAX_SVG_USE_EXPANSION elements, or a reference cycle, the file is refused
and gets no thumbnail.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import previews as P  # noqa: E402

HEAD = (b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"'
        b' width="100" height="100">')


def fan_out(levels: int, fan: int, attr: bytes = b"xlink:href") -> bytes:
    """The report's file (pt-rev6-sec/content/preview/svg_use.py)."""
    parts = [HEAD, b"<defs>",
             b'<g id="a0"><path d="M0 0L100 100L0 100Z" fill="red" stroke="blue" stroke-width="3"/></g>']
    for i in range(1, levels + 1):
        parts.append(b'<g id="a%d">' % i + (b'<use %s="#a%d"/>' % (attr, i - 1)) * fan + b"</g>")
    parts.append(b'</defs><use %s="#a%d"/></svg>' % (attr, levels))
    return b"".join(parts)


@pytest.mark.parametrize("levels", [6, 9])
def test_sad_a_use_fan_out_is_refused_before_it_is_drawn(levels):
    data = fan_out(levels, 10)
    assert len(data) < 3000
    started = time.monotonic()
    reason = P.svg_refusal(data)
    assert reason is not None and "references" in reason
    assert time.monotonic() - started < 2.0


def test_sad_plain_href_and_url_references_count_too():
    assert P.svg_refusal(fan_out(6, 10, b"href")) is not None
    fill = (HEAD + b'<defs><g id="p"><circle r="1"/></g></defs>'
            + b'<rect fill="url(#p)" width="1" height="1"/>' * 30_000 + b"</svg>")
    assert P.svg_refusal(fill) is not None


def test_edge_a_reference_cycle_is_refused():
    assert P.svg_refusal(HEAD + b'<g id="a"><use href="#a"/></g></svg>') is not None
    assert P.svg_refusal(HEAD + b'<g id="a"><use href="#b"/></g><g id="b"><use href="#a"/></g></svg>') is not None


def test_happy_ordinary_reuse_is_drawn():
    icons = (HEAD + b'<defs><g id="dot"><circle r="2"/><circle r="1" fill="white"/></g></defs>'
             + b'<use xlink:href="#dot" x="3"/>' * 500 + b"</svg>")
    assert P.svg_refusal(icons) is None
    assert P.svg_refusal(fan_out(3, 10)) is None          # a thousand draws
    # a reference to an id that is not there draws nothing
    assert P.svg_refusal(HEAD + b'<use href="#missing"/></svg>') is None


def test_edge_a_large_flat_file_is_checked_in_linear_time():
    data = HEAD + b"<g/>" * 200_000 + b"</svg>"
    started = time.monotonic()
    assert P.svg_refusal(data) is None
    assert time.monotonic() - started < 5.0


_RENDER = """
import sys, time
sys.path.insert(0, sys.argv[2])
from PyQt6.QtGui import QGuiApplication
app = QGuiApplication([])
from core import previews as P
start = time.perf_counter()
try:
    P._render_svg(sys.argv[1], 256)
    print("RENDERED", flush=True)
except P.PreviewNotAvailable:
    print("REFUSED", time.perf_counter() - start, flush=True)
"""


def test_e2e_the_thumbnail_of_a_use_bomb_is_refused_quickly(tmp_path):
    """In a child with a timeout: before, the render never came back."""
    import subprocess

    pytest.importorskip("PyQt6.QtSvg")
    bomb = tmp_path / "bomb.svg"
    bomb.write_bytes(fan_out(9, 10))
    root = str(Path(__file__).resolve().parents[1])
    try:
        out = subprocess.run([sys.executable, "-c", _RENDER, str(bomb), root],
                             capture_output=True, text=True, timeout=30, cwd=root)
    except subprocess.TimeoutExpired:
        pytest.fail("rendering the SVG did not end within 30 s")
    assert "REFUSED" in out.stdout, out.stdout + out.stderr[-2000:]
    assert float(out.stdout.split("REFUSED", 1)[1].split()[0]) < 2.0
