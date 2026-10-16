"""Gopher entry names are single, safe path components.

_entry_to_filename() sanitised the display string, but when it came out
empty (a display of only NUL bytes or spaces) it fell back to the RAW
selector, so "0\\x00\\t/nul\\t..." listed as "/nul.txt" - a name with a
separator that no path built from it resolves back to (found by
tests/test_fuzz_gopher.py). "." and ".." were passed through as names too.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import gopher_client as G  # noqa: E402


def _entry(t, display, selector):
    return {"type": t, "display": display, "selector": selector, "host": "h", "port": 70}


def test_happy_display_names_are_kept():
    assert G._entry_to_filename(_entry("0", "readme", "/r")) == "readme.txt"
    assert G._entry_to_filename(_entry("1", "Docs", "/d")) == "Docs"
    assert G._entry_to_filename(_entry("0", "", "/dir/notes")) == "notes.txt"


@pytest.mark.parametrize(
    "t, display, selector",
    [
        ("0", "\x00\x00", "/nul"),
        ("0", "   ", "/a/b"),
        ("1", "\x00", "/x/"),
        ("0", "", "/"),
        ("/", "", ""),
        ("\x00", "", ""),
        ("1", "..", "/up"),
        ("0", ".", "/dot"),
        ("1", "", "/a/.."),
    ],
)
def test_sad_fallback_names_are_single_safe_components(t, display, selector):
    name = G._entry_to_filename(_entry(t, display, selector))
    assert name and "/" not in name and "\\" not in name and "\x00" not in name
    assert name not in (".", "..")


def test_edge_listed_names_resolve_back_to_their_entry():
    s = G.GopherSession.__new__(G.GopherSession)
    s._host, s._port, s._dir_cache = "h", 70, {}
    menu = G._parse_menu(b"0\x00\t/nul\th\t70\r\n1..\t/up\th\t70\r\n0ok\t/ok\th\t70\r\n")
    s._dir_cache["/"] = menu
    names = [i.name for i in s.list_dir("/")]
    assert len(names) == 3
    for name in names:
        assert s._entry_for_path("/" + name) is not None, name
