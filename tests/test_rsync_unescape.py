"""rsync's "\\#ooo" escapes are undone byte by byte before the output is
read as UTF-8. Measured: rsync 3.5.1 escapes the bytes 0x80-0x9f even with
--8-bit-output, so "Grüße" came out as "Grü\\udcc3\\#237e" (the 0xc3 0x9f of
the sharp s split into a lone byte and an escape) and stat() could not find
the file; rsync 3.4 printed the name as it is."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.rsync_client import _unescape_rsync_output  # noqa: E402


def _rsync_3_5(name: str) -> str:
    """*name* as rsync 3.5 prints it with -8: C1 bytes escaped, the rest
    raw (read back with surrogateescape, as _run_rsync does)."""
    raw = name.encode("utf-8")
    out = b"".join(b"\\#%03o" % b if 0x80 <= b <= 0x9F else bytes([b]) for b in raw)
    return out.decode("utf-8", "surrogateescape")


def test_happy_c1_escapes_inside_utf8_names_are_undone():
    for name in ("Grüße ü 名前 space.txt", "naïve—dash.txt", "plain.txt"):
        assert _unescape_rsync_output(_rsync_3_5(name)) == name


def test_happy_a_listing_line_keeps_its_columns():
    line = "-rw-r--r--              5 2026/10/21 12:00:00 " + _rsync_3_5("Grüße.txt")
    assert _unescape_rsync_output(line).endswith(" Grüße.txt")


def test_edge_an_escaped_control_byte_comes_back():
    assert _unescape_rsync_output("a\\#012b") == "a\nb"


def test_edge_text_without_escapes_is_unchanged():
    for text in ("", "no escapes here", "back\\slash", "\\#12 too short", "\\#89 not octal"):
        assert _unescape_rsync_output(text) == text


def test_sad_a_name_that_is_not_utf8_survives_as_surrogates():
    raw = b"caf\xe9.txt".decode("utf-8", "surrogateescape")
    assert _unescape_rsync_output("caf\\#351.txt") == raw
