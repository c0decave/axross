"""PJL: a folder listing has no '.' / '..' entries, and a read is exactly
the bytes FSUPLOAD declares.

Review of 2026-10-17 (B28, B33):
- FSDIRLIST's "." and ".." lines came back as folders of the listing.
- Bytes after the declared SIZE (a form feed and CRLF) were returned as
  part of the file; and the body was found at the first blank line of
  the whole answer, so a device that sends no blank line after the
  FSUPLOAD line got its header handed back as content (or data with a
  blank line in it cut at the wrong place).
"""

from __future__ import annotations

import pytest

from core import pjl_client as PJ
from tests.test_pjl_truncated_upload import _Device, _read

UEL = PJ.UEL
STATUS = b"@PJL INFO STATUS\r\nCODE=10001\r\n"


def _line(size):
    return b'@PJL FSUPLOAD FORMAT:BINARY NAME="0:/report.txt" OFFSET=0 SIZE=%d\r\n' % size


def test_happy_dot_entries_are_not_listed():
    blob = (STATUS + b'@PJL FSDIRLIST NAME="0:/" ENTRY=1\r\n'
            b". TYPE=DIR\r\n.. TYPE=DIR\r\nPJL TYPE=DIR\r\nreport.txt TYPE=FILE SIZE=5\r\n" + UEL)
    assert [(i.name, i.is_dir) for i in PJ.PjlSession._parse_fsdirlist(blob)] == [
        ("PJL", True), ("report.txt", False)]


def test_happy_the_read_stops_at_the_declared_size():
    with _Device(STATUS + _line(5) + b"\r\nhello\x0c\r\n" + UEL) as dev:
        assert _read(dev) == b"hello"


def test_sad_without_a_blank_line_the_header_is_not_content():
    with _Device(STATUS + _line(5) + b"hello\x0c" + UEL) as dev:
        assert _read(dev) == b"hello"


@pytest.mark.parametrize("blank", [b"", b"\r\n"])
def test_edge_data_with_blank_lines_in_it_is_read_whole(blank):
    data = b"a\r\n\r\nb\r\n\r\n"
    with _Device(STATUS + _line(len(data)) + blank + data + b"\x0c" + UEL) as dev:
        assert _read(dev) == data
