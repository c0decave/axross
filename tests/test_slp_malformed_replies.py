"""A malformed SLP reply reaches SlpSession's callers as OSError.

The slp_lib packet parsers raise on a truncated header, a lying length or
a wrong function id - as plain ValueError, which list_dir and open_read let
through to the pane (found by tests/test_fuzz_slp.py). They now raise
SlpProtocolError, an OSError that is still a ValueError for callers of the
parsers themselves.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import slp_client as SC  # noqa: E402
from core import slp_lib as SL  # noqa: E402


def _reply(function: int, body: bytes) -> bytes:
    total = 16 + len(body)
    return (
        struct.pack(">BB", 2, function) + total.to_bytes(3, "big") + b"\x00" * 5
        + struct.pack(">HH", 1, 2) + b"en" + body
    )


GOOD_URLS = _reply(SL.FN_SRV_RPLY, b"\x00\x00\x00\x01\x00\x01\x2c\x00\x05x://y\x00")


def test_happy_srv_reply_parses():
    assert SL.parse_srv_reply(GOOD_URLS) == [("x://y", 300)]


BAD = {
    "empty": b"",
    "short-header": GOOD_URLS[:10],
    "lang-tag-lies": b"\x02\x02\x00\x00\x10" + b"\x00" * 7 + b"\xff\xff",
    "wrong-function": _reply(SL.FN_ATTR_RPLY, b"\x00\x00\x00\x00"),
    "string-lies": _reply(SL.FN_SRV_TYPE_RPLY, b"\x00\x00\xff\xff"),
}


@pytest.mark.parametrize("packet", list(BAD.values()), ids=list(BAD))
def test_sad_malformed_reply_is_an_oserror_and_still_a_valueerror(packet):
    raised = 0
    for parse in (SL.parse_srv_type_reply, SL.parse_srv_reply, SL.parse_attr_reply):
        try:
            parse(packet)
        except SL.SlpProtocolError as exc:
            assert isinstance(exc, OSError) and isinstance(exc, ValueError)
            raised += 1
    assert raised >= 2  # at least the parsers for the other function ids refuse


def test_edge_backend_calls_report_oserror():
    s = SC.SlpSession.__new__(SC.SlpSession)
    s._types_cache = ["service:printer"]
    s._urls_cache = {}
    s._scope = b"DEFAULT"
    s._query = lambda packet: BAD["short-header"]
    with pytest.raises(OSError):
        s.list_dir("/service_printer")
    s._urls_cache = {"service:printer": [("x://y", 300)]}
    with pytest.raises(OSError):
        s.open_read("/service_printer/x___y.attrs")
