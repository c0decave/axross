"""Exchange upload: a body in an unknown or broken charset still decodes.

Twin of the IMAP / POP3 header fixes (0.9.17, 0.9.21):
core/exchange_client._extract_text_body decoded the text part with the
charset the MIME headers name, so ``charset="x-bogus"`` raised
LookupError and a charset with a NUL ValueError ("embedded null
character") out of the .eml upload path.
"""

from __future__ import annotations

import email
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.exchange_client import _extract_text_body  # noqa: E402


def _msg(charset: str, body: bytes = b"caf\xc3\xa9") -> email.message.Message:
    return email.message_from_bytes(
        b"Subject: t\r\nContent-Type: text/plain; charset=" + charset.encode() + b"\r\n\r\n" + body
    )


def test_happy_utf8_body():
    assert _extract_text_body(_msg("utf-8")) == "café"


@pytest.mark.parametrize("charset", ["x-bogus", '"utf\\x00-8"', "utf-8\x00"])
def test_sad_unknown_or_broken_charset_falls_back(charset):
    assert _extract_text_body(_msg(charset)) == "café"


def test_edge_multipart_with_bogus_charset():
    raw = (
        b'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
        b"--b\r\nContent-Type: text/plain; charset=x-bogus\r\n\r\nhi\r\n--b--\r\n"
    )
    assert _extract_text_body(email.message_from_bytes(raw)).strip() == "hi"
