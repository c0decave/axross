"""IMAP: a message is named by its UID in ASCII digits (review round 2).

``\\d`` and ``int()`` take any Unicode digit: the path
``INBOX/\\uff11.eml`` (a fullwidth one) or ``INBOX/\\u0661`` (an
Arabic-Indic one) was parsed as a UID, and ``str(int(uid))`` made it
"1" - a move, flag change or delete of message 1, which the name never
named. Only ASCII digits are a UID now.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import imap_client as IC  # noqa: E402


def _session():
    s = object.__new__(IC.ImapSession)
    s._delimiter = "/"
    s._mailboxes = ["INBOX"]
    s._split_mailbox = lambda parts: (parts[0], parts[1:])
    return s


@pytest.mark.parametrize("leaf", ["\uff11.eml", "\u0661_subject.eml", "\u0661", "\uff11"])
def test_sad_unicode_digits_are_no_uid(leaf) -> None:
    assert _session()._parse_path("/INBOX/" + leaf) == ("INBOX", None)


def test_happy_ascii_uid() -> None:
    assert _session()._parse_path("/INBOX/42_hello.eml") == ("INBOX", "42")


@pytest.mark.parametrize("uid", ["\uff11", "\u0661", "1\u0662", "-1", " 1"])
def test_sad_api_uid_with_unicode_digits_is_refused(uid) -> None:
    with pytest.raises((ValueError, OSError)):
        IC._wire_uid(uid)


def test_happy_api_uid() -> None:
    assert IC._wire_uid(7) == "7"
    assert IC._wire_uid("12") == "12"
    assert IC._wire_uid(b"12") == "12"
