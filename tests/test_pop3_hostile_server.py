"""Pop3Session against servers that send what they should not.

Found by the POP3 / IMAP fuzz suites (tests/test_fuzz_pop3.py,
tests/test_fuzz_imap.py). The backend contract is OSError.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mail_fuzz_servers import FakePop3Server  # noqa: E402

from core import pop3_client as PC  # noqa: E402


def _session(srv) -> PC.Pop3Session:
    return PC.Pop3Session(srv.host, srv.port, "u", "p", use_ssl=False)


# --- the size cap applies while RETR is read ------------------------------
def _message(n_lines: int) -> bytes:
    return (
        b"+OK\r\n"
        + b"..x"
        + b"y" * 997
        + b"\r\n"
        + (b"z" * 1000 + b"\r\n") * (n_lines - 1)
        + b".\r\n"
    )


def test_happy_message_under_the_cap_is_read_whole(monkeypatch):
    monkeypatch.setattr(PC, "MAX_MESSAGE_BYTES", 1 << 20)
    with FakePop3Server(replies={"RETR": _message(100)}) as srv:
        data = _session(srv).open_read("/1_a.eml").read()
    assert data.startswith(b".x" + b"y" * 997 + b"\r\n")  # dot-unstuffed
    assert data.count(b"\r\n") == 99


def test_sad_endless_message_stops_at_the_cap_with_bounded_memory(monkeypatch):
    """poplib's retr() buffers the whole answer; the cap was checked only
    afterwards, so a server that never ends a message grew memory without
    bound."""
    import tracemalloc

    monkeypatch.setattr(PC, "MAX_MESSAGE_BYTES", 1 << 20)
    with FakePop3Server(replies={"RETR": _message(8000)}) as srv:
        s = _session(srv)
        tracemalloc.start()
        try:
            with pytest.raises(OSError, match="cap"):
                s.open_read("/1_a.eml")
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert peak < 4 << 20
        # The half-read answer is gone with its connection; the next call
        # works on a fresh one.
        assert [i.name for i in s.list_dir("/")] == ["1_hello.eml", "2_hello.eml"]


def test_edge_message_exactly_at_the_cap_is_allowed(monkeypatch):
    body = _message(10)
    cap = sum(len(line) + 2 for line in body.split(b"\r\n")[1:-2]) - 1  # dot-unstuffed size
    monkeypatch.setattr(PC, "MAX_MESSAGE_BYTES", cap)
    with FakePop3Server(replies={"RETR": body}) as srv:
        assert len(_session(srv).open_read("/1_a.eml").read()) > 0


# --- RFC 2047 words email.header cannot decode ----------------------------
def test_happy_encoded_subject_decodes():
    assert PC._decode_header("=?utf-8?B?SGVsbG8=?=") == "Hello"


@pytest.mark.parametrize("raw", ["=?utf-8?B? GVsbG8=?=", "=?utf-8?B?S?=", "=?utf-8?B?A===?="])
def test_sad_broken_base64_word_is_shown_raw(raw):
    assert PC._decode_header(raw) == raw


def test_edge_unknown_charset_still_falls_back():
    assert PC._decode_header("=?x-bogus?Q?abc?=") == "abc"


def test_sad_charset_with_nul_falls_back():
    # bytes.decode("\x00tf-8") raises ValueError("embedded null character"),
    # not LookupError.
    assert PC._decode_header("=?\x00tf-8?Q?abc?=") == "abc"
