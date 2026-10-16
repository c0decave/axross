"""ImapSession against servers that send what they should not.

Found by the IMAP fuzz suite (tests/test_fuzz_imap.py). The backend
contract is OSError, which is all the pane and the transfer worker catch.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mail_fuzz_servers import FakeImapServer  # noqa: E402

from core import imap_client as IC  # noqa: E402


@pytest.fixture(autouse=True)
def _short_timeout(monkeypatch):
    monkeypatch.setattr(IC, "IMAP_TIMEOUT", 2.0)


def _session(srv) -> IC.ImapSession:
    return IC.ImapSession(srv.host, srv.port, "u", "p", use_ssl=False)


# --- imaplib's own exceptions are not OSError -----------------------------
def test_happy_listing_works():
    with FakeImapServer() as srv:
        assert sorted(i.name for i in _session(srv).list_dir("/")) == ["Archive", "INBOX"]


@pytest.mark.parametrize(
    "verb, reply",
    [
        ("EXAMINE", b"* BYE going away\r\n"),  # imaplib raises IMAP4.abort
        ("EXAMINE", None),  # hang-up: IMAP4.abort("socket error: EOF")
        ("FETCH", None),
        ("LIST", lambda tag, arg: f"{tag} BAD nonsense\r\n".encode()),  # IMAP4.error
    ],
    ids=["bye", "eof-select", "eof-fetch", "tagged-bad"],
)
def test_sad_imaplib_errors_reach_callers_as_oserror(verb, reply):
    with FakeImapServer() as srv:
        s = _session(srv)
        srv.replies[verb] = reply
        for op in (
            lambda: s.list_dir("/INBOX"),
            lambda: s.stat("/INBOX/1_x.eml"),
            lambda: s.open_read("/INBOX/1_x.eml"),
            lambda: s.is_dir("/INBOX/1"),
        ):
            try:
                op()
            except OSError:
                pass


# --- mailbox names in broken modified UTF-7 -------------------------------
def test_happy_modified_utf7_decodes():
    assert IC._imap_utf7_decode(b"&ZeVnLIqe-") == "日本語"
    assert IC._imap_utf7_decode(b"Entw&APw-rfe") == "Entwürfe"
    assert IC._imap_utf7_decode(b"a&-b") == "a&b"


@pytest.mark.parametrize(
    "raw",
    [b"&A-", b"&ZZZZ-", b"IN&BO-1X", b"&!!!-", b"&AAAAAA-"],
    ids=["one-b64-char", "odd-utf16", "odd-utf16-mid", "not-base64", "nul-chars-ok"],
)
def test_sad_undecodable_shift_sequence_is_kept_literally(raw):
    """binascii.Error / UnicodeDecodeError used to escape list_dir; a shift
    sequence that does not decode stays as the literal text, like the
    existing "no closing '-'" case."""
    decoded = IC._imap_utf7_decode(raw)
    assert isinstance(decoded, str)
    if raw != b"&AAAAAA-":
        assert raw.decode("ascii") in decoded


def test_edge_hostile_mailbox_name_lists():
    with FakeImapServer(replies={"LIST": b'* LIST () "/" "&A-"\r\n* LIST () "/" "ok"\r\n'}) as srv:
        assert sorted(i.name for i in _session(srv).list_dir("/")) == ["&A-", "ok"]


# --- a Subject in a charset Python does not know --------------------------
def test_happy_encoded_subject_decodes():
    assert IC._decode_header("=?utf-8?B?SGVsbG8=?=") == "Hello"
    assert IC._decode_header("=?iso-8859-1?Q?caf=E9?=") == "café"


@pytest.mark.parametrize("raw", ["=?x-bogus?Q?abc?=", "=?utfm8?B?SGVsbG8=?=", "=?²?Q?a?="])
def test_sad_unknown_charset_falls_back_to_utf8(raw):
    """bytes.decode(<unknown charset>) raised LookupError out of list_dir
    (POP3's twin helper already had this fallback)."""
    assert isinstance(IC._decode_header(raw), str)


@pytest.mark.parametrize("raw", ["=?utf-8?B? GVsbG8=?=", "=?utf-8?B?S?=", "=?utf-8?B?A===?="])
def test_sad_broken_base64_word_is_shown_raw(raw):
    """email.header.decode_header raises HeaderParseError for a B-encoded
    word with bad padding; that escaped list_dir."""
    assert IC._decode_header(raw) == raw


def test_sad_charset_with_nul_falls_back():
    # bytes.decode("\x00tf-8") raises ValueError("embedded null character").
    assert IC._decode_header("=?\x00tf-8?Q?abc?=") == "abc"


def test_edge_listing_with_unknown_charset_subject():
    fetch = b'* 1 FETCH (UID 1 RFC822.SIZE 5 ENVELOPE (NIL "=?x-bogus?Q?abc?=" NIL))\r\n'
    with FakeImapServer(replies={"FETCH": fetch, "SEARCH": b"* SEARCH 1\r\n"}) as srv:
        assert [i.name for i in _session(srv).list_dir("/INBOX")] == ["1_abc.eml"]


# --- SEARCH answers that are not UID lists --------------------------------
def test_happy_search_returns_uids():
    with FakeImapServer(replies={"SEARCH": b"* SEARCH 3 17\r\n"}) as srv:
        assert _session(srv).search("ALL") == [3, 17]


@pytest.mark.parametrize(
    "reply", [b"* SEARCH 1 \xff 2\r\n", b"* SEARCH 1 abc 2\r\n", b"* SEARCH 1 \xc2\xb2 2\r\n"]
)
def test_sad_non_uid_search_tokens_are_skipped(reply):
    """b"\\xff" made list_dir raise UnicodeDecodeError (batch.decode("ascii"))
    and search() UnicodeDecodeError / ValueError (int("abc"))."""
    fetch = b"* 1 FETCH (UID 1 RFC822.SIZE 5)\r\n* 2 FETCH (UID 2 RFC822.SIZE 6)\r\n"
    with FakeImapServer(replies={"SEARCH": reply, "FETCH": fetch}) as srv:
        s = _session(srv)
        assert s.search("ALL") == [1, 2]
        assert [i.size for i in s.list_dir("/INBOX")] == [5, 6]
        assert any("FETCH 1,2 " in c for c in srv.commands)


def test_edge_search_with_only_garbage_is_empty():
    with FakeImapServer(replies={"SEARCH": b"* SEARCH \xff zz\r\n"}) as srv:
        s = _session(srv)
        assert s.search("ALL") == []
        assert s.list_dir("/INBOX") == []


def test_edge_session_recovers_after_an_abort():
    with FakeImapServer() as srv:
        s = _session(srv)
        srv.replies["EXAMINE"] = b"* BYE going away\r\n"
        with pytest.raises(OSError):
            s.list_dir("/INBOX")
        srv.replies["EXAMINE"] = b"* 2 EXISTS\r\n"
        assert [i.name for i in s.list_dir("/INBOX")] == ["1_Hello world.eml"]
