"""IMAP with hierarchy separator "/": nested mailboxes are folders.

With "/" (Gmail, Exchange, Dovecot configured so) the root listing
returned the nested mailbox "Work/2025" as ONE entry whose name holds
"/": the listing choke point (drop_unsafe_names) dropped it, list_dir
("/Work") did not show it, and open_write("/Work/2025/note.eml") was
refused - while _parse_path already mapped /Work/2025 to "Work/2025".
Gmail's "[Gmail]/Sent Mail" and the rest under the \\Noselect "[Gmail]"
could not be reached at all.

Now every directory lists only its first-level sub-mailboxes; a parent
that cannot be opened (\\Noselect, or not listed) is shown when it holds
a mailbox that can. Writes resolve their mailbox like every other path.
A separator other than "/" keeps the flat listing (each full name is
one valid path component there).

Driven against the scripted IMAP server on 127.0.0.1.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mail_fuzz_servers import FakeImapServer  # noqa: E402

from core import imap_client as IC  # noqa: E402
from core.path_policy import drop_unsafe_names  # noqa: E402

_MSG = "1_Hello world.eml"


@pytest.fixture(autouse=True)
def _short_timeout(monkeypatch):
    monkeypatch.setattr(IC, "IMAP_TIMEOUT", 2.0)


def _list(*rows: tuple[str, str], sep: str = "/") -> bytes:
    return b"".join(f'* LIST ({flags}) "{sep}" "{name}"\r\n'.encode() for flags, name in rows)


def _session(srv) -> IC.ImapSession:
    return IC.ImapSession(srv.host, srv.port, "u", "p", use_ssl=False)


def _names(s, path: str) -> list[str]:
    return [i.name for i in s.list_dir(path)]


# --- happy ----------------------------------------------------------------


def test_happy_nested_mailboxes_list_stat_and_take_writes_level_by_level():
    lst = _list(("\\HasChildren", "Work"), ("\\HasNoChildren", "Work/2025"), ("", "INBOX"))
    with FakeImapServer(replies={"LIST": lst}) as srv:
        s = _session(srv)
        root = s.list_dir("/")
        assert [i.name for i in root] == ["Work", "INBOX"]
        assert [i.name for i in drop_unsafe_names(root)] == ["Work", "INBOX"]
        assert _names(s, "/Work") == ["2025", _MSG]
        assert _names(s, "/Work/2025") == [_MSG]
        st = s.stat("/Work/2025")
        assert (st.name, st.is_dir) == ("2025", True)
        writer = s.open_write("/Work/2025/note.eml")
        assert (writer._mailbox, writer._filename) == ("Work/2025", "note.eml")
        writer.discard()
        writer = s.open_write("/Work/2025")
        assert (writer._mailbox, writer._filename) == ("Work/2025", None)
        writer.discard()


# --- sad ------------------------------------------------------------------


def test_sad_a_noselect_parent_is_a_folder_that_is_never_selected():
    lst = _list(
        ("\\HasNoChildren", "INBOX"),
        ("\\Noselect \\HasChildren", "[Gmail]"),
        ("\\HasNoChildren", "[Gmail]/Sent Mail"),
        ("\\Noselect", "Gone"),  # cannot be opened and holds nothing: hidden
    )
    with FakeImapServer(replies={"LIST": lst}) as srv:
        s = _session(srv)
        assert _names(s, "/") == ["INBOX", "[Gmail]"]
        assert _names(s, "/[Gmail]") == ["Sent Mail"]
        assert _names(s, "/[Gmail]/Sent Mail") == [_MSG]
        assert not any("[Gmail]" in c and "EXAMINE" in c and "Sent" not in c for c in srv.commands)


def test_sad_a_write_below_a_message_level_is_still_refused():
    lst = _list(("", "Work"), ("", "Work/2025"))
    with FakeImapServer(replies={"LIST": lst}) as srv:
        with pytest.raises(OSError):
            _session(srv).open_write("/Work/2025/1/deeper.eml")


# --- edge -----------------------------------------------------------------


def test_edge_parents_the_server_does_not_list_are_folders_too():
    # "x//y" has an empty component: no normalised path reaches it.
    lst = _list(("", "INBOX"), ("", "A/B/C"), ("", "x//y"))
    with FakeImapServer(replies={"LIST": lst}) as srv:
        s = _session(srv)
        assert _names(s, "/") == ["INBOX", "A"]
        assert _names(s, "/A") == ["B"]
        assert _names(s, "/A/B") == ["C"]
        assert s.stat("/A/B").is_dir and s.is_dir("/A/B")
        assert _names(s, "/A/B/C") == [_MSG]


def test_edge_a_dot_separator_keeps_the_flat_listing():
    lst = _list(("", "INBOX"), ("\\HasChildren", "box"), ("", "box.sub"), sep=".")
    with FakeImapServer(replies={"LIST": lst}) as srv:
        s = _session(srv)
        assert _names(s, "/") == ["INBOX", "box", "box.sub"]
        assert _names(s, "/box") == [_MSG]
        assert s.stat("/box.sub").name == "box.sub"
        writer = s.open_write("/box.sub/note.eml")
        assert writer._mailbox == "box.sub"
        writer.discard()
