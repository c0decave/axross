"""IMAP: removing INBOX or the personal namespace root asks first.

Review round 9: on Courier, Cyrus and Dovecot with ``prefix = INBOX.``
every folder is a child of INBOX, and DELETE INBOX is always an error
(RFC 3501 6.3.4). ``remove("/INBOX", recursive=True)`` deleted every
sub-mailbox first - Sent, Archive, Drafts - and then the server refused
INBOX itself: the operation could never succeed, but all folders were
gone.

Now such a remove raises ConfirmationRequired before a single DELETE (the
file pane asks; the maintainer: a person may want it, but nothing goes
unasked). With ``keep_namespace_root=True`` the folders below go, deepest
first; INBOX and its messages stay and no error follows. Another
namespace root (NAMESPACE, RFC 2342) goes last when the server lets it.

RENAME INBOX stays allowed: RFC 3501 6.3.5 has it move INBOX's messages
to the new mailbox and leave INBOX (and its sub-mailboxes) in place.
"""

from __future__ import annotations

import errno
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_imap_mailbox_tree_remove import _Dovecot, _session  # noqa: E402

from core.backend import ConfirmationRequired  # noqa: E402
from core.imap_client import _personal_namespace_roots  # noqa: E402


class _Courier(_Dovecot):
    """Every folder below INBOX; DELETE INBOX refused, as RFC 3501 says."""

    capabilities = ("IMAP4REV1",)

    def __init__(self, boxes, namespace=None, **kw):
        super().__init__(boxes, **kw)
        self.namespace_answer = namespace
        self.namespace_calls = 0
        self.renamed: list[tuple[str, str]] = []
        self.refuse: set[str] = set()
        if namespace is not None:
            self.capabilities = ("IMAP4REV1", "NAMESPACE")

    def namespace(self):
        self.namespace_calls += 1
        return "OK", [self.namespace_answer]

    def delete(self, name):
        if self._name(name).upper() == "INBOX":
            return "NO", [b"Cannot delete INBOX."]
        if self._name(name) in self.refuse:
            return "NO", [b"Permission denied."]
        return super().delete(name)

    def rename(self, old, new):
        old, new = self._name(old), self._name(new)
        self.renamed.append((old, new))
        # RFC 3501 6.3.5: the messages move, INBOX and its children stay.
        self.boxes[new] = self.boxes[old]
        if old.upper() == "INBOX":
            self.boxes[old] = 0
        else:
            del self.boxes[old]
        return "OK", [b"Rename completed."]


def _cpanel(**kw):
    return _Courier({"INBOX": 5, "INBOX.Sent": 1200, "INBOX.Archive": 30000,
                     "INBOX.Archive.2024": 9000, "INBOX.Drafts": 2}, **kw)


# --- happy ----------------------------------------------------------------


def test_happy_a_folder_below_inbox_still_goes():
    srv = _cpanel()
    _session(srv).remove("/INBOX.Archive", recursive=True)
    assert srv.deleted == ["INBOX.Archive.2024", "INBOX.Archive"]
    assert set(srv.boxes) == {"INBOX", "INBOX.Sent", "INBOX.Drafts"}


def test_happy_renaming_inbox_moves_its_messages_as_rfc_3501_says():
    srv = _cpanel()
    _session(srv).rename("/INBOX", "/INBOX.Old")
    assert srv.renamed == [("INBOX", "INBOX.Old")]
    assert srv.boxes["INBOX.Old"] == 5
    assert srv.boxes["INBOX"] == 0 and srv.boxes["INBOX.Sent"] == 1200


def test_happy_the_namespace_prefix_is_read_from_the_answer():
    assert _personal_namespace_roots([b'(("INBOX." ".")) NIL NIL']) == {"INBOX"}
    assert _personal_namespace_roots([b'(("" "/")) NIL (("#shared/" "/"))']) == set()
    assert _personal_namespace_roots([b'(("Mail/" "/")("#mh/" "/")) NIL NIL']) == {"Mail", "#mh"}
    assert _personal_namespace_roots([b"NIL NIL NIL"]) == set()


def test_happy_confirmed_inbox_deletes_the_folders_below_and_keeps_inbox():
    srv = _cpanel()
    _session(srv).remove("/INBOX", recursive=True, keep_namespace_root=True)  # no error
    assert srv.deleted[0] == "INBOX.Archive.2024"  # deepest first
    assert set(srv.deleted[1:]) == {"INBOX.Sent", "INBOX.Drafts", "INBOX.Archive"}
    assert srv.boxes == {"INBOX": 5}  # INBOX and its 5 messages stay


def test_happy_a_confirmed_namespace_root_goes_after_its_folders():
    srv = _Courier({"Mail": 0, "Mail/Sent": 3, "Mail/Archive": 7, "Other": 1}, sep="/",
                   namespace=b'(("Mail/" "/")) NIL NIL')
    _session(srv).remove("/Mail", recursive=True, keep_namespace_root=True)
    assert set(srv.deleted) == {"Mail/Sent", "Mail/Archive", "Mail"}
    assert srv.deleted[-1] == "Mail"
    assert srv.boxes == {"Other": 1}


# --- sad ------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/INBOX", "/inbox", "/Inbox", "/INBOX.", "INBOX"])
def test_sad_unconfirmed_inbox_asks_before_any_delete(path):
    srv = _cpanel()
    with pytest.raises(ConfirmationRequired) as info:
        _session(srv).remove(path, recursive=True)
    exc = info.value
    assert exc.errno == errno.EPERM and isinstance(exc, PermissionError)
    assert exc.kind == "imap_namespace_root" and exc.option == "keep_namespace_root"
    assert exc.details["subfolders"] == 4 and exc.details["inbox"] is True
    assert "4 other folders" in exc.explanation and "stay" in exc.explanation
    assert "keep_namespace_root=True" in str(exc)
    assert srv.deleted == []
    assert len(srv.boxes) == 5


def test_sad_declined_means_nothing_is_deleted():
    """The pane's No: remove() is simply not called again."""
    srv = _cpanel()
    s = _session(srv)
    with pytest.raises(ConfirmationRequired):
        s.remove("/INBOX", recursive=True)
    assert srv.deleted == [] and len(srv.boxes) == 5


@pytest.mark.parametrize("recursive", [True, False])
def test_sad_inbox_alone_can_never_be_deleted(recursive):
    srv = _Courier({"INBOX": 3, "Sent": 1}, sep="/")
    with pytest.raises(PermissionError) as info:
        _session(srv).remove("/INBOX", recursive=recursive, keep_namespace_root=True)
    assert not isinstance(info.value, ConfirmationRequired)  # Yes would do nothing
    assert srv.deleted == []


def test_sad_inbox_with_a_slash_separator_asks_too():
    srv = _Courier({"INBOX": 1, "INBOX/Sent": 3}, sep="/")
    with pytest.raises(ConfirmationRequired):
        _session(srv).remove("/INBOX/", recursive=True)
    assert srv.deleted == []


def test_sad_the_personal_namespace_root_asks():
    srv = _Courier({"Mail/Sent": 3, "Mail/Archive": 7, "Other": 1}, sep="/",
                   namespace=b'(("Mail/" "/")) NIL NIL')
    s = _session(srv)
    with pytest.raises(ConfirmationRequired) as info:
        s.remove("/Mail", recursive=True)
    details = info.value.details
    assert details["inbox"] is False and details["subfolders"] == 2
    assert set(details["names"]) == {"Mail/Archive", "Mail/Sent"}
    assert srv.deleted == []
    s.remove("/Mail/Sent", recursive=True)  # a folder in it needs no question
    assert srv.deleted == ["Mail/Sent"]
    assert srv.namespace_calls == 1  # asked once a connection


# --- edge -----------------------------------------------------------------


def test_edge_a_namespace_root_the_server_keeps_is_no_error():
    srv = _Courier({"Mail": 0, "Mail/Sent": 3}, sep="/", namespace=b'(("Mail/" "/")) NIL NIL')
    srv.refuse.add("Mail")
    _session(srv).remove("/Mail", recursive=True, keep_namespace_root=True)
    assert srv.deleted == ["Mail/Sent"]
    assert "Mail" in srv.boxes


def test_edge_a_name_that_only_starts_with_inbox_is_an_ordinary_mailbox():
    srv = _Courier({"INBOX": 1, "INBOXES": 2, "INBOXES.a": 1})
    _session(srv).remove("/INBOXES", recursive=True)
    assert srv.deleted == ["INBOXES.a", "INBOXES"]


def test_edge_an_empty_prefix_protects_nothing_more():
    srv = _Courier({"INBOX": 1, "box": 2}, sep="/", namespace=b'(("" "/")) NIL NIL')
    _session(srv).remove("/box", recursive=True)
    assert srv.deleted == ["box"]


def test_edge_a_failed_namespace_answer_is_asked_again():
    srv = _Courier({"INBOX": 1, "box": 2}, sep="/", namespace=b'(("Mail/" "/")) NIL NIL')
    srv.namespace = lambda: ("NO", [b"busy"])
    s = _session(srv)
    s.remove("/box", recursive=True)
    assert getattr(s, "_namespace_roots", None) is None
