"""Removing an IMAP mailbox removes its tree - and only when asked to.

GUI end-to-end run against the lab Dovecot: the root listed a mailbox
"axross-e2e-1de38b4c" that could not be opened ("Mailbox doesn't
exist"), next to "axross-e2e-1de38b4c.sub2" and "...sub2.deeper". An
earlier write matrix had created /box/sub2/deeper and removed /box with
recursive=True:

* remove() sent one DELETE for the mailbox itself. Its sub-mailboxes
  stayed, and the lab Dovecot keeps listing the deleted parent of living
  children as plain ``(\\HasChildren)`` while SELECT answers "Mailbox
  doesn't exist" (raw LIST, measured). Now the sub-mailboxes go first,
  deepest first.
* Such a parent left behind by another client opens as an empty folder
  instead of an error. A server that flags it (RFC 5258
  ``\\NonExistent``, which implies \\Noselect) has it left out of the
  listing, like ``\\Noselect``.
* remove() ignored ``recursive`` for mailboxes: without it, a mailbox
  full of mail was deleted all the same. Now a mailbox with messages or
  sub-mailboxes is refused without recursive=True, like any folder.
"""

from __future__ import annotations

import errno
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.imap_client import ImapSession  # noqa: E402


class _Dovecot:
    """Mailboxes with a message count; deletes like the lab Dovecot.

    ``dead_flags`` is how LIST shows a deleted parent of living children:
    plain ``\\HasChildren`` as measured on the lab, ``\\NonExistent`` on an
    RFC 5258 server.
    """

    def __init__(self, boxes: dict[str, int], sep: str = ".", dead_flags: str = "\\NonExistent \\HasChildren"):
        self.boxes = dict(boxes)
        self.dead: set[str] = set()  # deleted parents of living children
        self.sep = sep
        self.dead_flags = dead_flags
        self.deleted: list[str] = []

    def _children(self, name):
        return [b for b in self.boxes if b.startswith(name + self.sep)]

    def list(self, *a, **k):
        rows = []
        for name in sorted(self.boxes):
            rows.append(f'(\\HasNoChildren) "{self.sep}" "{name}"'.encode())
        for name in sorted(self.dead):
            if self._children(name):
                rows.append(f'({self.dead_flags}) "{self.sep}" "{name}"'.encode())
        return "OK", rows

    def status(self, name, what):
        if name not in self.boxes:
            return "NO", [b"Mailbox doesn't exist"]
        return "OK", [f'"{name}" (MESSAGES {self.boxes[name]})'.encode()]

    def delete(self, name):
        if name not in self.boxes:
            return "NO", [f"Mailbox doesn't exist: {name}".encode()]
        del self.boxes[name]
        self.deleted.append(name)
        if self._children(name):
            self.dead.add(name)
        return "OK", [b"Delete completed."]

    def select(self, name, readonly=True):
        if name not in self.boxes:
            return "NO", [f"Mailbox doesn't exist: {name}".encode()]
        return "OK", [str(self.boxes[name]).encode()]

    def close(self):
        return "OK", [b""]


def _session(server: _Dovecot) -> ImapSession:
    s = object.__new__(ImapSession)
    s._host, s._port, s._username = "lab", 143, "u"
    s._use_ssl = False
    s._imap = server
    s._ensure_connected = lambda: server
    s._hierarchy_sep = server.sep
    s._selected_mailbox = None
    s._mailbox_cache = None
    return s


# --- happy ----------------------------------------------------------------


def test_happy_recursive_remove_takes_the_sub_mailboxes_deepest_first():
    srv = _Dovecot({"INBOX": 1, "box": 2, "box.sub2": 1, "box.sub2.deeper": 0, "boxer": 1})
    _session(srv).remove("/box", recursive=True)
    assert srv.deleted == ["box.sub2.deeper", "box.sub2", "box"]
    assert set(srv.boxes) == {"INBOX", "boxer"}  # a name that only starts alike stays
    assert not srv.dead


def test_happy_an_empty_mailbox_goes_without_recursive():
    srv = _Dovecot({"INBOX": 1, "empty": 0})
    _session(srv).remove("/empty")
    assert srv.deleted == ["empty"]


# --- sad ------------------------------------------------------------------


def test_sad_a_mailbox_with_mail_is_kept_without_recursive():
    srv = _Dovecot({"INBOX": 1, "full": 3})
    with pytest.raises(OSError) as info:
        _session(srv).remove("/full")
    assert info.value.errno == errno.ENOTEMPTY
    assert srv.boxes["full"] == 3 and srv.deleted == []


def test_sad_a_mailbox_with_sub_mailboxes_is_kept_without_recursive():
    srv = _Dovecot({"box": 0, "box.sub": 0})
    with pytest.raises(OSError) as info:
        _session(srv).remove("/box")
    assert info.value.errno == errno.ENOTEMPTY
    assert srv.deleted == []


def test_sad_a_dead_parent_is_not_listed():
    srv = _Dovecot({"INBOX": 0, "box.sub2": 0})
    srv.dead.add("box")
    names = [i.name for i in _session(srv).list_dir("/")]
    assert names == ["INBOX", "box.sub2"]


# --- edge -----------------------------------------------------------------


def test_edge_removing_a_living_child_tree_lets_its_dead_parent_vanish():
    srv = _Dovecot({"box.sub2": 0, "box.sub2.deeper": 0})
    srv.dead.add("box")
    s = _session(srv)
    s.remove("/box.sub2", recursive=True)
    assert srv.boxes == {}
    assert [i.name for i in s.list_dir("/")] == []


def test_edge_a_dead_parent_removed_recursively_takes_its_children():
    srv = _Dovecot({"box.sub2": 1})
    srv.dead.add("box")
    _session(srv).remove("/box", recursive=True)
    assert srv.boxes == {} and srv.deleted == ["box.sub2"]


def test_edge_slash_separator_trees_work_the_same():
    srv = _Dovecot({"Projects": 0, "Projects/2025": 4}, sep="/")
    _session(srv).remove("/Projects", recursive=True)
    assert srv.deleted == ["Projects/2025", "Projects"]


def test_edge_the_flag_check_ignores_case():
    srv = _Dovecot({"INBOX": 0})
    srv.list = lambda *a, **k: ("OK", [b'(\\HasNoChildren) "." "INBOX"', b'(\\nonexistent) "." "gone"'])
    assert [i.name for i in _session(srv).list_dir("/")] == ["INBOX"]


def test_edge_a_dead_parent_listed_as_plain_has_children_opens_empty():
    srv = _Dovecot({"INBOX": 0, "box.sub2": 1}, dead_flags="\\HasChildren")
    srv.dead.add("box")
    s = _session(srv)
    assert "box" in [i.name for i in s.list_dir("/")]  # the server lists it
    assert s.list_dir("/box") == []


def test_sad_a_missing_mailbox_without_children_is_still_an_error():
    srv = _Dovecot({"INBOX": 0})
    srv.list = lambda *a, **k: ("OK", [b'(\\HasNoChildren) "." "INBOX"', b'(\\HasNoChildren) "." "ghost"'])
    with pytest.raises(OSError):
        _session(srv).list_dir("/ghost")
