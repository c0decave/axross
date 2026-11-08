"""Exchange: deleting a message moves it to Deleted Items, never hard-deletes.

remove() called exchangelib's ``Item.delete()`` - EWS HardDelete: the
message skipped Deleted Items and "Recover deleted items", while the same
Delete in Outlook or OWA only moves it. It now calls ``move_to_trash()``,
and ``soft_delete()`` for a message already in Deleted Items.

exchangelib is not needed: the folder tree is a stand-in with exchangelib's
calls.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import exchange_client as EC  # noqa: E402


class _Msg:
    def __init__(self, mid):
        self.id = mid
        self.calls: list[str] = []

    def delete(self):
        self.calls.append("delete")

    def move_to_trash(self):
        self.calls.append("move_to_trash")

    def soft_delete(self):
        self.calls.append("soft_delete")


class _Folder:
    def __init__(self, name, fid, children=(), messages=()):
        self.name, self.id = name, fid
        self.children = list(children)
        self.messages = list(messages)

    def __truediv__(self, other):
        for c in self.children:
            if c.name.lower() == other.lower():
                return c
        raise LookupError(f"No subfolder with name {other!r}")

    def filter(self, id):  # noqa: A002 - exchangelib's keyword
        found = [m for m in self.messages if m.id == id]

        class _Query:
            def only(self, *fields):
                return self

            def __iter__(self):
                return iter(found)

        return _Query()


def _session(trash_lookup_fails=False):
    inbox = _Folder("Inbox", "F-INBOX", messages=[_Msg("M1")])
    trash = _Folder("Gelöschte Elemente", "F-TRASH", messages=[_Msg("M2")])
    root = _Folder("root", "F-ROOT", [inbox, trash])
    if trash_lookup_fails:
        account = _FailingTrash(root)
    else:
        # Another object for the same folder, as exchangelib hands out.
        account = SimpleNamespace(root=root, trash=_Folder(trash.name, "F-TRASH"))
    s = object.__new__(EC.ExchangeSession)
    s._account = account
    return s, inbox, trash


class _FailingTrash:
    def __init__(self, root):
        self.root = root

    @property
    def trash(self):
        raise OSError("ErrorAccessDenied")


def test_sad_delete_moves_the_message_to_deleted_items_instead_of_hard_deleting():
    s, inbox, _ = _session()
    s.remove("/Inbox/M1_hi.eml")
    assert inbox.messages[0].calls == ["move_to_trash"]


def test_edge_delete_in_deleted_items_is_a_soft_delete():
    s, _, trash = _session()
    s.remove("/Gelöschte Elemente/M2_old.eml")
    assert trash.messages[0].calls == ["soft_delete"]


def test_edge_a_failed_deleted_items_lookup_still_never_hard_deletes():
    s, inbox, _ = _session(trash_lookup_fails=True)
    s.remove("/Inbox/M1_hi.eml")
    assert inbox.messages[0].calls == ["move_to_trash"]


def test_sad_a_refused_move_is_an_oserror():
    s, inbox, _ = _session()

    def refuse():
        raise RuntimeError("ErrorQuotaExceeded")

    inbox.messages[0].move_to_trash = refuse
    with pytest.raises(OSError, match="ErrorQuotaExceeded"):
        s.remove("/Inbox/M1_hi.eml")
