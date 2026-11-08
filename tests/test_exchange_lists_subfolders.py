"""Exchange: list_dir() of a folder below the root lists its subfolders.

Only the root listing had folder items; ``list_dir("/Inbox")`` showed the
messages and attachment folders but not ``/Inbox/Projects``, although
exists() and list_dir() of that path worked. A recursive copy, move or
delete of Inbox never saw the subfolder.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import exchange_client as EC  # noqa: E402


class _NotFound(Exception):
    pass


class _Q(list):
    def only(self, *fields):
        return self


class _Folder:
    def __init__(self, name, children=(), messages=()):
        self.name, self.children, self.messages = name, list(children), list(messages)

    def __truediv__(self, other):
        for child in self.children:
            if child.name.lower() == other.lower():
                return child
        raise _NotFound(f"No subfolder with name {other!r}")

    def all(self):
        return _Q(self.messages)

    def filter(self, id):  # noqa: A002 - exchangelib's keyword
        return _Q([m for m in self.messages if m.id == id])


def _msg(mid, subject):
    return SimpleNamespace(
        id=mid, subject=subject, size=10, datetime_received=None,
        has_attachments=False, attachments=[],
    )


@pytest.fixture
def session():
    projects = _Folder("Projects", messages=[_msg("P1", "plan")])
    archive = _Folder("Archive")
    inbox = _Folder("Inbox", children=[projects, archive], messages=[_msg("M1", "hi")])
    s = object.__new__(EC.ExchangeSession)
    s._account = SimpleNamespace(root=_Folder("root", [inbox]))
    return s


def test_sad_list_dir_of_a_subfolder_lists_its_child_folders(session) -> None:
    items = {i.name: i.is_dir for i in session.list_dir("/Inbox")}
    assert items == {"Projects": True, "Archive": True, "M1_hi.eml": False}


def test_edge_a_leaf_folder_lists_only_its_messages(session) -> None:
    """A folder without children (and the root) list as before."""
    assert [(i.name, i.is_dir) for i in session.list_dir("/Inbox/Projects")] == [
        ("P1_plan.eml", False)
    ]
    assert [i.name for i in session.list_dir("/")] == ["Inbox"]
    assert session.list_dir("/Inbox/Archive") == []
    names = [i.name for i in session.list_dir("/Inbox")]
    assert "Archive" in names
