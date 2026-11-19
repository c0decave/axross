"""A profile rename: a damaged Smart Folder stops nothing, the local shell
is never taken for a profile, and a terminal bookmark follows whole.

Review 2026-11-20 (profile references round 2), each reproduced before:

* A Smart Folder whose ``scopes`` is not a list (a hand edit, a damaged
  file: the bookmark itself loads) raised TypeError out of
  rename_profile_references - past its "each store on its own" catch and
  out of the Connection dialog's Save, after the old profile was gone:
  no bookmark and no saved pane followed the new name.
* "local" names the local shell in terminal bookmarks and saved layouts.
  Renaming a profile called "local" made every local-shell terminal
  bookmark a shell on the renamed host; renaming "nas" to "local" made
  the nas terminals local shells. A new profile may not be named
  "local" any more, and a rename of an older one leaves the local
  shells alone.
* A terminal bookmark's backend name (its profile's name) stayed on the
  old name, so bookmarking the renamed profile's terminal again made a
  duplicate.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import bookmarks as BM  # noqa: E402
from core.profile_references import rename_profile_references  # noqa: E402


@pytest.fixture
def stores(tmp_path, monkeypatch):
    monkeypatch.setattr(BM, "BOOKMARKS_FILE", tmp_path / "bookmarks.json")
    session = tmp_path / "session.json"
    session.write_text(json.dumps({"splitter": {"children": [
        {"type": "terminal", "local": True},
        {"type": "terminal", "profile": "nas"},
        {"type": "pane", "profile": "nas", "path": "/srv"},
    ]}}), encoding="utf-8")
    return BM.BookmarkManager(), session


def _terminal(name, profile, backend):
    return BM.Bookmark(name=name, path="/srv", backend_name=backend, profile_name=profile,
                       kind=BM.KIND_TERMINAL)


def test_sad_a_smart_folder_with_bad_scopes_does_not_stop_the_rename(stores):
    manager, session = stores
    manager.add(BM.Bookmark(name="sf", path="search:1", backend_name="Smart Folder",
                            search={"scopes": 5}))
    manager.add(BM.Bookmark(name="n", path="/srv", backend_name="nas", profile_name="nas"))
    counts = rename_profile_references("nas", "nas2", bookmarks=manager, session_file=session)
    assert counts == {"bookmarks": 1, "session": 2}
    assert [b.profile_name for b in BM.BookmarkManager().all() if b.name == "n"] == ["nas2"]


def test_sad_renaming_a_profile_called_local_leaves_the_local_shells(stores):
    manager, session = stores
    manager.add(_terminal("my shell", BM.LOCAL_SHELL, "Local"))
    rename_profile_references("local", "prod", bookmarks=manager, session_file=session)
    [shell] = [b for b in BM.BookmarkManager().all() if b.name == "my shell"]
    assert shell.profile_name == BM.LOCAL_SHELL
    tree = json.loads(session.read_text(encoding="utf-8"))["splitter"]["children"]
    assert tree[0] == {"type": "terminal", "local": True}


def test_sad_a_new_profile_may_not_be_called_local(tmp_path, monkeypatch):
    from core import profiles as P

    monkeypatch.setattr(P, "PROFILES_FILE", tmp_path / "profiles.json", raising=False)
    manager = P.ProfileManager.__new__(P.ProfileManager)
    manager._profiles = {}
    with pytest.raises(ValueError, match="local shell"):
        manager.add(P.ConnectionProfile(name=BM.LOCAL_SHELL, protocol="sftp", host="h"))


def test_happy_a_terminal_bookmark_follows_with_its_backend_name(stores):
    manager, session = stores
    manager.add(_terminal("nas: /srv", "nas", "nas"))
    rename_profile_references("nas", "nas2", bookmarks=manager, session_file=session)
    [mark] = BM.BookmarkManager().all()
    assert (mark.profile_name, mark.backend_name) == ("nas2", "nas2")
