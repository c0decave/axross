"""Renaming a connection profile takes its bookmarks, terminal bookmarks,
Smart Folders and saved session panes along.

Reproduced 2026-11-19 (independent review): Save with a new name in the
Connection dialog replaced profile "nas" by "home-nas", and every bookmark
(folder or terminal), every Smart Folder scope and every saved pane of
session.json kept naming "nas" - a profile that no longer existed ("The
profile 'nas' no longer exists"). Now the rename rewrites those
references, on disk and in the running window.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def home(tmp_path, monkeypatch):
    import core.bookmarks as B
    import core.i18n as I
    import core.profiles as P

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(P, "PROFILES_FILE", tmp_path / ".config/axross/profiles.json")
    monkeypatch.setattr(B, "_bookmarks_file", lambda: tmp_path / ".config/axross/bookmarks.json")
    monkeypatch.setattr(I, "SETTINGS_FILE", tmp_path / ".config/axross/session.json")
    return tmp_path


def _bookmarks():
    from core.bookmarks import Bookmark, BookmarkManager, new_smart_folder

    bm = BookmarkManager()
    bm.add(Bookmark(name="photos", path="/photos", backend_name="me@nas.lan", profile_name="nas"))
    bm.add(Bookmark(name="nas shell", path="/home/me", backend_name="nas",
                    profile_name="nas", kind="terminal"))
    bm.add(Bookmark(name="other", path="/x", backend_name="o", profile_name="nas2"))
    bm.add(new_smart_folder("big files", {
        "version": 1, "scopes": [
            {"backend_name": "me@nas.lan", "profile_name": "nas", "path": "/"},
            {"backend_name": "Local", "profile_name": "", "path": "/home"},
        ]}))
    return bm


def _session(home: Path) -> Path:
    path = home / ".config/axross/session.json"
    tree = {"type": "splitter", "children": [
        {"type": "pane", "profile": "nas", "path": "/photos"},
        {"type": "terminal", "profile": "nas"},
        {"type": "pane", "local": True, "path": "/tmp"},
        {"type": "pane", "profile": "nas2", "path": "/"},
    ]}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "language": "de",
        "splitter": tree,
        "workspaces": [{"name": "W1", "splitter": tree, "current": True},
                       {"name": "W2", "splitter": {"type": "splitter", "children": [
                           {"type": "pane", "profile": "nas", "path": "/b"}]}}],
    }))
    return path


def _profiles_in(tree: dict) -> list:
    out = []
    stack = [tree]
    while stack:
        node = stack.pop()
        if node.get("type") in ("pane", "terminal") and "profile" in node:
            out.append(node["profile"])
        stack.extend(node.get("children", []))
    return sorted(out)


def test_happy_the_references_on_disk_follow_the_rename(home):
    from core.bookmarks import BookmarkManager
    from core.profile_references import rename_profile_references

    _bookmarks()
    session = _session(home)
    rename_profile_references("nas", "home-nas")

    marks = {b.name: b for b in BookmarkManager().all()}
    assert marks["photos"].profile_name == "home-nas"
    assert marks["nas shell"].profile_name == "home-nas"
    assert marks["other"].profile_name == "nas2"  # another profile: untouched
    scopes = marks["big files"].search["scopes"]
    assert [s["profile_name"] for s in scopes] == ["home-nas", ""]
    data = json.loads(session.read_text())
    assert data["language"] == "de"  # the rest of the file is kept
    assert _profiles_in(data["splitter"]) == ["home-nas", "home-nas", "nas2"]
    assert _profiles_in(data["workspaces"][0]["splitter"]) == ["home-nas", "home-nas", "nas2"]
    assert _profiles_in(data["workspaces"][1]["splitter"]) == ["home-nas"]


def test_sad_a_host_terminal_bookmark_is_not_a_profile_reference(home):
    """A terminal bookmark on a bare host keeps its address as its
    profile_name; a profile named like that address is another thing."""
    from core.bookmarks import Bookmark, BookmarkManager
    from core.profile_references import rename_profile_references

    bm = BookmarkManager()
    bm.add(Bookmark(name="h", path="/", kind="terminal", host="nas.lan", username="me"))
    before = BookmarkManager().all()[0].profile_name
    rename_profile_references(before, "renamed")
    assert BookmarkManager().all()[0].profile_name == before


def test_edge_no_session_file_and_nothing_to_rename_is_fine(home):
    from core.profile_references import rename_profile_references

    rename_profile_references("nas", "home-nas")
    assert not (home / ".config/axross/session.json").exists()


def test_happy_the_connection_dialog_rename_keeps_bookmarks_working(home):
    """The review's repro: rename in the dialog, the bookmark still works."""
    from core.backend_registry import init_registry
    from core.bookmarks import BookmarkManager
    from core.profiles import ConnectionProfile, ProfileManager
    from ui.connection_dialog import ConnectionDialog

    init_registry()
    pm = ProfileManager()
    pm.add(ConnectionProfile(name="nas", protocol="sftp", host="nas.lan", username="me",
                             store_password=False))
    _bookmarks()
    renamed = []
    with mock.patch.object(QMessageBox, "information"), \
         mock.patch.object(QMessageBox, "warning"), \
         mock.patch.object(ConnectionDialog, "_validate_backend_available", return_value=True):
        dlg = ConnectionDialog(pm)
        dlg.profile_renamed.connect(lambda old, new: renamed.append((old, new)))
        dlg._on_profile_selected("nas")
        dlg._profile_name.setText("home-nas")
        dlg._save_profile()
        dlg.deleteLater()
    assert pm.list_names() == ["home-nas"]
    assert renamed == [("nas", "home-nas")]
    names = {b.profile_name for b in BookmarkManager().all() if b.name in ("photos", "nas shell")}
    assert names == {"home-nas"}


def test_happy_the_running_window_follows_the_rename(home, monkeypatch):
    """The open window's panes, placeholders, recent list and bookmarks
    take the new name: its session save at exit must not write the old
    name back."""
    from core.profiles import ConnectionProfile
    from ui import main_window as MW
    from ui.disconnected_pane import KIND_PANE

    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", home / ".config/axross/session.json")
    monkeypatch.setattr(MW.MainWindow, "_RECENTS_FILE", home / ".config/axross/recents.json")
    window = MW.MainWindow()
    try:
        profile = ConnectionProfile(name="nas", protocol="sftp", host="nas.lan", username="me",
                                    store_password=False)
        window._profile_manager.add(profile)
        pane = window._panes[0]
        window._pane_profiles[pane] = profile
        pane.profile_name = "nas"
        window._make_placeholder(window._current_ws.root, KIND_PANE, "nas", "/data")
        window._recent_profiles = ["nas", "nas2"]
        _bookmarks()
        window._bookmark_manager.load()

        renamed = ConnectionProfile(name="home-nas", protocol="sftp", host="nas.lan",
                                    username="me", store_password=False)
        window._profile_manager.add(renamed)
        window._profile_manager.remove("nas")
        from core.profile_references import rename_profile_references

        rename_profile_references("nas", "home-nas")
        window._on_profile_renamed("nas", "home-nas")

        tree = window._serialize_workspaces()[0]["splitter"]
        assert "nas" not in _profiles_in(tree)
        assert _profiles_in(tree).count("home-nas") == 2
        assert window._pane_profiles[pane].name == "home-nas"
        assert pane.profile_name == "home-nas"
        assert window._recent_profiles == ["home-nas", "nas2"]
        live = {b.name: b.profile_name for b in window._bookmark_manager.all()}
        assert live["photos"] == "home-nas"
    finally:
        window._pane_profiles.clear()
        window.close()
        window.deleteLater()
        APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        time.sleep(0.01)
