"""File > Restore Last Session: what it asks, what it keeps, what it saves.

Three faults of the session restore, found in one review:

* ``_restore_pane`` decided on its own whether a remote pane needed a
  password - a short list of protocols that need none - instead of
  ``core.profiles.password_needed``, which Quick Connect and the MCP
  server use. TFTP, anonymous S3, rsync over SSH and every SSH key profile
  were asked for a password or passphrase nothing used. Cancel at that
  prompt (or a failed connect) put a *local* pane in the remote one's
  place, listing the local disk.
  Now ``password_needed`` decides, an SSH key is asked for its passphrase
  only when the key turns out to need one, and a cancelled prompt or a
  failed connect leaves a "Not connected" placeholder (with Reconnect)
  that says why.
* Restore tore down every pane and shell of every workspace without a
  question, while a layout switch asks first. It asks the same way now,
  over all workspaces.
* A pane opened without a saved profile (a share Network Search opened)
  was written to the session as ``"local": true`` with its remote path.
  Such panes are left out of the session now.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication, QInputDialog, QMessageBox  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from core.profiles import ConnectionProfile, password_needed  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _settle(seconds: float = 0.1) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.005)


@pytest.fixture
def win(tmp_path, monkeypatch):
    from ui import main_window as MW

    home = tmp_path / "home"
    home.mkdir()
    with mock.patch("pathlib.Path.home", return_value=home):
        window = MW.MainWindow()
    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", home / "session.json")
    # No modal dialog may block a test: every prompt is noted and answered.
    window.test_prompts = []
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(
        lambda parent, title, *a, **k: (window.test_prompts.append(title), ("", False))[1]))
    for name in ("information", "warning", "critical"):
        monkeypatch.setattr(QMessageBox, name, staticmethod(
            lambda *a, _n=name, **k: window.test_prompts.append(_n)))
    monkeypatch.setattr(QMessageBox, "question", staticmethod(
        lambda *a, **k: (window.test_prompts.append("question"),
                         QMessageBox.StandardButton.No)[1]))
    window._quit_with_transfers = True
    window.test_home = home
    yield window
    window._pane_profiles.clear()  # the fakes below hold no real connection
    window.close()
    window.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


class _Connect:
    """Stands in for ui.off_gui.connect_off_gui; notes every call."""

    def __init__(self, events: list, fail_until_passphrase: bool = False,
                 error: Exception | None = None) -> None:
        self.events = events
        self.fail_until_passphrase = fail_until_passphrase
        self.error = error

    def __call__(self, manager, profile, *, password="", key_passphrase="", **_kw):
        self.events.append(f"connect pw={password!r} kp={key_passphrase!r}")
        if self.error is not None:
            raise self.error
        if self.fail_until_passphrase and not key_passphrase:
            import paramiko

            raise paramiko.PasswordRequiredException("private key file is encrypted")
        return LocalFS()


def _asking(events: list, answer: tuple[str, bool]):
    def get_text(parent, title, *a, **k):
        events.append(f"ask {title}")
        return answer
    return staticmethod(get_text)


def _add(win, **fields) -> ConnectionProfile:
    profile = ConnectionProfile(host="127.0.0.1", **fields)
    profile.store_password = False
    win._profile_manager.add(profile)
    return profile


@pytest.mark.parametrize("fields", [
    {"name": "p-tftp", "protocol": "tftp"},
    {"name": "p-s3", "protocol": "s3", "username": ""},
    {"name": "p-rsync", "protocol": "rsync", "rsync_ssh": True},
    {"name": "p-key", "protocol": "sftp", "auth_type": "key", "key_file": "/nonexist"},
])
def test_happy_no_password_prompt_where_nothing_needs_one(win, tmp_path, monkeypatch, fields):
    profile = _add(win, **fields)
    assert password_needed(profile) is False
    events: list[str] = []
    monkeypatch.setattr("ui.off_gui.connect_off_gui", _Connect(events))
    monkeypatch.setattr(QInputDialog, "getText", _asking(events, ("", False)))
    pane = win._restore_pane(win._root_splitter,
                             {"type": "pane", "profile": profile.name, "path": str(tmp_path)})
    assert events == ["connect pw='' kp=''"]
    assert pane is not None and win._pane_profiles.get(pane) is profile


def test_sad_cancel_at_the_password_leaves_a_placeholder_not_a_local_pane(win, monkeypatch):
    profile = _add(win, name="p-ftp", protocol="ftp", username="bob")
    assert password_needed(profile) is True
    events: list[str] = []
    monkeypatch.setattr("ui.off_gui.connect_off_gui", _Connect(events))
    monkeypatch.setattr(QInputDialog, "getText", _asking(events, ("", False)))
    panes = list(win._panes)
    result = win._restore_pane(win._root_splitter,
                               {"type": "pane", "profile": profile.name, "path": "/srv/x"})
    assert result is None
    assert events == ["ask Session Restore – Password Required"]  # no connect after Cancel
    assert win._panes == panes  # no local pane at the remote path
    placeholder = win._pane_placeholders[-1]
    assert placeholder.profile_name == "p-ftp" and placeholder.path == "/srv/x"
    assert "password" in placeholder._note.text()


def test_sad_a_failed_connect_leaves_a_placeholder_with_the_reason(win, monkeypatch):
    profile = _add(win, name="p-down", protocol="tftp")
    events: list[str] = []
    monkeypatch.setattr("ui.off_gui.connect_off_gui",
                        _Connect(events, error=OSError("host is down")))
    panes = list(win._panes)
    assert win._restore_pane(
        win._root_splitter, {"type": "pane", "profile": profile.name, "path": "/"}) is None
    assert win._panes == panes
    assert win.test_prompts == []  # TFTP takes no password
    assert "host is down" in win._pane_placeholders[-1]._note.text()


def test_edge_an_encrypted_key_is_asked_for_after_the_first_try(win, tmp_path, monkeypatch):
    pytest.importorskip("paramiko")
    profile = _add(win, name="p-enc", protocol="sftp", auth_type="key", key_file="/k")
    events: list[str] = []
    monkeypatch.setattr("ui.off_gui.connect_off_gui",
                        _Connect(events, fail_until_passphrase=True))
    monkeypatch.setattr(QInputDialog, "getText", _asking(events, ("secret", True)))
    pane = win._restore_pane(win._root_splitter,
                             {"type": "pane", "profile": profile.name, "path": str(tmp_path)})
    assert events == [
        "connect pw='' kp=''",
        "ask Session Restore – Key Passphrase",
        "connect pw='' kp='secret'",
    ]
    assert pane is not None and win._pane_key_passphrases.get(pane) == "secret"


# -- Restore asks before it closes what runs ----------------------------------------


def test_sad_restore_asks_before_it_closes_a_connection(win, monkeypatch):
    win._save_session()
    pane = win._panes[0]
    # The pane counts as connected through a profile (no real connection).
    win._pane_profiles[pane] = ConnectionProfile(name="remote", protocol="sftp", host="h")
    asked: list[str] = []

    def question(parent, title, text, *a, **k):
        asked.append(f"{title}: {text}")
        return QMessageBox.StandardButton.No

    monkeypatch.setattr(QMessageBox, "question", staticmethod(question))
    win._restore_session()
    assert len(asked) == 1 and "Restore" in asked[0] and "1 connection" in asked[0]
    assert win._panes == [pane]  # No: nothing torn down

    # Nothing running: restored without a question.
    win._pane_profiles.clear()
    win._restore_session()
    _settle()
    assert len(asked) == 1
    assert win._panes and win._panes[0] is not pane


def test_edge_the_question_counts_every_workspace(win, monkeypatch):
    win._save_session()
    first = win._panes[0]
    win.new_workspace()
    _settle()
    second = [p for p in win._panes if p is not first][0]
    profile = ConnectionProfile(name="remote", protocol="sftp", host="h")
    win._pane_profiles[first] = profile
    win._pane_profiles[second] = profile
    asked: list[str] = []
    monkeypatch.setattr(QMessageBox, "question", staticmethod(
        lambda parent, title, text, *a, **k: (asked.append(text),
                                              QMessageBox.StandardButton.No)[1]))
    win._restore_session()
    assert len(asked) == 1 and "2 connections" in asked[0]


# -- a pane without a profile is not saved as a local one ----------------------------


class _RemoteFS:
    """A backend that is no LocalFS (a share Network Search opened)."""

    name = "smb://host/share"


def test_sad_an_unprofiled_remote_pane_is_not_saved_as_local(win, tmp_path):
    pane = win._panes[0]
    real = pane._backend
    pane._backend = _RemoteFS()
    try:
        assert win._serialize_pane(pane) is None
        tree = win._serialize_splitter(win._root_splitter)
    finally:
        pane._backend = real
    assert all(child.get("local") is not True for child in tree["children"])
    # A local pane still is.
    entry = win._serialize_pane(pane)
    assert entry["local"] is True and "profile" not in entry
