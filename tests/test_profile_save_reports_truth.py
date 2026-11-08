"""Saving and importing profiles blames the right thing.

UX review round 3:

* Save Profile with the name ``box:proxy`` said "Keyring Error - Could not
  save credentials": the name was the problem (its keyring entry is
  another profile's proxy password), so the form's check says so now.
* A full disk (ENOSPC) showed the main window's "Not saved" and then the
  dialog's "Saved"; an unreadable profiles.json (it stays untouched, so
  nothing in it is lost) showed only "Saved". ``ProfileManager.save()``
  returned nothing; it returns a ``SaveResult`` now and the dialog reports
  that.
* Import Profiles put "(keyring unavailable?)" over every failure, next to
  Python class names ("ValueError: Profile name ...").
* Test Connection against an SSH host whose key is not in known_hosts
  failed with "Connection Failed"; nothing failed - Connect shows the
  fingerprint to trust - so it says that now.
"""

from __future__ import annotations

import errno
import json
import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QFileDialog, QMessageBox  # noqa: E402

import core.profiles as P  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def boxes():
    shown: list[tuple[str, str, str]] = []

    def record(kind):
        def box(_parent, title, text, *_a, **_k):
            shown.append((kind, str(title), str(text)))
            return QMessageBox.StandardButton.Yes
        return box

    patches = [mock.patch.object(QMessageBox, kind, staticmethod(record(kind)))
               for kind in ("information", "warning", "critical", "question")]
    for p in patches:
        p.start()
    yield shown
    for p in patches:
        p.stop()


@pytest.fixture
def manager(tmp_path, monkeypatch):
    monkeypatch.setattr(P, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(P, "PROFILES_FILE", tmp_path / "profiles.json")
    return P.ProfileManager()


@pytest.fixture
def listener():
    """The save-failure listeners (the main window's "Not saved")."""
    from core import json_store

    told: list[tuple[str, str]] = []
    json_store.on_save_failure(lambda what, err: told.append((what, err)))
    yield told
    json_store._SAVE_FAILURE_LISTENERS.pop()


def _save_in_dialog(manager, name: str):
    from ui.connection_dialog import ConnectionDialog

    dlg = ConnectionDialog(manager)
    try:
        dlg._profile_name.setText(name)
        dlg._host.setText("example.org")
        dlg._username.setText("bob")
        dlg._save_profile()
    finally:
        dlg.close()
        dlg.deleteLater()


def _full_disk(real=os.replace):
    def replace(src, dst):
        if str(dst).endswith("profiles.json"):
            raise OSError(errno.ENOSPC, "No space left on device")
        return real(src, dst)
    return replace


# --- ProfileManager.save() ---------------------------------------------------


def test_happy_save_returns_a_true_result(manager):
    result = manager.add(P.ConnectionProfile(name="ok", protocol="sftp", host="h.example"))
    assert result and result.ok and result.error is None
    assert "ok" in json.loads(P.PROFILES_FILE.read_text())


def test_sad_a_full_disk_is_a_false_result_with_a_reason(manager, listener):
    with mock.patch.object(P.os, "replace", _full_disk()):
        result = manager.add(P.ConnectionProfile(name="box", protocol="sftp", host="h"))
    assert not result
    assert isinstance(result.error, OSError) and result.error.errno == errno.ENOSPC
    assert "space" in result.reason
    assert result.reported and listener  # the window's "Not saved" is told


def test_edge_report_failure_false_leaves_the_listeners_to_the_caller(manager, listener):
    with mock.patch.object(P.os, "replace", _full_disk()):
        result = manager.add(P.ConnectionProfile(name="box", protocol="sftp", host="h"),
                             report_failure=False)
    assert not result and not result.reported
    assert listener == []


def test_sad_an_unreadable_profiles_file_is_a_false_result(manager):
    P.PROFILES_FILE.mkdir()  # profiles.json cannot be read or replaced
    result = manager.add(P.ConnectionProfile(name="box", protocol="sftp", host="h"))
    assert not result and "could not be read" in result.reason


# --- the connection dialog ----------------------------------------------------


def test_sad_a_reserved_name_is_a_name_problem_not_a_keyring_error(manager, boxes):
    _save_in_dialog(manager, "box:proxy")
    assert len(boxes) == 1, boxes
    kind, title, text = boxes[0]
    assert title != "Keyring Error" and "keyring" not in title.lower()
    assert "box:proxy" in text and "Choose another name" in text
    assert manager.peek("box:proxy") is None


def test_sad_a_full_disk_says_not_saved_and_never_saved(manager, boxes, listener):
    with mock.patch.object(P.os, "replace", _full_disk()):
        _save_in_dialog(manager, "box4")
    titles = [title for _kind, title, _text in boxes]
    assert titles == ["Not saved"], boxes
    assert "space" in boxes[0][2]
    assert listener == []  # one "Not saved", not two
    boxes.clear()
    _save_in_dialog(manager, "box4")  # with space again (it asks to replace the kept one)
    assert [(kind, title) for kind, title, _t in boxes if kind != "question"] == [
        ("information", "Saved")]


def test_sad_an_unreadable_profiles_file_is_not_reported_as_saved(manager, boxes):
    P.PROFILES_FILE.mkdir()
    _save_in_dialog(manager, "box3")
    titles = [title for _kind, title, _text in boxes]
    assert "Saved" not in titles and titles == ["Not saved"], boxes
    assert "could not be read" in boxes[0][2]


def test_edge_test_connection_on_a_new_host_key_points_to_connect(manager, boxes):
    """No "Connection Failed" for a key that only needs a look."""
    import core.connection_manager as CM
    from core.ssh_client import UnknownHostKeyError
    from ui.connection_dialog import ConnectionDialog

    def connect(self, profile, **_kwargs):
        raise UnknownHostKeyError("h.example", "ssh-ed25519", "abc")

    dlg = ConnectionDialog(manager)
    try:
        dlg._host.setText("h.example")
        dlg._username.setText("bob")
        with mock.patch.object(CM.ConnectionManager, "connect", connect):
            dlg._test_connection()
            assert dlg._connect_thread.wait(5000)
            for _ in range(20):
                APP.processEvents()
        assert [kind for kind, _t, _x in boxes] == ["information"], boxes
        assert "new host key" in boxes[0][2] and "Connect" in boxes[0][2]
    finally:
        dlg.close()
        dlg.deleteLater()


# --- Import Profiles -----------------------------------------------------------


def test_sad_the_import_names_each_cause_and_no_class_names(manager, boxes, tmp_path):
    import ui.main_window as MW
    from PyQt6.QtWidgets import QWidget

    source = tmp_path / "import.json"
    source.write_text(json.dumps({
        "good": {"name": "good", "protocol": "sftp", "host": "a.example", "username": "u"},
        "work:proxy": {"name": "work:proxy", "protocol": "sftp", "host": "b.example"},
    }))

    class Window(QWidget):
        _profile_manager = manager

    window = Window()
    with mock.patch.object(QFileDialog, "getOpenFileName",
                           staticmethod(lambda *a, **k: (str(source), ""))):
        MW.MainWindow._import_profiles_json(window)
    report = boxes[-1][2]
    assert "keyring unavailable" not in report
    assert "ValueError" not in report
    assert "work:proxy" in report and "Choose another name" in report
    assert manager.peek("good") is not None
