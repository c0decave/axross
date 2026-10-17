"""Saving a profile under the name of another profile asks first.

Before: the connection dialog's Save called ``ProfileManager.add`` with
whatever name the form held. Renaming "prod" to "staging", or saving a
new connection whose automatic name (user@host) already existed,
replaced the other profile without a word - its host, user, key file and
auth type were gone.

Now Save asks before it replaces a profile other than the one loaded into
the form; No leaves both profiles as they were.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core.profiles import ConnectionProfile, ProfileManager  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture()
def manager():
    with tempfile.TemporaryDirectory() as tmp:
        with mock.patch("core.profiles.CONFIG_DIR", Path(tmp)), mock.patch(
            "core.profiles.PROFILES_FILE", Path(tmp) / "profiles.json"
        ), mock.patch.object(QMessageBox, "information"), mock.patch.object(
            QMessageBox, "warning"
        ):
            pm = ProfileManager()
            pm.add(ConnectionProfile(name="prod", host="prod.example", username="alice"))
            pm.add(ConnectionProfile(name="staging", host="staging.example", username="bob"))
            yield pm


def _answer(button):
    asked: list[str] = []

    def question(*args, **kwargs):
        asked.append(args[2])
        return button

    return asked, mock.patch.object(QMessageBox, "question", side_effect=question)


def _dialog(manager, name):
    from ui.connection_dialog import ConnectionDialog

    dlg = ConnectionDialog(manager)
    dlg._profile_combo.setCurrentText(name)
    return dlg


def _hosts() -> dict[str, str]:
    pm = ProfileManager()
    return {n: pm.get(n).host for n in pm.list_names()}


def test_sad_renaming_onto_another_profile_asks_and_no_keeps_both(manager):
    dlg = _dialog(manager, "prod")
    dlg._profile_name.setText("staging")
    asked, patch = _answer(QMessageBox.StandardButton.No)
    with patch:
        dlg._save_profile()
    assert len(asked) == 1 and "staging" in asked[0]
    assert _hosts() == {"prod": "prod.example", "staging": "staging.example"}


def test_happy_yes_replaces_the_other_profile(manager):
    dlg = _dialog(manager, "prod")
    dlg._profile_name.setText("staging")
    asked, patch = _answer(QMessageBox.StandardButton.Yes)
    with patch:
        dlg._save_profile()
    assert len(asked) == 1
    assert _hosts() == {"staging": "prod.example"}


def test_happy_saving_the_loaded_profile_asks_nothing(manager):
    dlg = _dialog(manager, "prod")
    dlg._host.setText("new.example")
    asked, patch = _answer(QMessageBox.StandardButton.No)
    with patch:
        dlg._save_profile()
    assert asked == []
    assert _hosts()["prod"] == "new.example"


def test_edge_a_new_connection_with_a_taken_automatic_name_asks(manager):
    manager.add(ConnectionProfile(name="alice@prod.example", host="prod.example",
                                  username="alice", auth_type="key", key_file="/k/id"))
    dlg = _dialog(manager, "(New Connection)")
    dlg._host.setText("prod.example")
    dlg._username.setText("alice")
    asked, patch = _answer(QMessageBox.StandardButton.No)
    with patch:
        dlg._save_profile()
    assert len(asked) == 1
    kept = ProfileManager().get("alice@prod.example")
    assert (kept.auth_type, kept.key_file) == ("key", "/k/id")


def test_edge_a_new_unique_name_asks_nothing(manager):
    dlg = _dialog(manager, "(New Connection)")
    dlg._profile_name.setText("fresh")
    dlg._host.setText("fresh.example")
    dlg._username.setText("carol")
    asked, patch = _answer(QMessageBox.StandardButton.No)
    with patch:
        dlg._save_profile()
    assert asked == []
    assert _hosts()["fresh"] == "fresh.example"
