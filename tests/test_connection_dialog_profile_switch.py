"""Connect to Server: what a profile switch, a Delete, a rename and the two
connection buttons do with the form (review round 2).

* A typed secret survived a profile switch: ``_load_profile`` cleared the
  SSH password, the proxy password and the key passphrase, but not the
  password of FTP / SMB / WebDAV / IMAP (the S3 secret, the Azure key).
  Connect then sent A's password to B, and with "Save in keyring" on
  stored it as B's. (New Connection kept the last address family, too.)
* Delete removed the profile from the list, ``removeItem`` selected the
  next one and the form was emptied under its name: the next Delete
  removed a profile the user was not looking at.
* A rename left the old name in the list (for a profile that was gone),
  and Save emptied the typed SSH password: selecting the saved name loaded
  the profile again.
* Deploy SSH Key built ``SSHSession(profile)`` from the form: a profile set
  to "default proxy" went to the server directly.
* Test Connection left the session open when ``session.home()`` raised
  after a successful connect, and enrolled it in ``core.conn_health``
  under the app's own key: its disconnect removed the health record of a
  pane open on that profile.
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

from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication, QInputDialog, QMessageBox  # noqa: E402

from core.profiles import ConnectionProfile  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture()
def manager():
    from core.profiles import ProfileManager

    with tempfile.TemporaryDirectory() as tmp:
        with mock.patch("core.profiles.CONFIG_DIR", Path(tmp)), \
                mock.patch("core.profiles.PROFILES_FILE", Path(tmp) / "profiles.json"), \
                mock.patch.object(QMessageBox, "information"), \
                mock.patch.object(QMessageBox, "warning"), \
                mock.patch.object(QMessageBox, "critical"), \
                mock.patch.object(QMessageBox, "question",
                                  return_value=QMessageBox.StandardButton.Yes):
            pm = ProfileManager()
            pm.add(ConnectionProfile(name="a-ftp", protocol="ftp", host="a.example",
                                     username="alice", port=21, address_family="ipv6"))
            pm.add(ConnectionProfile(name="b-ftp", protocol="ftp", host="b.example",
                                     username="bob", port=21))
            pm.add(ConnectionProfile(name="c-sftp", protocol="sftp", host="c.example",
                                     username="carol"))
            yield pm


@pytest.fixture
def dialogs():
    made = []
    yield made
    for dlg in made:
        dlg.close()
        dlg.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def _open(dialogs, manager):
    from ui.connection_dialog import ConnectionDialog

    dlg = ConnectionDialog(manager)
    dialogs.append(dlg)
    return dlg


def _combo_items(dlg) -> list[str]:
    combo = dlg._profile_combo
    return [combo.itemText(i) for i in range(combo.count())]


# -- typed secrets and a profile switch --------------------------------------


def test_sad_a_typed_ftp_password_does_not_go_to_the_next_profile(dialogs, manager):
    dlg = _open(dialogs, manager)
    dlg._profile_combo.setCurrentText("a-ftp")
    dlg._simple_password.setText("ALICE-SECRET")
    dlg._profile_combo.setCurrentText("b-ftp")
    assert dlg._host.text() == "b.example"
    assert dlg._simple_password.text() == ""
    with mock.patch.object(dlg, "_validate_backend_available", return_value=True):
        dlg._on_accept()
    assert dlg.result_profile.host == "b.example"
    assert dlg.result_password == ""  # not Alice's


def test_happy_every_secret_field_is_empty_after_a_switch(dialogs, manager):
    dlg = _open(dialogs, manager)
    dlg._profile_combo.setCurrentText("c-sftp")
    for field in (dlg._password, dlg._simple_password, dlg._key_passphrase,
                  dlg._proxy_password):
        field.setText("typed")
    dlg._profile_combo.setCurrentText("a-ftp")
    assert [f.text() for f in (dlg._password, dlg._simple_password, dlg._key_passphrase,
                               dlg._proxy_password)] == ["", "", "", ""]


def test_edge_new_connection_forgets_the_last_address_family(dialogs, manager):
    dlg = _open(dialogs, manager)
    dlg._profile_combo.setCurrentText("a-ftp")
    assert dlg._addr_family.currentIndex() == 2  # ipv6
    dlg._simple_password.setText("x")
    dlg._profile_combo.setCurrentText("(New Connection)")
    assert dlg._addr_family.currentIndex() == 0  # auto
    assert dlg._simple_password.text() == ""


# -- Delete --------------------------------------------------------------------


def test_sad_after_delete_the_list_shows_new_connection_not_the_next_profile(
        dialogs, manager):
    dlg = _open(dialogs, manager)
    dlg._profile_combo.setCurrentText("a-ftp")
    dlg._delete_profile()
    assert manager.get("a-ftp") is None
    assert dlg._profile_combo.currentText() == "(New Connection)"
    assert dlg._loaded_profile_name is None and dlg._host.text() == ""
    # A second Delete removes nothing: the form is a new connection.
    dlg._delete_profile()
    assert manager.get("b-ftp") is not None
    assert "b-ftp" in _combo_items(dlg)


# -- rename / Save ---------------------------------------------------------------


def test_sad_a_rename_drops_the_old_name_and_keeps_the_typed_password(dialogs, manager):
    dlg = _open(dialogs, manager)
    dlg._profile_combo.setCurrentText("c-sftp")
    dlg._profile_name.setText("c-renamed")
    dlg._password.setText("typed")
    with mock.patch.object(dlg, "_validate_backend_available", return_value=True):
        dlg._save_profile()
    assert _combo_items(dlg) == ["(New Connection)", "a-ftp", "b-ftp", "c-renamed"]
    assert dlg._profile_combo.currentText() == "c-renamed"
    assert dlg._loaded_profile_name == "c-renamed"
    assert dlg._password.text() == "typed"
    assert manager.get("c-sftp") is None and manager.get("c-renamed") is not None


def test_happy_saving_a_new_connection_keeps_the_typed_password(dialogs, manager):
    dlg = _open(dialogs, manager)
    dlg._profile_name.setText("d-sftp")
    dlg._host.setText("d.example")
    dlg._username.setText("dave")
    dlg._password.setText("typed")
    dlg._key_passphrase.setText("phrase")
    with mock.patch.object(dlg, "_validate_backend_available", return_value=True):
        dlg._save_profile()
    assert dlg._profile_combo.currentText() == "d-sftp"
    assert (dlg._password.text(), dlg._key_passphrase.text()) == ("typed", "phrase")
    # A second Save is no "rename onto an existing profile".
    with mock.patch.object(dlg, "_validate_backend_available", return_value=True):
        dlg._save_profile()
    assert _combo_items(dlg).count("d-sftp") == 1


# -- the route of Deploy SSH Key -------------------------------------------------


def test_sad_deploy_ssh_key_takes_the_default_proxy(dialogs, manager, tmp_path, monkeypatch):
    import ui.connection_dialog as CD
    from core import proxy_settings as PS

    monkeypatch.setattr(PS, "SETTINGS_PATH", tmp_path / "proxy.json")
    PS.save(PS.ProxyDefaults(proxy_type="socks5", host="proxy.corp", port=1080))
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "id.pub").write_text("ssh-ed25519 AAAA test")
    monkeypatch.setattr(Path, "home", lambda: home)

    dlg = _open(dialogs, manager)
    dlg._host.setText("ssh.example")
    dlg._username.setText("u")
    assert dlg._proxy_group.isChecked() and dlg._proxy_mode.currentIndex() == 0
    seen = {}

    class FakeSession:
        def __init__(self, profile):
            seen["profile"] = profile

        def connect(self, **_kw):
            raise RuntimeError("stop here")

        def disconnect(self):
            pass

    with mock.patch.object(CD, "SSHSession", FakeSession), \
            mock.patch.object(QInputDialog, "getItem", return_value=("id.pub", True)), \
            mock.patch("ui.off_gui.run_off_gui", side_effect=lambda f: f()), \
            mock.patch.object(dlg, "_validate_backend_available", return_value=True):
        dlg._deploy_ssh_key()
    profile = seen["profile"]
    assert (profile.proxy_type, profile.proxy_host) == ("socks5", "proxy.corp")


# -- Test Connection ---------------------------------------------------------------


class _Session:
    def __init__(self, closed):
        self._closed = closed

    def home(self):
        raise OSError("PWD refused")

    def close(self):
        self._closed.append(1)


def test_sad_test_connection_closes_the_session_when_home_fails(monkeypatch):
    import core.connection_manager as CM
    from ui.connection_dialog import _ConnectThread

    closed: list = []

    class FakeManager:
        def __init__(self):
            self.sessions = []

        def connect(self, profile, **_kw):
            session = _Session(closed)
            self.sessions.append(session)
            return session

        def disconnect_all(self):
            for session in self.sessions:
                session.close()

    monkeypatch.setattr(CM, "ConnectionManager", FakeManager)
    thread = _ConnectThread(object(), "pw", "")
    errors: list = []
    thread.error.connect(errors.append)
    thread.start()
    assert thread.wait(5000)
    APP.processEvents()
    assert errors == ["PWD refused"]
    assert closed == [1]


def test_edge_a_test_connection_leaves_the_health_records_alone(monkeypatch):
    """The test session is never enrolled, so its disconnect cannot remove
    the record a pane open on the same profile has under the same key."""
    import core.connection_manager as CM
    from ui.connection_dialog import _ConnectThread

    health: list = []
    monkeypatch.setattr(CM.ConnectionManager, "_enroll_health",
                        staticmethod(lambda *a, **k: health.append("enroll")))
    monkeypatch.setattr(CM.ConnectionManager, "_unenroll_health",
                        staticmethod(lambda *a, **k: health.append("unenroll")))

    class Session:
        def home(self):
            return "/home/u"

    def create(self, profile, password, key_passphrase, on_unknown_host):
        return Session()

    monkeypatch.setattr(CM.ConnectionManager, "_create_session", create)
    monkeypatch.setattr(CM.ConnectionManager, "_disconnect_session", lambda self, s: None)
    profile = ConnectionProfile(name="p", protocol="sftp", host="h.example", username="u")
    thread = _ConnectThread(profile, "pw", "")
    homes: list = []
    errors: list = []
    thread.success.connect(homes.append)
    thread.error.connect(errors.append)
    thread.start()
    assert thread.wait(5000)
    APP.processEvents()
    assert errors == [] and homes == ["/home/u"]
    assert health == []
