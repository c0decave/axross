"""The terminal dock tells two SSH connections to one user@host apart.

The dock keyed its entries by the SSH
session's name, ``user@host``. Connecting a second profile with the same
user@host (another port, or two jump-host profiles to one inner address)
re-pointed the first entry to the new transport and restarted its RUNNING
shell there: a terminal opened on "prod" silently became a shell on
"staging", and the next command ran on the wrong machine.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")
from PyQt6.QtWidgets import QApplication  # noqa: E402

from tests.test_terminal_screen_widget import _Channel  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def _pump(app, n=5):
    for _ in range(n):
        app.processEvents()


class _Transport:
    """A paramiko-like transport that records the shells opened on it."""

    def __init__(self, active=True):
        self.log = []
        self.active = active

    def open_session(self):
        return _Channel(self.log)

    def is_active(self):
        return self.active


def _labels(dock):
    combo = dock._session_combo
    return [combo.itemText(i) for i in range(combo.count())]


# -- the dock itself: a live entry is never re-pointed ------------------------


def _dock(app):
    from ui.terminal_widget import TerminalDock

    dock = TerminalDock()
    dock.resize(700, 300)
    dock.show()
    _pump(app)
    return dock


def _start(app, dock, label):
    dock._session_combo.setCurrentText(label)
    _pump(app)
    dock._start_session()
    return dock._tabs[label].session


def test_happy_a_second_live_transport_gets_its_own_entry(app):
    dock = _dock(app)
    prod = _Transport()
    dock.add_ssh_session("deploy@h", prod)
    running = _start(app, dock, "SSH: deploy@h")
    staging = _Transport()
    dock.add_ssh_session("deploy@h", staging)
    assert dock._tabs["SSH: deploy@h"].session is running  # not restarted
    assert running.is_active
    assert len([lbl for lbl in _labels(dock) if lbl.startswith("SSH: deploy@h")]) == 2
    combo = dock._session_combo
    data = {combo.itemText(i): combo.itemData(i) for i in range(combo.count())}
    assert data["SSH: deploy@h"] is prod
    assert staging in data.values()
    dock.remove_ssh_session("deploy@h")
    assert not [lbl for lbl in _labels(dock) if lbl.startswith("SSH:")]
    dock.shutdown()


def test_sad_a_reconnect_of_a_dead_transport_still_restarts_the_shell(app):
    dock = _dock(app)
    old = _Transport()
    dock.add_ssh_session("deploy@h", old)
    _start(app, dock, "SSH: deploy@h")
    old.active = False  # the link dropped
    new = _Transport()
    dock.add_ssh_session("deploy@h", new)
    assert [lbl for lbl in _labels(dock) if lbl.startswith("SSH:")] == ["SSH: deploy@h"]
    assert new.log, "the shell was not restarted on the new transport"
    dock.shutdown()


def test_edge_the_same_transport_registered_twice_keeps_one_entry(app):
    dock = _dock(app)
    transport = _Transport()
    dock.add_ssh_session("deploy@h", transport)
    running = _start(app, dock, "SSH: deploy@h")
    dock.add_ssh_session("deploy@h", transport)
    assert [lbl for lbl in _labels(dock) if lbl.startswith("SSH:")] == ["SSH: deploy@h"]
    assert dock._tabs["SSH: deploy@h"].session is running
    dock.shutdown()


# -- the window: entries are named after the profile, not user@host -----------


class _FakeSSH:
    def __init__(self, transport, user="deploy", host="127.0.0.1"):
        self.transport = transport
        self.connected = True
        self.name = f"{user}@{host}"

    def home(self):
        return "/"

    def list_dir(self, path):
        return []

    def is_dir(self, path):
        return True

    def exists(self, path):
        return True

    def normalize(self, path):
        return path

    def join(self, *parts):
        return os.path.join(*parts)

    def parent(self, path):
        return os.path.dirname(path)

    def disconnect(self):
        self.connected = False


@pytest.fixture
def win(app):
    from ui import main_window as MW

    home = tempfile.mkdtemp()
    with mock.patch("pathlib.Path.home", return_value=Path(home)):
        window = MW.MainWindow()
    yield window
    window._pane_profiles.clear()
    window.close()
    window.deleteLater()
    _pump(app)
    shutil.rmtree(home, ignore_errors=True)


def _connect(win, profile, session):
    from ui import main_window as MW

    def run_now(_profile, _pw, _kp, on_success, _on_failure):
        on_success(session)

    with (
        mock.patch.object(win, "_run_connect_async", side_effect=run_now),
        mock.patch.object(MW, "_is_ssh_session", return_value=True),
        mock.patch.object(win, "_add_to_recent"),
    ):
        win._quick_connect_profile(profile)


def _profile(name, port):
    from core.profiles import ConnectionProfile

    return ConnectionProfile(
        name=name, host="127.0.0.1", port=port, username="deploy", auth_type="key"
    )


def test_happy_two_profiles_on_one_user_at_host_get_two_entries(win):
    prod_t, stage_t = _Transport(), _Transport()
    _connect(win, _profile("prod", 2201), _FakeSSH(prod_t))
    _connect(win, _profile("staging", 2202), _FakeSSH(stage_t))
    dock = win._terminal_dock
    ssh = [lbl for lbl in _labels(dock) if lbl.startswith("SSH:")]
    assert len(ssh) == 2
    assert any("prod" in lbl for lbl in ssh) and any("staging" in lbl for lbl in ssh)


def test_sad_closing_one_pane_keeps_the_other_profiles_entry(win):
    from ui import main_window as MW

    _connect(win, _profile("prod", 2201), _FakeSSH(_Transport()))
    _connect(win, _profile("staging", 2202), _FakeSSH(_Transport()))
    staging_pane = win._panes[-1]
    with (
        mock.patch.object(MW, "_is_ssh_session", return_value=True),
        mock.patch.object(win._connection_manager, "release"),
    ):
        win._close_pane(staging_pane)
    ssh = [lbl for lbl in _labels(win._terminal_dock) if lbl.startswith("SSH:")]
    assert len(ssh) == 1 and "prod" in ssh[0]


def test_edge_default_port_keeps_a_short_name(win):
    from ui import main_window as MW

    name = MW._terminal_name(_FakeSSH(_Transport()), _profile("box", 22))
    assert name == "box (deploy@127.0.0.1)"
    assert MW._terminal_name(_FakeSSH(_Transport()), None) == "deploy@127.0.0.1"
