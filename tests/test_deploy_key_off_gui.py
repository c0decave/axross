"""Deploy SSH Key no longer freezes the window.

Audit (feedback: no blocked windows): the connection dialog's Deploy SSH
Key connected, looked at ~/.ssh and wrote authorized_keys on the GUI
thread - a handshake and about eight round trips with every window
frozen. It runs on a worker now (ui.off_gui); the host-key question
still comes up on the GUI thread (core.connect_worker.HostKeyPrompt),
and its answer reaches the connect.
"""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QTimer  # noqa: E402
from PyQt6.QtWidgets import QApplication, QInputDialog, QMessageBox  # noqa: E402

from core.profiles import ConnectionProfile, ProfileManager  # noqa: E402

APP = QApplication.instance() or QApplication([])

# TICKS_NOTE: a timer that ticked at all ran during the wait - a GUI thread
# held by the call gets none (the timer stops before the loop runs again).
# How often it ticked depends on the host's load, so only "at all" counts.


class FakeSession:
    """An SSH server holding one home folder in memory."""

    files: dict[str, bytes] = {}
    threads: list[str] = []
    asked: list[bool] = []

    def __init__(self, profile) -> None:
        self.profile = profile

    def connect(self, password="", key_passphrase="", on_unknown_host=None):
        FakeSession.threads.append(threading.current_thread().name)
        time.sleep(0.3)
        if on_unknown_host is not None:
            FakeSession.asked.append(on_unknown_host(RuntimeError("new host key")))
            if not FakeSession.asked[-1]:
                raise OSError("host key rejected")

    def home(self):
        return "/home/u"

    def join(self, *parts):
        return "/".join(p.rstrip("/") for p in parts)

    def exists(self, path):
        FakeSession.threads.append(threading.current_thread().name)
        return path in FakeSession.files or path == "/home/u/.ssh"

    def mkdir(self, path):
        pass

    def chmod(self, path, mode):
        pass

    def open_read(self, path):
        import io

        return io.BytesIO(FakeSession.files.get(path, b""))

    def disconnect(self):
        pass


@pytest.fixture
def dialog(tmp_path, monkeypatch):
    from ui import connection_dialog as CD

    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "id_ed25519.pub").write_text("ssh-ed25519 AAAAtest me@host\n")
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setattr(CD, "SSHSession", FakeSession)
    written: dict = {}

    def write(session, path, data):
        FakeSession.threads.append(threading.current_thread().name)
        written[path] = data

    monkeypatch.setattr("core.atomic_io.atomic_write", write)
    FakeSession.files, FakeSession.threads, FakeSession.asked = {}, [], []
    with tempfile.TemporaryDirectory() as tmp, mock.patch(
            "core.profiles.CONFIG_DIR", Path(tmp)), mock.patch(
            "core.profiles.PROFILES_FILE", Path(tmp) / "profiles.json"):
        profile = ConnectionProfile(name="srv", protocol="sftp", host="srv.example", username="u")
        dlg = CD.ConnectionDialog(ProfileManager(), profile=profile)
        dlg.written = written
        monkeypatch.setattr(dlg, "_validate", lambda: True)
        monkeypatch.setattr(QInputDialog, "getItem", lambda *a, **k: ("id_ed25519.pub", True))
        yield dlg
        dlg.deleteLater()


def test_happy_the_deploy_runs_off_the_gui_thread_and_asks_here(dialog):
    questions: list[str] = []

    def confirm(_error):
        questions.append(threading.current_thread().name)
        return True

    dialog._confirm_unknown_host = confirm
    ticks = []
    timer = QTimer()
    timer.setInterval(20)
    timer.timeout.connect(lambda: ticks.append(1))
    timer.start()
    with mock.patch.object(QMessageBox, "information") as info:
        dialog._deploy_ssh_key()
    timer.stop()
    assert "Successfully deployed id_ed25519.pub" in info.call_args.args[2]
    assert dialog.written == {"/home/u/.ssh/authorized_keys": b"ssh-ed25519 AAAAtest me@host\n"}
    assert "MainThread" not in FakeSession.threads
    assert questions == ["MainThread"] and FakeSession.asked == [True]
    assert len(ticks) >= 1
    assert dialog._btn_deploy_key.isEnabled() and dialog._btn_deploy_key.text() == "Deploy SSH Key"


def test_sad_a_rejected_host_key_is_reported(dialog):
    dialog._confirm_unknown_host = lambda _error: False
    with mock.patch.object(QMessageBox, "critical") as critical:
        dialog._deploy_ssh_key()
    assert "host key rejected" in critical.call_args.args[2]
    assert dialog.written == {}
    assert dialog._btn_deploy_key.isEnabled()


def test_edge_a_key_already_there_is_said_and_not_written_again(dialog):
    dialog._confirm_unknown_host = lambda _error: True
    FakeSession.files["/home/u/.ssh/authorized_keys"] = b"ssh-ed25519 AAAAtest me@host\n"
    with mock.patch.object(QMessageBox, "information") as info:
        dialog._deploy_ssh_key()
    assert "already deployed" in info.call_args.args[2]
    assert dialog.written == {}
