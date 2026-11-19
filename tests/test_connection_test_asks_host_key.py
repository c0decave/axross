"""Test Connection asks "Trust Host Key?" for a new SFTP host.

A new profile's Test Connection to a server whose host key was not in
known_hosts only said "Use Connect to review its fingerprint and trust it":
no question, no way to accept the key there. It asks now, as Connect and
Deploy Key do: Yes stores the key and the test goes on; No is a note, not
a failure, and stores nothing.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")
pytest.importorskip("paramiko")

from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402
from settings_testkit import isolate  # noqa: E402
from sftp_testkit import SftpServer  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _wait(predicate, timeout: float = 20.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if predicate():
            return True
        time.sleep(0.02)
    return False


@pytest.fixture
def setup(tmp_path, monkeypatch):
    stores = isolate(tmp_path, monkeypatch)
    served = tmp_path / "served"
    served.mkdir()
    server = SftpServer(str(served))
    shown: list = []
    for kind in ("information", "critical", "warning"):
        monkeypatch.setattr(QMessageBox, kind, staticmethod(
            lambda *a, _k=kind, **k: shown.append((_k, a[1], a[2]))))
    from core.profiles import ConnectionProfile, ProfileManager
    from ui.connection_dialog import ConnectionDialog

    profile = ConnectionProfile(name="new", protocol="sftp", host="127.0.0.1", port=server.port,
                                username="u", auth_type="password")
    dialog = ConnectionDialog(ProfileManager(), None, profile=profile)
    dialog._password.setText("pw")
    yield dialog, shown, monkeypatch
    dialog.done(0)
    dialog.deleteLater()
    stores.restore()
    server.close()


def _known_hosts() -> str:
    from core.ssh_client import SSHSession

    path = Path(getattr(SSHSession, "KNOWN_HOSTS_PATH", "") or Path.home() / ".ssh" / "known_hosts")
    candidates = [path, Path.home() / ".ssh" / "known_hosts",
                  Path.home() / ".config" / "axross" / "known_hosts"]
    return "".join(p.read_text() for p in candidates if p.is_file())


def test_happy_test_connection_asks_and_a_yes_trusts_the_key(setup):
    dialog, shown, monkeypatch = setup
    asked = []
    monkeypatch.setattr(QMessageBox, "question", staticmethod(
        lambda *a, **k: (asked.append(a[1]), QMessageBox.StandardButton.Yes)[1]))
    dialog._test_connection()
    assert _wait(lambda: shown), "the test never finished"
    assert asked == ["Trust Host Key?"]
    kind, title, text = shown[0]
    assert (kind, title) == ("information", "Success"), shown
    assert "127.0.0.1" in _known_hosts()


def test_sad_a_no_is_a_note_and_trusts_nothing(setup):
    dialog, shown, monkeypatch = setup
    monkeypatch.setattr(QMessageBox, "question", staticmethod(
        lambda *a, **k: QMessageBox.StandardButton.No))
    dialog._test_connection()
    assert _wait(lambda: shown), "the test never finished"
    kind, title, text = shown[0]
    assert (kind, title) == ("information", "Not Connected"), shown
    assert "did not trust" in text
    assert "127.0.0.1" not in _known_hosts()
