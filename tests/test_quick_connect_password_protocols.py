"""Quick Connect asks for the password of every protocol that has one.

Found by the GUI end-to-end run against the lab: a Telnet profile failed
with "Login incorrect". Quick Connect prompted (and read the keyring) only
for a hand-written list of protocols - telnet, cisco-telnet, dfsn, pop3,
nntp and winrm were missing, although the connection dialog offers their
password field. They connected with an empty password, even with the
password saved. Both now derive from one set,
``core.profiles.SIMPLE_PASSWORD_PROTOCOLS``.

The same run: an Azure profile showed Host and Port in the dialog, but
the backend never reads them - the endpoint comes from the account name
or the connection string. A host entered there was silently replaced by
``<account>.blob.core.windows.net``. The dialog no longer shows them for
Azure, and Quick Connect does not ask for an account key that a
connection string or SAS token already carries.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QInputDialog  # noqa: E402

from core.profiles import SIMPLE_PASSWORD_PROTOCOLS, ConnectionProfile  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture(scope="module")
def window():
    # One window for the module: each test patches it afresh.
    from ui.main_window import MainWindow

    win = MainWindow()
    win._reconnect_timer.stop()
    yield win
    win.close()
    win.deleteLater()
    pump()


@pytest.fixture
def connect(window, monkeypatch):
    """Record the prompts and the password each connect is started with."""
    from core import credentials

    seen = {"prompts": [], "passwords": [], "stored": {}}

    def fake_get_text(parent, title, label, *a, **k):
        seen["prompts"].append(label)
        return seen.get("answer", "typed"), seen.get("ok", True)

    monkeypatch.setattr(QInputDialog, "getText", staticmethod(fake_get_text))
    monkeypatch.setattr(credentials, "get_password", lambda name: seen["stored"].get(name))
    monkeypatch.setattr(
        window,
        "_run_connect_async",
        lambda profile, pw, kp, on_success, on_failure: seen["passwords"].append(pw),
    )

    def run(**fields):
        fields.setdefault("name", "p")
        fields.setdefault("host", "lab.example")
        fields.setdefault("username", "u")
        window._quick_connect_profile(ConnectionProfile(**fields))
        return seen

    run.seen = seen
    return run


def _ready(proto: str) -> dict:
    """Fields a profile of *proto* needs before its password matters."""
    fields = {"protocol": proto}
    if proto in ("azure_blob", "azure_files"):
        fields["azure_account_name"] = "acct"
    return fields


# --- happy -----------------------------------------------------------------


def test_happy_telnet_prompts_and_connects_with_the_typed_password(connect) -> None:
    seen = connect(protocol="telnet")
    assert seen["prompts"] and "Telnet" in seen["prompts"][0]
    assert seen["passwords"] == ["typed"]


def test_happy_a_saved_telnet_password_is_used_without_a_prompt(connect) -> None:
    connect.seen["stored"]["p"] = "saved"
    seen = connect(protocol="telnet")
    assert seen["prompts"] == []
    assert seen["passwords"] == ["saved"]


@pytest.mark.parametrize("proto", sorted(SIMPLE_PASSWORD_PROTOCOLS))
def test_happy_every_password_protocol_prompts(connect, proto) -> None:
    seen = connect(**_ready(proto))
    assert len(seen["prompts"]) == 1, proto
    assert seen["passwords"] == ["typed"], proto


# --- sad -------------------------------------------------------------------


def test_sad_cancelling_the_prompt_does_not_connect(connect) -> None:
    connect.seen["ok"] = False
    seen = connect(protocol="pop3")
    assert len(seen["prompts"]) == 1
    assert seen["passwords"] == []


def test_sad_the_dialog_hides_host_and_port_for_azure() -> None:
    from core.profiles import ProfileManager
    from ui.connection_dialog import ConnectionDialog

    dlg = ConnectionDialog(ProfileManager(), parent=None)
    try:
        for proto, host_shown in (("azure_blob", False), ("azure_files", False), ("telnet", True)):
            if proto not in dlg._protocol_ids:
                continue
            dlg._protocol_combo.setCurrentIndex(dlg._protocol_ids.index(proto))
            assert dlg._host.isHidden() is not host_shown, proto
            assert dlg._port.isHidden() is not host_shown, proto
    finally:
        dlg.deleteLater()


# --- edge ------------------------------------------------------------------


@pytest.mark.parametrize(
    "extra",
    [
        {"azure_connection_string": "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=a2V5;"},
        {"azure_sas_token": "sv=2024&sig=x"},
    ],
)
def test_edge_azure_with_its_own_credential_asks_for_no_key(connect, extra) -> None:
    seen = connect(**_ready("azure_blob"), **extra)
    assert seen["prompts"] == []
    assert seen["passwords"] == [""]


@pytest.mark.parametrize("proto", ["nntp", "s3"])
def test_edge_anonymous_nntp_and_s3_ask_for_nothing(connect, proto) -> None:
    seen = connect(protocol=proto, username="")
    assert seen["prompts"] == []
    assert seen["passwords"] == [""]


def test_edge_the_dialog_password_field_follows_the_same_set() -> None:
    from core.profiles import ProfileManager
    from ui.connection_dialog import ConnectionDialog

    dlg = ConnectionDialog(ProfileManager(), parent=None)
    try:
        for proto in dlg._protocol_ids:
            dlg._protocol_combo.setCurrentIndex(dlg._protocol_ids.index(proto))
            assert dlg._simple_password.isHidden() is (proto not in SIMPLE_PASSWORD_PROTOCOLS), proto
    finally:
        dlg.deleteLater()


@pytest.mark.parametrize("proto", sorted(SIMPLE_PASSWORD_PROTOCOLS | {"sftp", "scp", "nfs", "gopher"}))
def test_edge_the_mcp_server_needs_a_password_exactly_where_quick_connect_asks(connect, proto) -> None:
    from core.mcp_groups import password_prompt_needed

    profile = ConnectionProfile(name="p", host="lab.example", username="u", **_ready(proto))
    seen = connect(name="p", host="lab.example", username="u", **_ready(proto))
    assert password_prompt_needed(profile) is bool(seen["prompts"]), proto
