"""A repeated DisplayPasskey updates the pairing dialog already open
(review round 2).

BlueZ's Agent1 API: DisplayPasskey "might be called multiple times to
update the entered value" - once per digit typed on the keyboard being
paired. Before, every call was a new request with a new token, and the
panel opened one more pairing dialog for each: seven dialogs stacked up
for one passkey. Now the client keeps the token of a code already shown
for the same device and kind, and the panel updates the dialog that
shows it (also for a request with another token, as the USB-stick
backend makes them).
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import bluetooth as BT  # noqa: E402

APP = QApplication.instance() or QApplication([])
DEV = "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_01"
OTHER = "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_02"


def _panel():
    spec = importlib.util.spec_from_file_location(
        "bt_display_passkey", ROOT / "resources" / "extensions" / "bluetooth.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    client = BT.BluezClient(bus=None)
    return client, module.BluetoothPanel(client, sink_lister=lambda: [])


def _open(panel) -> list:
    APP.processEvents()
    return [d for d in panel._agent_dialogs.values() if d.isVisible()]


def test_sad_one_dialog_for_a_passkey_shown_digit_by_digit():
    client, panel = _panel()
    try:
        for _digit in range(7):
            client._agent_show("display-passkey", DEV, passkey=123456)
        shown = _open(panel)
        assert len(shown) == 1
        assert "123456" in shown[0].text_label.text()
        # The digits typed so far (DisplayPasskey's "entered") are shown.
        client._agent_show("display-passkey", DEV, passkey=123456, entered=6)
        assert _open(panel) == shown
        assert "6 of 6" in shown[0].text_label.text()
        # Another device's code is a dialog of its own.
        client._agent_show("display-passkey", OTHER, passkey=654321)
        assert len(_open(panel)) == 2
        # BlueZ's Cancel closes the one dialog of the first device.
        client._agent_cancel_all()
        assert _open(panel) == []
    finally:
        panel.close()
        panel.deleteLater()


def test_edge_a_request_with_another_token_updates_the_open_dialog():
    """The USB-stick backend makes a new token per call: matched by device
    and kind."""
    client, panel = _panel()
    try:
        for token, passkey in ((901, 42), (902, 43)):
            panel._agent_request(BT.AgentRequest(token=token, kind="display-passkey",
                                                 device_path=DEV, device_name="Keyboard",
                                                 passkey=passkey))
        shown = _open(panel)
        assert len(shown) == 1
        assert "000043" in shown[0].text_label.text()  # the latest
        panel._agent_cancelled(902)
        assert _open(panel) == []
    finally:
        panel.close()
        panel.deleteLater()
