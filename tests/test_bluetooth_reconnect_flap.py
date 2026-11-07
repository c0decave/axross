"""Reconnect automatically gives up on a device that connects and drops
again at once.

BlueZ can connect a device and drop it right away (a profile it needs
fails: br-connection-profile-unavailable). Every brief Connected=True
counted as repaired and started the count over, so such a device was
retried for ever - 49 attempts in 2 s with three allowed, and gave_up
never came. A connection now counts as repaired only once it has stayed
up for a while; dropping before continues the count.
"""

from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QCoreApplication, QObject, QTimer, pyqtSignal  # noqa: E402

from core import bluetooth_link as BTL  # noqa: E402

from PyQt6.QtWidgets import QApplication  # noqa: E402

# QApplication, not QCoreApplication: the worker runs widget tests after this one
APP = QCoreApplication.instance() or QApplication([])
PATH = "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_07"


@dataclass(frozen=True)
class Dev:
    path: str
    address: str
    connected: bool
    adapter: str = "/org/bluez/hci0"


@dataclass(frozen=True)
class Adapter:
    path: str
    powered: bool = True


class FlappingClient(QObject):
    """A client whose device connects on request and, when *flaps*, drops
    again 10 ms later."""

    device_updated = pyqtSignal(str)
    devices_changed = pyqtSignal()
    adapters_changed = pyqtSignal()
    operation_finished = pyqtSignal(str, str, str)

    def __init__(self) -> None:
        super().__init__()
        self.dev = Dev(PATH, "AA:BB:CC:DD:EE:07", True)
        self.connects = 0
        self.flaps = True

    def devices(self):
        return [self.dev]

    def device(self, path):
        return self.dev if path == self.dev.path else None

    def adapter(self, path):
        return Adapter(path) if path == self.dev.adapter else None

    def set(self, on: bool) -> None:
        self.dev = replace(self.dev, connected=on)
        self.device_updated.emit(self.dev.path)

    def connect_device(self, path) -> None:
        self.connects += 1

        def connected():
            self.set(True)
            self.operation_finished.emit(path, "connect", "")
            if self.flaps:
                QTimer.singleShot(10, lambda: self.set(False))

        QTimer.singleShot(5, connected)


def run(seconds: float, until=lambda: False) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end and not until():
        APP.processEvents()
        time.sleep(0.002)


@pytest.fixture
def setup(tmp_path):
    client = FlappingClient()
    rec = BTL.Reconnector(client, path=tmp_path / "bt.json", delays=(0.01, 0.01, 0.01),
                          stable=0.5)
    rec.set_enabled(client.dev, True)
    events = {"attempts": [], "back": 0, "gave_up": []}
    rec.attempting.connect(lambda p, n: events["attempts"].append(n))
    rec.reconnected.connect(lambda p: events.__setitem__("back", events["back"] + 1))
    rec.gave_up.connect(events["gave_up"].append)
    yield client, rec, events
    rec.stop()


def test_sad_a_device_that_drops_at_once_is_given_up(setup):
    client, rec, events = setup
    client.set(False)  # the first drop
    run(2.0, until=lambda: events["gave_up"])
    run(0.2)  # nothing after giving up
    assert events["gave_up"] == [PATH]
    assert events["attempts"] == [1, 2, 3]
    assert client.connects == rec.max_attempts == 3


def test_happy_a_connection_that_stays_up_starts_the_count_over(setup):
    client, rec, events = setup
    client.flaps = False
    client.set(False)
    run(1.0, until=lambda: events["back"])
    assert events["attempts"] == [1]
    run(0.7)  # longer than the stable time
    client.set(False)  # a later, separate drop
    run(1.0, until=lambda: events["back"] == 2)
    assert events["attempts"] == [1, 1] and events["gave_up"] == []


def test_edge_the_user_s_disconnect_after_a_flap_starts_over(setup):
    client, rec, events = setup
    client.flaps = False
    client.set(False)
    run(1.0, until=lambda: events["back"])
    rec.expect_disconnect(PATH)
    client.set(False)  # the user's own: no attempt, and the count is gone
    run(0.1)
    client.set(True)
    client.set(False)  # a real drop right after
    run(1.0, until=lambda: events["back"] == 2)
    assert events["attempts"] == [1, 1]
