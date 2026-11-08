"""XMPP Encryption… asks for the OMEMO devices without holding the window.

The review found ``show_security`` waiting on the GUI thread for
``client.own_device()`` and ``client.devices_of(jid)`` -
``runner.submit(...).result(15)`` each, and python-omemo documents both as
network round trips: the window froze for up to 15 s per call, twice, and a
TimeoutError escaped the slot. The dialog's refresh after a trust change
asked the network again the same way. Now both run on the client's loop,
the dialog opens once they are in, and a timeout or error is shown.
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QMessageBox, QWidget  # noqa: E402

from core import chat as C  # noqa: E402
from core import extensions as EX  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _load():
    spec = importlib.util.spec_from_file_location("xmpp_encryption_off_gui",
                                                  EX.bundled_dir() / "xmpp.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


XM = _load()


def wait_until(cond, timeout: float = 5.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return cond()


class Client:
    """An online XMPP client whose device lookups take *delay* seconds on
    a real asyncio loop thread (as python-omemo's round trips do)."""

    def __init__(self, delay: float = 0.4, fail: BaseException | None = None) -> None:
        self.state = C.STATE_ONLINE
        self.jid = "me@example.net"
        self.runner = C.AsyncRunner("xmpp-test-loop")
        self.delay, self.fail = delay, fail
        self.asked_on: list[str] = []
        self.answered = threading.Event()

    def conversation(self, key):
        return C.Conversation(key=key, kind=C.CONV_DIRECT, title=key)

    async def own_device(self):
        self.asked_on.append(threading.current_thread().name)
        await asyncio.sleep(self.delay)
        return SimpleNamespace(device_id="1", fingerprint="aa bb")

    async def devices_of(self, jid):
        self.asked_on.append(threading.current_thread().name)
        await asyncio.sleep(self.delay)
        if self.fail is not None:
            raise self.fail
        self.answered.set()
        return [SimpleNamespace(user_id=jid, device_id="2", name="", fingerprint="cc dd",
                                trust="undecided", identity_key=b"k")]

    def set_trust(self, *args):
        pass


class Dialogs:
    """Stands in for DevicesDialog: records what it was opened with."""

    def __init__(self) -> None:
        self.opened: list = []

    def __call__(self, parent, title, own, devices, *args, **kwargs):
        record = self

        class Dialog:
            def setAttribute(self, *a):  # noqa: N802 - Qt
                pass

            def open(self):
                record.opened.append((title, own, list(devices()), devices))

        return Dialog()


def test_happy_the_window_stays_free_while_the_devices_are_fetched(monkeypatch):
    dialogs = Dialogs()
    monkeypatch.setattr(XM, "DevicesDialog", dialogs)
    panel = QWidget()
    client = Client(delay=0.4)
    try:
        started = time.monotonic()
        XM.show_security(panel, client, "bob@example.net")
        assert time.monotonic() - started < 0.3
        assert not client.answered.is_set() and dialogs.opened == []
        assert wait_until(lambda: dialogs.opened, 5)
        assert set(client.asked_on) == {"xmpp-test-loop"}
        title, own, devices, again = dialogs.opened[0]
        assert "bob@example.net" in title and own.device_id == "1"
        assert [d.device_id for d in devices] == ["2"]
        asked = len(client.asked_on)
        again()  # the dialog's refresh after a trust change: no new round trip
        assert len(client.asked_on) == asked
    finally:
        panel.deleteLater()


def test_sad_no_answer_in_time_is_shown_not_raised(monkeypatch):
    dialogs = Dialogs()
    shown: list[str] = []
    monkeypatch.setattr(XM, "DevicesDialog", dialogs)
    monkeypatch.setattr(XM, "DEVICES_TIMEOUT", 0.2)
    monkeypatch.setattr(QMessageBox, "open", lambda self: shown.append(self.text()))
    panel = QWidget()
    try:
        XM.show_security(panel, Client(delay=5.0), "bob@example.net")
        assert wait_until(lambda: shown, 5)
        assert "did not answer" in shown[0] and dialogs.opened == []
    finally:
        panel.deleteLater()


def test_sad_an_error_of_the_lookup_is_shown(monkeypatch):
    dialogs = Dialogs()
    shown: list[str] = []
    monkeypatch.setattr(XM, "DevicesDialog", dialogs)
    monkeypatch.setattr(QMessageBox, "open", lambda self: shown.append(self.text()))
    panel = QWidget()
    try:
        XM.show_security(panel, Client(delay=0.0, fail=C.ChatError("OMEMO is not running.")),
                         "bob@example.net")
        assert wait_until(lambda: shown, 5)
        assert "OMEMO is not running." in shown[0] and dialogs.opened == []
    finally:
        panel.deleteLater()


def test_edge_a_panel_closed_before_the_answer_gets_nothing(monkeypatch):
    dialogs = Dialogs()
    monkeypatch.setattr(XM, "DevicesDialog", dialogs)
    panel = QWidget()
    client = Client(delay=0.2)
    XM.show_security(panel, client, "bob@example.net")
    panel.deleteLater()
    from PyQt6.QtCore import QEvent

    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    assert client.answered.wait(5)
    wait_until(lambda: False, 0.3)
    assert dialogs.opened == []
