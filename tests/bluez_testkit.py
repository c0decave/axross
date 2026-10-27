"""A private D-Bus with the fake BlueZ of tests/fake_bluez.py on it.

``FakeBluezBus`` starts ``dbus-daemon`` on a socket in a temporary folder
(never the host's system or session bus), then the fake service, and
steers the fake through its JSON control method. The Qt side gets its own
connection to the same bus (:meth:`FakeBluezBus.qt_connection`), which is
what core.bluetooth.BluezClient takes instead of the system bus.

Skips (pytest.skip) when dbus-daemon, jeepney or PyQt6.QtDBus is missing.
"""

from __future__ import annotations

import json
import os
import select
import shutil
import subprocess
import sys
import tempfile
import time
from itertools import count
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
FAKE = HERE / "fake_bluez.py"
_names = count(1)


def _pump(seconds: float) -> None:
    from PyQt6.QtTest import QTest

    QTest.qWait(int(seconds * 1000))


def wait_until(predicate, timeout: float = 5.0, step: float = 0.02) -> bool:
    """Run the Qt event loop until *predicate()* is true or *timeout* ends."""
    from PyQt6.QtCore import QCoreApplication

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        QCoreApplication.processEvents()
        if predicate():
            return True
        _pump(step)
    QCoreApplication.processEvents()
    return bool(predicate())


class FakeBluezBus:
    def __init__(self) -> None:
        daemon = shutil.which("dbus-daemon")
        if daemon is None:
            pytest.skip("dbus-daemon is not installed")
        pytest.importorskip("jeepney", reason="jeepney (keyring's D-Bus library) is missing")
        pytest.importorskip("PyQt6.QtDBus", reason="PyQt6.QtDBus is missing")
        self.dir = tempfile.mkdtemp(prefix="axross-fake-bluez-")
        self.daemon = subprocess.Popen(
            [daemon, "--session", "--nofork", "--nopidfile", "--print-address=1",
             f"--address=unix:dir={self.dir}"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        ready, _w, _x = select.select([self.daemon.stdout], [], [], 10)
        if not ready:
            self.close()
            raise RuntimeError("dbus-daemon gave no address")
        self.address = self.daemon.stdout.readline().strip()
        self.fake: subprocess.Popen | None = None
        self._control = None
        self._qt_names: list[str] = []
        self.start_fake()

    # -- the fake service ---------------------------------------------------------------

    def start_fake(self) -> None:
        env = dict(os.environ, DBUS_SESSION_BUS_ADDRESS=self.address)
        self.fake = subprocess.Popen([sys.executable, str(FAKE)], env=env, text=True,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ready, _w, _x = select.select([self.fake.stdout], [], [], 10)
        line = self.fake.stdout.readline().strip() if ready else ""
        if line != "ready":
            err = self.fake.stderr.read() if self.fake.poll() is not None else ""
            raise RuntimeError(f"the fake BlueZ did not start: {line!r} {err}")

    def kill_fake(self) -> None:
        """The service dies (bluetoothd crashed or was stopped)."""
        if self.fake is not None and self.fake.poll() is None:
            self.fake.kill()
            self.fake.wait(5)

    def control(self):
        if self._control is None:
            from jeepney.io.blocking import open_dbus_connection

            self._control = open_dbus_connection(bus=self.address)
        return self._control

    def command(self, op: str, **kw):
        from jeepney import DBusAddress, MessageType, new_method_call

        msg = new_method_call(DBusAddress("/org/axross/test", "org.bluez",
                                          "org.axross.test.FakeBluez"),
                              "Command", "s", (json.dumps({"op": op, **kw}),))
        reply = self.control().send_and_get_reply(msg, timeout=10)
        if reply.header.message_type == MessageType.error:
            raise RuntimeError(f"fake command {op} failed: {reply.body}")
        return json.loads(reply.body[0])

    def calls(self, member: str | None = None) -> list[dict]:
        calls = self.command("calls")
        return [c for c in calls if member is None or c["member"] == member]

    # -- the Qt side ----------------------------------------------------------------------

    def qt_connection(self):
        from PyQt6.QtDBus import QDBusConnection

        name = f"axross-test-bluez-{os.getpid()}-{next(_names)}"
        self._qt_names.append(name)
        conn = QDBusConnection.connectToBus(self.address, name)
        if not conn.isConnected():
            raise RuntimeError(f"cannot connect Qt to {self.address}: {conn.lastError().message()}")
        return conn

    def close(self) -> None:
        if self._control is not None:
            try:
                self._control.close()
            except OSError:
                pass
            self._control = None
        try:
            from PyQt6.QtDBus import QDBusConnection

            for name in self._qt_names:
                QDBusConnection.disconnectFromBus(name)
        except ImportError:
            pass
        self._qt_names = []
        self.kill_fake()
        for proc in (self.fake, self.daemon):
            if proc is not None:
                for stream in (proc.stdout, proc.stderr):
                    if stream is not None:
                        stream.close()
        if self.daemon.poll() is None:
            self.daemon.terminate()
            try:
                self.daemon.wait(5)
            except subprocess.TimeoutExpired:
                self.daemon.kill()
        shutil.rmtree(self.dir, ignore_errors=True)


__all__ = ["FakeBluezBus", "wait_until"]
