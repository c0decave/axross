"""SFTP on a network that goes silent: requests time out, Cancel wakes them.

Round 6 found (repro reconn/netloss/t_sftp*.py): the SFTP channel had no
time-out, so a request on a connection that went silent - no RST, no
answer: Wi-Fi gone, a NAT entry dropped - waited for ever (a listing, a
download, an upload), and Cancel could not stop a transfer blocked in
such a read or write: it is checked between chunks only.

Now (core.ssh_client.SFTP_IO_TIMEOUT): a request the server leaves
unanswered fails with TimeoutError (ETIMEDOUT) and a sentence, the next
call opens a new channel; in a running transfer Cancel closes the
channel (core.transfer_hooks.CancelWatch), so the blocked read or write
returns at once with InterruptedError.
"""

from __future__ import annotations

import errno
import os
import socket
import sys
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.ssh_client as ssh_client  # noqa: E402
from core import transfer_hooks  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402
from core.ssh_client import SSHSession  # noqa: E402


class _SilenceRelay:
    """TCP relay that, while ``silent``, passes nothing either way (and
    sends no RST): the network went quiet under an open connection."""

    def __init__(self, target_port: int) -> None:
        self.target = ("127.0.0.1", target_port)
        self.silent = False
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def close(self) -> None:
        self._sock.close()

    def _serve(self) -> None:
        while True:
            try:
                client, _ = self._sock.accept()
            except OSError:
                return
            upstream = socket.create_connection(self.target)
            for a, b in ((client, upstream), (upstream, client)):
                threading.Thread(target=self._pump, args=(a, b), daemon=True).start()

    def _pump(self, src, dst) -> None:
        try:
            while True:
                while self.silent:
                    time.sleep(0.02)
                data = src.recv(65536)
                if not data:
                    break
                while self.silent:  # held, as a dead link would
                    time.sleep(0.02)
                dst.sendall(data)
        except OSError:
            pass


@pytest.fixture
def sftp(tmp_path):
    from tests.sftp_testkit import SftpServer

    (tmp_path / "srv" / "d").mkdir(parents=True)
    for i in range(5):
        (tmp_path / "srv" / "d" / f"f{i}").write_bytes(b"x")
    (tmp_path / "srv" / "big.bin").write_bytes(os.urandom(3_000_000))
    (tmp_path / "home" / ".ssh").mkdir(parents=True)
    with mock.patch("pathlib.Path.home", return_value=tmp_path / "home"):
        srv = SftpServer(str(tmp_path / "srv"))
        relay = _SilenceRelay(srv.port)
        profile = ConnectionProfile(
            name="t", protocol="sftp", host="127.0.0.1", port=relay.port, username="u"
        )
        s = SSHSession(profile)
        s.connect(password="x", on_unknown_host=lambda _e: True)
        try:
            yield s, relay, tmp_path / "srv"
        finally:
            relay.silent = False
            s.disconnect()
            relay.close()
            srv.close()


def _in_thread(fn, cap: float):
    box: dict = {}

    def go():
        t0 = time.monotonic()
        try:
            box["ok"] = fn()
        except BaseException as exc:  # noqa: BLE001 - reported to the test
            box["exc"] = exc
        box["took"] = time.monotonic() - t0

    th = threading.Thread(target=go, daemon=True)
    th.start()
    th.join(cap)
    assert not th.is_alive(), f"still blocked after {cap} s"
    return box


def test_happy_a_working_connection_is_unaffected(sftp, monkeypatch):
    s, _relay, srv = sftp
    hooks = transfer_hooks.TransferHooks(threading.Event())
    with transfer_hooks.active(hooks):
        with s.open_read("/big.bin") as fh:
            data = fh.read()
        with s.open_write("/up.bin") as fh:
            fh.write(data)
    assert (srv / "up.bin").read_bytes() == (srv / "big.bin").read_bytes()
    assert sorted(i.name for i in s.list_dir("/d")) == [f"f{i}" for i in range(5)]


def test_sad_a_request_on_a_silent_connection_times_out(sftp, monkeypatch):
    from core.user_errors import describe

    s, relay, _srv = sftp
    monkeypatch.setattr(ssh_client, "SFTP_IO_TIMEOUT", 1.0)  # the thread's new channel

    def list_twice():
        s.list_dir("/d")  # this thread's channel is open
        relay.silent = True
        return s.list_dir("/d")

    box = _in_thread(list_twice, cap=20)  # was: for ever
    exc = box.get("exc")
    assert isinstance(exc, TimeoutError), box
    assert exc.errno == errno.ETIMEDOUT
    assert "sent nothing for 1 s" in str(exc)
    assert "did not answer in time" in describe(exc, "h")
    # A new channel on the silent connection: its opening times out too.
    box = _in_thread(lambda: s.list_dir("/d"), cap=20)
    exc = box.get("exc")
    assert isinstance(exc, TimeoutError) and exc.errno == errno.ETIMEDOUT, box
    assert "did not open a channel within 1 s" in str(exc)
    relay.silent = False
    # The timed-out channel is replaced: the next call works.
    assert len(s.list_dir("/d")) == 5


def test_sad_a_download_on_a_silent_connection_times_out(sftp):
    s, relay, _srv = sftp
    s._get_sftp_client().get_channel().settimeout(1.0)
    fh = s.open_read("/big.bin")
    fh.read(100_000)
    relay.silent = True
    box = _in_thread(lambda: fh.read(), cap=20)
    exc = box.get("exc")
    assert isinstance(exc, TimeoutError) and exc.errno == errno.ETIMEDOUT, box
    relay.silent = False
    fh.close()


def test_edge_cancel_wakes_a_download_blocked_on_a_silent_connection(sftp, monkeypatch):
    s, relay, _srv = sftp
    monkeypatch.setattr(ssh_client, "SFTP_IO_TIMEOUT", 120.0)
    cancel = threading.Event()
    hooks = transfer_hooks.TransferHooks(cancel)

    def download():
        with transfer_hooks.active(hooks):
            with s.open_read("/big.bin") as fh:
                fh.read(100_000)
                relay.silent = True
                threading.Timer(0.5, cancel.set).start()
                return fh.read()

    box = _in_thread(download, cap=15)  # was: blocked until the network came back
    assert isinstance(box.get("exc"), InterruptedError), box
    assert box["took"] < 10
    relay.silent = False
    assert len(s.list_dir("/d")) == 5  # a new channel for the next call


def test_edge_cancel_wakes_an_upload_blocked_on_a_silent_connection(sftp, monkeypatch):
    s, relay, srv = sftp
    # The WRITEs fill the socket's send buffer: paramiko retries a full
    # socket for ever, so the connection is closed after the grace time.
    monkeypatch.setattr(transfer_hooks.CancelWatch, "GRACE", 1.0)
    cancel = threading.Event()
    hooks = transfer_hooks.TransferHooks(cancel)
    payload = os.urandom(4 * 1024 * 1024)

    def upload():
        with transfer_hooks.active(hooks):
            fh = s.open_write("/up.bin")
            try:
                relay.silent = True
                threading.Timer(0.5, cancel.set).start()
                fh.write(payload)  # more than MAX_IN_FLIGHT: waits for acks
                fh.close()
            finally:
                relay.silent = False

    box = _in_thread(upload, cap=15)  # was: blocked until TCP gave up
    assert isinstance(box.get("exc"), InterruptedError), box
    assert box["took"] < 10


def test_edge_a_cancel_watch_outside_a_transfer_is_none():
    assert transfer_hooks.watch_cancel(lambda: None) is None
    hooks = transfer_hooks.TransferHooks(threading.Event())
    hooks.cancel_event.set()
    with transfer_hooks.active(hooks):
        with pytest.raises(InterruptedError):
            transfer_hooks.watch_cancel(lambda: None)


class _BlockingChannel:
    """An exec channel whose ``recv`` waits until it is closed."""

    def __init__(self) -> None:
        self.closed = threading.Event()

    def close(self) -> None:
        self.closed.set()

    def recv(self, _n: int) -> bytes:
        self.closed.wait(30)
        return b""


def test_edge_cancel_wakes_a_blocked_scp_channel():
    from core.scp_client import _closed_on_cancel

    chan = _BlockingChannel()
    cancel = threading.Event()
    hooks = transfer_hooks.TransferHooks(cancel)

    def read():
        with transfer_hooks.active(hooks):
            with _closed_on_cancel(chan):
                if not chan.recv(1):
                    raise OSError("Cannot read /x: the SCP stream ended")

    threading.Timer(0.3, cancel.set).start()
    box = _in_thread(read, cap=10)
    assert isinstance(box.get("exc"), InterruptedError), box
    assert box["took"] < 5
