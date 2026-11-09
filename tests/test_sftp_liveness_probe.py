"""SFTP: exec channels honour Cancel and a dead network; slow-but-alive
servers are waited for; Cancel keeps a shared connection.

Round 7 found (repros sftp/repro_sftp_checksum_hang.py,
sftp/repro_sftp_slow_but_alive.py):

* after every upload the transfer engine runs ``sha256sum`` over an SSH
  exec channel - with no time-out and no Cancel watch (keepalive is off
  by default, docs/OPSEC.md): a slow hash ignored Cancel, a network gone
  silent hung the job for ever with the temp file never renamed;
* the fixed 60 s SFTP time-out failed a server that is alive but slow to
  answer one request (a tape/HSM recall) as "check the network";
* Cancel's escalation closed the whole SSH connection - and every
  terminal on it - after 10 s.

Now an exec channel is watched (core.ssh_client._ExecWatch): Cancel
closes it; no output for the I/O time-out asks the connection whether it
is alive (keepalive@openssh.com) and fails only when it does not answer.
SFTP requests do the same before their time-out fires
(SFTP_SLOW_SERVER_CAP), the time-out is per profile (sftp_timeout), and
the escalation closes the connection only when nothing else uses it or
it does not answer.
"""

from __future__ import annotations

import errno
import os
import sys
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.ssh_client as ssh_client  # noqa: E402
from core import sftp_io, transfer_hooks  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402
from core.ssh_client import SSHSession  # noqa: E402
from test_sftp_silent_network import _in_thread, _SilenceRelay  # noqa: E402
from tests import sftp_testkit as K  # noqa: E402

_EXEC_SEEN = threading.Event()


def _silent_exec(self, channel, command):
    """A command that runs "for ever" and never answers."""
    _EXEC_SEEN.set()
    return True


def _late_hash(delay: float):
    """A sha256sum that answers after *delay* seconds."""

    def handler(self, channel, command):
        def answer():
            time.sleep(delay)
            channel.sendall(b"%s  /x\n" % (b"ab" * 32))
            channel.send_exit_status(0)
            channel.close()

        threading.Thread(target=answer, daemon=True).start()
        return True

    return handler


@pytest.fixture
def sftp(tmp_path):
    (tmp_path / "srv").mkdir()
    (tmp_path / "home" / ".ssh").mkdir(parents=True)
    with mock.patch("pathlib.Path.home", return_value=tmp_path / "home"):
        srv = K.SftpServer(str(tmp_path / "srv"))
        relay = _SilenceRelay(srv.port)
        s = SSHSession(ConnectionProfile(
            name="t", protocol="sftp", host="127.0.0.1", port=relay.port, username="u"
        ))
        s.connect(password="x", on_unknown_host=lambda _e: True)
        try:
            yield s, relay, tmp_path
        finally:
            relay.silent = False
            s.disconnect()
            relay.close()
            srv.close()


# -- exec channels (the post-upload checksum) ------------------------------------------


def test_sad_cancel_ends_a_slow_checksum_of_a_transfer(sftp, monkeypatch):
    from core.local_fs import LocalFS
    from core.transfer_worker import TransferJob, TransferWorker

    s, _relay, tmp = sftp
    monkeypatch.setattr(K._Auth, "check_channel_exec_request", _silent_exec)
    _EXEC_SEEN.clear()
    src = tmp / "up.bin"
    src.write_bytes(os.urandom(300_000))
    job = TransferJob(source_path=str(src), dest_path="/up.bin", filename="up.bin",
                      total_bytes=src.stat().st_size, source_backend=LocalFS(),
                      dest_backend=s, use_temp_file=True)
    th = threading.Thread(target=TransferWorker()._process_job, args=(job,), daemon=True)
    th.start()
    assert _EXEC_SEEN.wait(30), (job.status, job.error_message)
    time.sleep(0.5)
    job.cancel_event.set()
    pressed = time.monotonic()
    th.join(10)  # was: still running after 25 s
    assert not th.is_alive()
    assert time.monotonic() - pressed < 5
    assert job.status.name == "CANCELLED", job.error_message
    assert not (tmp / "srv" / "up.bin").exists()


def test_sad_a_checksum_on_a_silent_network_times_out(sftp, monkeypatch):
    s, relay, _tmp = sftp
    monkeypatch.setattr(ssh_client, "SFTP_IO_TIMEOUT", 1.0)
    monkeypatch.setattr(K._Auth, "check_channel_exec_request", _silent_exec)
    _EXEC_SEEN.clear()

    def go_silent():  # the network goes quiet while sha256sum runs
        if _EXEC_SEEN.wait(20):
            time.sleep(0.2)
            relay.silent = True

    threading.Thread(target=go_silent, daemon=True).start()

    def hash_on_silence():
        return s.checksum("/x")

    box = _in_thread(hash_on_silence, cap=20)  # was: for ever
    relay.silent = False
    exc = box.get("exc")
    assert isinstance(exc, TimeoutError) and exc.errno == errno.ETIMEDOUT, box
    assert "did not answer a keepalive" in str(exc)
    assert box["took"] < 10
    assert s._checksum_unavailable == {}  # not taken for "runs no commands"


def test_happy_a_long_command_on_a_live_connection_is_waited_for(sftp, monkeypatch):
    s, _relay, _tmp = sftp
    monkeypatch.setattr(ssh_client, "SFTP_IO_TIMEOUT", 0.5)
    monkeypatch.setattr(K._Auth, "check_channel_exec_request", _late_hash(2.0))
    box = _in_thread(lambda: s.checksum("/x"), cap=20)
    assert box.get("ok") == "sha256:" + "ab" * 32, box  # not a time-out after 0.5 s


def test_edge_cancel_ends_a_server_side_copy(sftp, monkeypatch):
    s, _relay, _tmp = sftp
    monkeypatch.setattr(K._Auth, "check_channel_exec_request", _silent_exec)
    cancel = threading.Event()
    hooks = transfer_hooks.TransferHooks(cancel)

    def copy():
        with transfer_hooks.active(hooks):
            threading.Timer(0.5, cancel.set).start()
            s.copy("/a", "/b")

    box = _in_thread(copy, cap=15)  # was: for ever
    assert isinstance(box.get("exc"), InterruptedError), box


def test_edge_an_exec_request_on_a_cancelled_transfer_is_not_sent(sftp, monkeypatch):
    s, _relay, _tmp = sftp
    monkeypatch.setattr(K._Auth, "check_channel_exec_request", _silent_exec)
    _EXEC_SEEN.clear()
    hooks = transfer_hooks.TransferHooks(threading.Event())
    hooks.cancel_event.set()
    with transfer_hooks.active(hooks), pytest.raises(InterruptedError):
        s.checksum("/x")
    assert not _EXEC_SEEN.is_set()


# -- SFTP requests: a slow server that is alive ----------------------------------------


def test_happy_a_slow_but_alive_server_is_waited_for(sftp, monkeypatch):
    s, _relay, tmp = sftp
    (tmp / "srv" / "tape.bin").write_bytes(b"archived" * 1000)
    orig_open = K._Sftp.open

    def slow_open(self, path, flags, attr):
        if path.endswith("tape.bin"):
            time.sleep(2.5)  # an HSM recall
        return orig_open(self, path, flags, attr)

    monkeypatch.setattr(K._Sftp, "open", slow_open)
    monkeypatch.setattr(ssh_client, "SFTP_IO_TIMEOUT", 1.0)

    def read():
        s.list_dir("/")  # this thread's channel, with the 1 s time-out
        with s.open_read("/tape.bin") as fh:
            return fh.read()

    box = _in_thread(read, cap=20)
    assert box.get("ok") == b"archived" * 1000, box  # was: TimeoutError after 1 s


def test_sad_the_slow_server_cap_still_ends_the_wait(sftp, monkeypatch):
    s, _relay, tmp = sftp
    (tmp / "srv" / "tape.bin").write_bytes(b"x")
    orig_open = K._Sftp.open

    def stuck_open(self, path, flags, attr):
        if path.endswith("tape.bin"):
            time.sleep(4)
        return orig_open(self, path, flags, attr)

    monkeypatch.setattr(K._Sftp, "open", stuck_open)
    monkeypatch.setattr(ssh_client, "SFTP_IO_TIMEOUT", 0.5)
    monkeypatch.setattr(ssh_client, "SFTP_SLOW_SERVER_CAP", 1.5)

    def read():
        s.list_dir("/")
        return s.open_read("/tape.bin")

    box = _in_thread(read, cap=20)
    exc = box.get("exc")
    assert isinstance(exc, TimeoutError) and exc.errno == errno.ETIMEDOUT, box
    assert "is connected but did not answer" in str(exc)
    from core.user_errors import describe

    assert "still connected" in describe(exc, "h")
    assert len(s.list_dir("/")) >= 1  # a new channel for the next call


def test_edge_the_time_out_is_per_profile():
    p = ConnectionProfile(name="t", protocol="sftp", host="h", username="u")
    assert SSHSession(p)._io_timeout() == ssh_client.SFTP_IO_TIMEOUT
    p.sftp_timeout = 300
    assert SSHSession(p)._io_timeout() == 300
    again = ConnectionProfile.from_dict(p.to_dict())
    assert again.sftp_timeout == 300
    assert "sftp_timeout" not in ConnectionProfile(name="t", protocol="sftp").to_dict()
    bad = dict(p.to_dict(), sftp_timeout=10**9)
    assert ConnectionProfile.from_dict(bad).sftp_timeout == 0  # out of range: the default


# -- Cancel's escalation and a shared connection ---------------------------------------


def test_edge_escalation_keeps_a_connection_other_channels_use(sftp):
    s, _relay, _tmp = sftp
    other = s.open_sftp_channel()  # a terminal, another pane
    mine = s.open_sftp_channel()
    sftp_io._close_transport(mine)
    assert s._transport.is_active()  # was: closed, the terminal with it
    assert other.listdir("/") is not None
    other.close()
    s._get_sftp_client().close()
    sftp_io._close_transport(mine)  # nothing else on it now: closed
    assert not s._transport.is_active()


def test_sad_escalation_closes_a_dead_connection_even_when_shared(sftp):
    s, relay, _tmp = sftp
    s.open_sftp_channel()
    mine = s.open_sftp_channel()
    mine.get_channel().settimeout(1.0)
    relay.silent = True
    box = _in_thread(lambda: sftp_io._close_transport(mine), cap=15)
    assert "exc" not in box, box
    assert not s._transport.is_active()


def test_edge_a_probe_ends_on_stop():
    class _Transport:
        completion_event = None

        def is_active(self):
            return True

        def _send_user_message(self, m):
            pass  # never answered

    t0 = time.monotonic()
    assert not ssh_client.transport_answers(_Transport(), 30, stop=lambda: True)
    assert time.monotonic() - t0 < 2
