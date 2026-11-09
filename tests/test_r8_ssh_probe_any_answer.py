"""The SSH keepalive probe: any packet is proof of life, paramiko's events stay its own.

Measured before (review round 8, repro ssh/probe_no_global_reply.py):

* a server that is alive but drops global requests without the answer
  RFC 4254 4 asks for (some embedded / appliance servers) made every
  command that stays silent for twice the idle time fail with "the
  network connection is probably lost" - a checksum that takes 3 s with
  a 1 s time-out failed after 2 s;
* the probe set ``transport.completion_event`` to its own Event, and the
  answer set ``global_response``: whatever else waited on paramiko's
  global request lost its event.

Now (core.ssh_client._TransportWatch) every packet the transport reads
wakes the probe, the probe's answers are taken from paramiko's per
transport handler table before paramiko's own handlers, and a server
that leaves the keepalive request unanswered gets a channel open of an
unknown type half-way (which every server answers, RFC 4254 5.1).
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from unittest import mock

import paramiko
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.ssh_client as ssh_client  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402
from core.ssh_client import SSHSession  # noqa: E402
from tests import sftp_testkit as K  # noqa: E402

DIGEST = "ab" * 32


def _late_hash(delay: float):
    """A sha256sum that answers after *delay* silent seconds."""

    def handler(self, channel, command):
        def answer():
            time.sleep(delay)
            try:
                channel.sendall(f"{DIGEST}  /x\n".encode())
                channel.send_exit_status(0)
                channel.close()
            except Exception:  # noqa: BLE001 - the client gave up
                pass

        threading.Thread(target=answer, daemon=True).start()
        return True

    return handler


@pytest.fixture
def drop_global_requests(monkeypatch):
    """The server side drops every global request without an answer."""
    original = paramiko.Transport._parse_global_request

    def parse(self, m):
        if self.server_mode:
            return None
        return original(self, m)

    monkeypatch.setattr(paramiko.Transport, "_parse_global_request", parse)


@pytest.fixture
def session(tmp_path):
    (tmp_path / "srv").mkdir()
    (tmp_path / "srv" / "x").write_bytes(b"x" * 1000)
    (tmp_path / "home" / ".ssh").mkdir(parents=True)
    with mock.patch("pathlib.Path.home", return_value=tmp_path / "home"):
        srv = K.SftpServer(str(tmp_path / "srv"))
        s = SSHSession(ConnectionProfile(
            name="t", protocol="sftp", host="127.0.0.1", port=srv.port, username="u"))
        s.connect(password="x", on_unknown_host=lambda _e: True)
        try:
            yield s
        finally:
            s.disconnect()
            srv.close()


# -- happy -------------------------------------------------------------------


def test_happy_a_server_that_drops_keepalives_is_still_alive(
        drop_global_requests, session, monkeypatch):
    monkeypatch.setattr(ssh_client, "SFTP_IO_TIMEOUT", 1.0)
    monkeypatch.setattr(K._Auth, "check_channel_exec_request", _late_hash(3.0))
    assert session.checksum("/x") == "sha256:" + DIGEST
    assert session._transport.is_active()


def test_happy_a_server_answering_the_keepalive_needs_no_channel_open(session, monkeypatch):
    opened = []
    original = ssh_client._TransportWatch.send_channel_open
    monkeypatch.setattr(ssh_client._TransportWatch, "send_channel_open",
                        lambda self, t: (opened.append(t), original(self, t)))
    assert ssh_client.transport_answers(session._transport, 4.0)
    time.sleep(2.2)  # past the half-way mark of the probe
    assert opened == []


# -- sad ---------------------------------------------------------------------


def test_sad_the_probe_leaves_paramikos_completion_event_alone(session):
    sentinel = threading.Event()
    session._transport.completion_event = sentinel
    assert ssh_client.transport_answers(session._transport, 5.0)
    assert session._transport.completion_event is sentinel
    assert not sentinel.is_set()


def test_sad_the_probe_leaves_paramikos_global_response_alone(session):
    marker = object()
    session._transport.global_response = marker
    assert ssh_client.transport_answers(session._transport, 5.0)
    time.sleep(0.2)  # the answer is handled on the transport's thread
    assert session._transport.global_response is marker


def test_sad_a_refused_probe_channel_leaves_no_saved_exception(
        drop_global_requests, session):
    session._transport.saved_exception = None
    assert ssh_client.transport_answers(session._transport, 2.0)
    time.sleep(0.2)
    assert session._transport.saved_exception is None
    assert session._transport.is_active()


# -- edge --------------------------------------------------------------------


def test_edge_a_server_that_opens_the_probe_channel_keeps_the_connection(
        drop_global_requests, session, monkeypatch):
    """A server that accepts the unknown channel type: it is closed again,
    and what the server sends for it later does not end the transport."""
    monkeypatch.setattr(K._Auth, "check_channel_request",
                        lambda self, kind, chanid: paramiko.OPEN_SUCCEEDED)
    assert ssh_client.transport_answers(session._transport, 2.0)
    time.sleep(0.5)
    assert session._transport.is_active()
    assert [i.name for i in session.list_dir("/")] == ["x"]


def test_edge_any_packet_wakes_a_probe(drop_global_requests, session, monkeypatch):
    """Traffic on another channel proves the connection as well as an
    answer: no channel open is needed when output arrives first."""
    opened = []
    monkeypatch.setattr(ssh_client._TransportWatch, "send_channel_open",
                        lambda self, t: opened.append(t))
    box = {}
    probe = threading.Thread(
        target=lambda: box.setdefault("ok", ssh_client.transport_answers(session._transport, 4.0)))
    probe.start()
    time.sleep(0.3)
    session.list_dir("/")  # an SFTP answer arrives while the probe waits
    probe.join(10)
    assert box.get("ok") is True
    assert opened == []
