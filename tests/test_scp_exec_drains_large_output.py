"""SCPSession.exec returns clipped output when a command prints more than
the cap, like SSHSession.exec.

It read ``stdout_cap + 1`` bytes of stdout and then waited for the end
of stderr. The remote command could not finish while its unread stdout
filled the channel window, so exec() failed after its timeout with an
empty "SCP exec failed:" - or blocked for ever with timeout=None. A
chatty stderr deadlocked the same way. Both streams are now drained
together by the loop SSHSession.exec uses.
"""

from __future__ import annotations

import threading
import time

import paramiko
import pytest

from core.profiles import ConnectionProfile
from core.scp_client import SCPSession
from tests.ssh_exec_testkit import ExecServer

MIB = 1024 * 1024


@pytest.fixture
def session():
    server = ExecServer()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        "127.0.0.1",
        port=server.port,
        username="u",
        password="pw",
        allow_agent=False,
        look_for_keys=False,
        timeout=10,
    )
    sess = SCPSession(ConnectionProfile(host="127.0.0.1", port=server.port, username="u"))
    sess._client = client
    try:
        yield sess
    finally:
        client.close()
        server.close()


def _bounded(fn, limit: float = 20.0) -> dict:
    box: dict = {}

    def target():
        t0 = time.monotonic()
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - handed to the test
            box["error"] = exc
        box["elapsed"] = time.monotonic() - t0

    th = threading.Thread(target=target, daemon=True)
    th.start()
    th.join(limit)
    assert not th.is_alive(), f"exec still blocked after {limit} s"
    return box


# -- happy -------------------------------------------------------------------


def test_happy_stdout_above_the_cap_is_clipped_and_flagged(session):
    box = _bounded(lambda: session.exec(f"out:{3 * MIB}", timeout=10.0, stdout_cap=MIB))
    r = box.get("value")
    assert r is not None, box
    assert r.returncode == 0
    assert r.stdout == b"x" * MIB and r.truncated_stdout is True
    assert r.truncated_stderr is False


def test_happy_a_small_answer_is_returned_whole(session):
    r = session.exec("echo:hello", timeout=10.0)
    assert r.returncode == 0 and r.stdout == b"hello" and not r.truncated_stdout


# -- sad ---------------------------------------------------------------------


def test_sad_a_chatty_stderr_does_not_deadlock(session):
    box = _bounded(lambda: session.exec(f"err:{3 * MIB}", timeout=10.0, stderr_cap=64 * 1024))
    r = box.get("value")
    assert r is not None, box
    assert len(r.stderr) == 64 * 1024 and r.truncated_stderr is True
    assert r.stdout == b""


def test_sad_both_streams_above_their_caps(session):
    box = _bounded(
        lambda: session.exec(f"both:{2 * MIB}", timeout=10.0, stdout_cap=MIB, stderr_cap=MIB)
    )
    r = box.get("value")
    assert r is not None, box
    assert r.truncated_stdout and r.truncated_stderr


def test_sad_a_command_that_never_ends_raises_after_the_timeout(session):
    box = _bounded(lambda: session.exec("hang", timeout=1.0), 10.0)
    assert isinstance(box.get("error"), OSError), box
    assert box["elapsed"] < 5.0


# -- edge --------------------------------------------------------------------


def test_edge_no_timeout_still_returns_for_large_output(session):
    box = _bounded(lambda: session.exec(f"out:{3 * MIB}", timeout=None, stdout_cap=MIB))
    assert box.get("value") is not None, box
    assert box["value"].truncated_stdout


def test_edge_output_exactly_at_the_cap_is_not_truncated(session):
    r = session.exec(f"out:{MIB}", timeout=10.0, stdout_cap=MIB)
    assert len(r.stdout) == MIB and r.truncated_stdout is False
