"""drain_exec_channel reads whatever the channel holds, whatever select()
says.

Measured under parallel test load: paramiko's or-pipe behind
Channel.fileno() lost its wake-up - select() reported the channel not
readable 97 times in a row while recv_ready() / recv_stderr_ready() were
true. The loop read only when select() named the channel, so it never read
again, the remote blocked on a full window and exec() failed after its
timeout (tests/test_scp_exec_drains_large_output.py failed now and then).
select() now only waits; readiness is asked of the channel itself.
"""

from __future__ import annotations

import sys
from pathlib import Path

import paramiko
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import ssh_client as S  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402
from core.scp_client import SCPSession  # noqa: E402
from tests.ssh_exec_testkit import ExecServer  # noqa: E402

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


@pytest.fixture
def lost_wakeups(monkeypatch):
    """The channel never wakes the wait: every wait times out empty."""
    monkeypatch.setattr(S, "_wait_readable", lambda chan, timeout: False)


def test_happy_both_streams_drain_without_a_single_wakeup(session, lost_wakeups):
    r = session.exec(f"both:{2 * MIB}", timeout=20.0, stdout_cap=MIB, stderr_cap=MIB)
    assert r.truncated_stdout and r.truncated_stderr
    assert len(r.stdout) == MIB and len(r.stderr) == MIB


def test_sad_a_command_that_never_ends_still_times_out(session, lost_wakeups):
    with pytest.raises(OSError):
        session.exec("hang", timeout=1.0)


def test_edge_small_output_without_wakeups(session, lost_wakeups):
    r = session.exec("out:10", timeout=10.0)
    assert r.stdout == b"x" * 10
