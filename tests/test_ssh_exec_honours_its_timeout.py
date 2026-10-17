"""SSHSession.exec(timeout=...) ends a command that does not finish.

The read loop only left on an exit status; the channel timeout applies
to blocking reads, and the loop only read when data was ready. A command
that never finished therefore blocked exec() forever, whatever timeout
the caller (the MCP ``remote_exec`` tool among them) passed.
"""

from __future__ import annotations

import threading
import time

import pytest

from core.profiles import ConnectionProfile
from core.ssh_client import SSHSession
from tests.ssh_exec_testkit import ExecServer


@pytest.fixture
def session():
    server = ExecServer()
    prof = ConnectionProfile(
        name="t", protocol="sftp", host="127.0.0.1", port=server.port, username="u"
    )
    sess = SSHSession(prof)
    sess._transport = server.client_transport()
    try:
        yield sess
    finally:
        sess._transport.close()
        server.close()


def _run_bounded(fn, limit: float):
    """Run *fn* in a thread; fail the test instead of hanging the suite."""
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


def test_happy_a_quick_command_returns_its_output(session):
    r = session.exec("echo:hello", timeout=5.0)
    assert r.returncode == 0 and r.stdout == b"hello"


def test_happy_a_command_that_ends_before_the_timeout_returns_its_status(session):
    r = session.exec("slow:0.5", timeout=5.0)
    assert r.returncode == 3 and r.stdout == b"tick"


# -- sad ---------------------------------------------------------------------


def test_sad_a_command_that_never_finishes_raises_after_the_timeout(session):
    box = _run_bounded(lambda: session.exec("hang", timeout=1.0), 8.0)
    assert isinstance(box.get("error"), TimeoutError), box
    assert isinstance(box["error"], OSError)
    assert "1" in str(box["error"])
    assert 0.9 <= box["elapsed"] < 4.0


def test_sad_output_before_the_end_does_not_extend_the_timeout(session):
    box = _run_bounded(lambda: session.exec("slow:6", timeout=1.0), 8.0)
    assert isinstance(box.get("error"), TimeoutError), box
    assert box["elapsed"] < 4.0


# -- edge --------------------------------------------------------------------


def test_edge_the_session_still_works_after_a_timeout(session):
    _run_bounded(lambda: session.exec("hang", timeout=0.5), 8.0)
    r = session.exec("echo:again", timeout=5.0)
    assert r.stdout == b"again"


def test_edge_timeout_none_waits_for_the_command(session):
    r = session.exec("slow:0.3", timeout=None)
    assert r.returncode == 3
