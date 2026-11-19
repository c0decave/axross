"""Telnet with one shell and several users of it.

* ``connected`` (ConnectionManager._is_connected, the pane's health
  check) ran "echo ok" through the shell and so waited for the shell's
  lock: while a transfer ran - up to an hour for a tree operation - every
  "is it alive?" question hung behind it. A shell that is busy is alive;
  the question is answered at once.
* Two threads that found the connection dropped both logged in again: two
  new connections, and the first one's shell leaked. One reconnect now
  serves both.
* A connection the server closed was noticed only at the time-out of the
  command waiting for its answer (30 s; an hour for a tree operation):
  the transport saw the end of the stream and the read went on waiting.
* checksum() ran sha256sum under the 30 s command time-out, and after a
  time-out logged in again and ran it once more: a large file on a slow
  box failed twice, and two hash runs went on on the server. It now gets
  the long time-out of the tree operations and is never sent twice.

Against a real shell on a pty (tests/telnet_pty_server.py).
"""

from __future__ import annotations

import sys
import threading
import time

import pytest

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="needs a pty")

from tests.telnet_pty_server import PtyTelnetServer  # noqa: E402

import core.telnet_client as tc  # noqa: E402


@pytest.fixture
def server_session(tmp_path):
    with PtyTelnetServer(cwd=str(tmp_path)) as srv:
        s = tc.TelnetSession("127.0.0.1", srv.port, "u", "pw")
        try:
            yield srv, s
        finally:
            s.close()


def test_connected_answers_at_once_while_a_command_runs(server_session):
    _srv, s = server_session
    worker = threading.Thread(target=s.exec, args=("sleep 3",), kwargs={"timeout": 20})
    worker.start()
    time.sleep(0.5)
    started = time.monotonic()
    assert s.connected is True
    assert time.monotonic() - started < 1.0
    worker.join(20)


def test_two_threads_after_a_drop_log_in_once(server_session, tmp_path):
    srv, s = server_session
    (tmp_path / "f").write_text("x")
    assert srv.connections == 1
    srv.drop_all()
    time.sleep(0.3)
    results: list[object] = []

    def work():
        try:
            results.append([i.name for i in s.list_dir(str(tmp_path))])
        except Exception as exc:  # noqa: BLE001
            results.append(exc)

    threads = [threading.Thread(target=work) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert results == [["f"]] * 4, results
    assert srv.connections == 2


def test_checksum_has_the_long_time_out_and_is_sent_once(server_session, tmp_path):
    _srv, s = server_session
    (tmp_path / "f").write_text("data")
    seen: list[tuple[str, float]] = []
    shell = s._shell
    real = shell.execute

    def spy(cmd, timeout=tc.CMD_TIMEOUT):
        seen.append((cmd, timeout))
        return real(cmd, timeout=timeout)

    shell.execute = spy
    digest = s.checksum(str(tmp_path / "f"))
    assert digest.startswith("sha256:")
    sums = [t for cmd, t in seen if "sha256sum" in cmd]
    assert sums == [tc.TREE_OP_TIMEOUT], seen


def test_a_dropped_connection_is_noticed_at_once(server_session, tmp_path):
    srv, s = server_session
    srv.close()  # no shell, and no new login either
    started = time.monotonic()
    with pytest.raises(OSError):
        s.list_dir(str(tmp_path))
    assert time.monotonic() - started < 5.0
    assert s.connected is False


def test_a_command_whose_answer_keeps_arriving_does_not_time_out(server_session):
    """The command time-out counts silence: a long listing over a slow line
    went past the 30 s while still arriving (and ran again after a
    reconnect). exec() keeps its caller's deadline for the whole run."""
    _srv, s = server_session
    out = s._exec("for i in 1 2 3 4 5 6 7; do echo line$i; sleep 0.5; done", timeout=2.0)
    assert out.split() == [f"line{i}" for i in range(1, 8)]
    with pytest.raises(TimeoutError):
        s.exec("for i in 1 2 3 4 5 6 7; do echo x; sleep 0.5; done", timeout=1.5)
