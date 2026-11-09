"""An MCP server that never answers ``initialize`` no longer holds the Agent
tab for the whole call timeout (120 s): starting a server may take
CONNECT_TIMEOUT at most, Stop ends a starting server at once (its process
with it), and the transcript says which server it waits for."""

from __future__ import annotations

import os
import sys
import threading
import time

import pytest

from core import agent as A
from core import mcp_client as C
from core.mcp_script_pin import pinned
from core.llm_profiles import LLMProfile
from tests.test_agent_loop import _Fake
from tests.test_agent_tabs import APP, Env

#: A server that starts and never says a word - and ignores the end of its
#: input, as a hung one does. It writes its pid so the test sees it end.
SLEEPER = "import os, sys, time\nopen(sys.argv[1], 'w').write(str(os.getpid()))\ntime.sleep(600)\n"


@pytest.fixture
def sleeper(tmp_path):
    script = tmp_path / "sleeper.py"
    script.write_text(SLEEPER)
    pid_file = tmp_path / "pid"

    def config(**kw):
        kw.setdefault("timeout", 120)
        return pinned(C.McpServerConfig(name="sleepy",
                                        command=(sys.executable, str(script), str(pid_file)),
                                        **kw))

    config.pid_file = pid_file
    return config


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:  # a zombie is gone for this purpose
        with open(f"/proc/{pid}/stat") as f:
            return f.read().split(")")[-1].split()[0] != "Z"
    except OSError:
        return True


def _wait_gone(pid_file, seconds=8.0) -> bool:
    end = time.monotonic() + seconds
    while not pid_file.exists() and time.monotonic() < end:
        time.sleep(0.05)
    pid = int(pid_file.read_text())
    while time.monotonic() < end:
        if not _alive(pid):
            return True
        time.sleep(0.05)
    return False


# -- happy ---------------------------------------------------------------------


def test_happy_stop_ends_a_starting_server_at_once(sleeper):
    pool = C.McpClientPool(token_lookup=lambda name: "")
    cancel = threading.Event()
    started = []
    threading.Timer(0.5, cancel.set).start()
    begun = time.monotonic()
    tools, errors = pool.tools([sleeper()], cancel=cancel, on_start=started.append)
    assert time.monotonic() - begun < 3
    assert (tools, errors, started) == ([], [], ["sleepy"])
    assert _wait_gone(sleeper.pid_file), "the stopped server still runs"
    pool.close_all()


def test_happy_the_tab_names_the_server_and_stop_ends_the_wait(tmp_path, sleeper):
    from PyQt6.QtCore import Qt

    env = Env(tmp_path)
    env.settings.mcp_servers = [sleeper()]
    env.mcp_pool = C.McpClientPool(token_lookup=lambda name: "")
    try:
        env.fake({"content": "never asked"})
        tab = env.dock().current_tab()
        for i in range(tab.groups.count()):
            if tab.groups.item(i).text() == "mcp:sleepy":
                tab.groups.item(i).setCheckState(Qt.CheckState.Checked)
        tab.input.setPlainText("hi")
        tab.send()
        end = time.monotonic() + 10
        while "Starting MCP server sleepy" not in tab.transcript.toPlainText():
            assert time.monotonic() < end, tab.transcript.toPlainText()
            APP.processEvents()
            time.sleep(0.02)
        tab.stop()
        end = time.monotonic() + 3
        while tab.busy():
            assert time.monotonic() < end, "Stop did not end the wait for the server"
            APP.processEvents()
            time.sleep(0.02)
        APP.processEvents()
        text = tab.transcript.toPlainText()
        assert "Stopped" in text and "not available" not in text
        assert _wait_gone(sleeper.pid_file)
    finally:
        env.close()
        env.mcp_pool.close_all()


# -- sad -----------------------------------------------------------------------


def test_sad_a_silent_server_gives_up_after_the_start_timeout(sleeper, monkeypatch):
    monkeypatch.setattr(C, "CONNECT_TIMEOUT", 1.0, raising=False)
    begun = time.monotonic()
    with pytest.raises(C.McpClientError, match="no answer within 1 s"):
        C.McpClient(sleeper(timeout=20))
    assert time.monotonic() - begun < 8
    assert _wait_gone(sleeper.pid_file)


def test_sad_an_http_server_that_never_answers_is_cut_by_stop():
    import socket

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)  # accepts, never answers
    try:
        config = C.McpServerConfig(name="mute", transport="http", timeout=120,
                                   url=f"http://127.0.0.1:{listener.getsockname()[1]}/mcp")
        cancel = threading.Event()
        threading.Timer(0.5, cancel.set).start()
        begun = time.monotonic()
        with pytest.raises(C.McpCancelled):
            C.McpClient(config, cancel=cancel)
        assert time.monotonic() - begun < 3
    finally:
        listener.close()


# -- edge ----------------------------------------------------------------------


def test_edge_a_stopped_start_is_tried_again_by_the_next_task(tmp_path):
    server = _Fake([{"content": "fine"}])
    calls = []
    cancel = threading.Event()

    def external():
        calls.append(1)
        if len(calls) == 1:
            cancel.set()  # Stop while the server starts
            return [], []
        return [], []

    try:
        profile = LLMProfile(name="local", provider="lmstudio", endpoint=server.url,
                             model="tiny")
        agent = A.Agent(A.AgentConfig(profile=profile, root=str(tmp_path),
                                      external_tools=external), cancel=cancel)
        notices = []
        agent._on_event = notices.append
        assert agent.run("one").stopped == "cancelled"
        assert not [n for n in notices if n.get("type") == "notice"]
        cancel.clear()
        assert agent.run("two").answer == "fine"
        assert len(calls) == 2
    finally:
        server.close()
