"""A sandboxed child outlives the thread that started it.

Incident: every sandboxed (bubblewrap) agent task ended with the worker
killed (-9, no stderr), so each task started a new worker. Traced with
strace: bwrap's --die-with-parent is prctl(PR_SET_PDEATHSIG, SIGKILL) on
bwrap itself, and the kernel's "parent" for that is the THREAD that forked
it - the tab's run thread ("axross-agent"), which ends after each task.
core.process_launcher starts such children from one thread that lives as
long as axross, so the signal means what it should: axross is gone.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import process_launcher as PL  # noqa: E402

#: A child that asks for SIGKILL when its parent (thread) dies, then waits.
_PDEATH_CHILD = (
    "import ctypes, signal, sys, time\n"
    "ctypes.CDLL(None).prctl(1, signal.SIGKILL, 0, 0, 0)\n"  # PR_SET_PDEATHSIG
    "sys.stdout.write('armed\\n'); sys.stdout.flush()\n"
    "time.sleep(30)\n"
)

linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="PR_SET_PDEATHSIG")


def _start_in_short_thread(start) -> subprocess.Popen:
    """Call *start* in a thread that waits until the child armed its
    parent-death signal, then ends - like the tab's run thread."""
    box: dict = {}

    def run():
        proc = start()
        proc.stdout.readline()  # "armed": prctl took hold while this thread lives
        box["proc"] = proc

    thread = threading.Thread(target=run, name="short-lived")
    thread.start()
    thread.join(20)
    return box["proc"]


@linux_only
def test_happy_a_child_started_by_the_launcher_survives_the_callers_thread():
    proc = _start_in_short_thread(lambda: PL.popen(
        [sys.executable, "-c", _PDEATH_CHILD], stdout=subprocess.PIPE))
    try:
        time.sleep(0.5)
        assert proc.poll() is None
    finally:
        proc.kill()
        proc.wait(10)


@linux_only
def test_happy_the_control_a_plain_popen_child_dies_with_the_callers_thread():
    """The mechanism the launcher exists for, shown on plain Popen."""
    proc = _start_in_short_thread(lambda: subprocess.Popen(
        [sys.executable, "-c", _PDEATH_CHILD], stdout=subprocess.PIPE))
    assert proc.wait(10) == -9


def test_sad_a_program_that_cannot_start_raises_in_the_caller():
    with pytest.raises(FileNotFoundError):
        PL.popen(["/nonexistent/axross-no-such-program"])


def test_sad_a_bad_argument_raises_in_the_caller_and_the_launcher_goes_on():
    with pytest.raises(TypeError):
        PL.popen([sys.executable, "-c", "pass"], no_such_popen_argument=1)
    proc = PL.popen([sys.executable, "-c", "pass"])
    assert proc.wait(10) == 0


def test_edge_many_threads_at_once_each_get_their_own_child():
    results: list[int] = []
    lock = threading.Lock()

    def run(i):
        proc = PL.popen([sys.executable, "-c", f"import sys; sys.exit({i})"])
        with lock:
            results.append(proc.wait(20))

    threads = [threading.Thread(target=run, args=(i,)) for i in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert sorted(results) == list(range(12))


def test_edge_calling_it_from_the_launcher_thread_itself_does_not_deadlock():
    box: dict = {}

    def nested():
        box["proc"] = PL.popen([sys.executable, "-c", "pass"])
        return box["proc"]

    PL._LAUNCHER.call(nested)
    assert box["proc"].wait(10) == 0


# -- the agent worker in a real bubblewrap sandbox ---------------------------------------------

def _bwrap_works() -> bool:
    if not shutil.which("bwrap"):
        return False
    probe = subprocess.run(["bwrap", "--unshare-all", "--ro-bind", "/", "/", "true"],
                           capture_output=True, timeout=20)
    return probe.returncode == 0


@pytest.mark.skipif(not _bwrap_works(), reason="bubblewrap cannot create a sandbox here")
def test_e2e_the_sandboxed_worker_serves_two_tasks_from_short_lived_threads(tmp_path):
    """As the Agent dock does it: each task in its own thread. One worker
    for both, alive after each."""
    from core import agent as A
    from core import agent_sandbox as SB
    from core.llm_profiles import LLMProfile
    from tests.test_agent_loop import _Fake

    fake = _Fake([{"content": "One."}, {"content": "Two."}])
    profile = LLMProfile(name="local", provider="lmstudio", endpoint=fake.url, model="tiny")
    agent = SB.SandboxedAgent(A.AgentConfig(profile=profile, root=str(tmp_path)),
                              SB.SandboxProfile(name="B", engine="bubblewrap", level="normal"))
    pids, answers = [], []
    try:
        for task in ("first", "second"):
            thread = threading.Thread(target=lambda t=task: answers.append(agent.run(t).answer),
                                      name="axross-agent")
            thread.start()
            thread.join(60)
            time.sleep(1.0)
            pids.append(agent._proc.pid)
            assert agent._proc.poll() is None, f"the worker ended after {task!r}"
    finally:
        agent.close()
        fake.close()
    assert answers == ["One.", "Two."]
    assert pids[0] == pids[1]


@pytest.mark.skipif(not _bwrap_works(), reason="bubblewrap cannot create a sandbox here")
def test_e2e_a_sandboxed_mcp_server_survives_the_thread_that_started_it(tmp_path):
    from core import mcp_client as MC

    server = tmp_path / "srv.py"
    server.write_text(
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    msg = json.loads(line)\n"
        "    if 'id' not in msg: continue\n"
        "    if msg['method'] == 'initialize':\n"
        "        res = {'protocolVersion': '2024-11-05', 'capabilities': {}, "
        "'serverInfo': {'name': 's', 'version': '1'}}\n"
        "    else:\n"
        "        res = {'tools': []}\n"
        "    print(json.dumps({'jsonrpc': '2.0', 'id': msg['id'], 'result': res}), flush=True)\n"
    )
    from core import agent_sandbox as SB

    profile = SB.SandboxProfile(name="M", engine="bubblewrap", level="normal")
    wrap = lambda argv: SB.sandbox_command(profile, str(tmp_path), writable=False, inner=argv)  # noqa: E731
    config = MC.McpServerConfig(name="s", command=[sys.executable, str(server)])
    box: dict = {}

    def start():
        client = MC.McpClient(config, wrap=wrap)
        box["client"] = client
        box["tools"] = client.tools()

    thread = threading.Thread(target=start)
    thread.start()
    thread.join(60)
    client = box["client"]
    try:
        time.sleep(1.0)
        assert client._transport._proc.poll() is None
        assert client.tools() == []  # still answering
    finally:
        client.close()
