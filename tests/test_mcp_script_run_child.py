"""MCP ``script_run`` runs the saved script in a bounded child process.

The handler used to exec() the script inside the MCP server: a looping
script held the server until the tool timeout and then kept running in a
thread nothing could stop, and under the stdio transport ``input()`` read
the next JSON-RPC request off the server's own stdin (the request was
answered by nobody). Now every run is a child (core.script_runner) with
stdin on /dev/null, its own process group, a wall-clock timeout, bounded
output and a structured reply a machine can act on.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest

from core import mcp_server as M
from core import script_runner as SR
from core import scripting
from core.local_fs import LocalFS

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def tools(tmp_path) -> dict:
    built = M._build_tools(LocalFS(), allow_write=False, root=str(tmp_path), allow_scripts=True)
    return {t.name: t for t in built}


@pytest.fixture
def script():
    names: list[str] = []

    def _save(source: str) -> str:
        name = f"t_{uuid.uuid4().hex[:10]}"
        scripting.save_script(name, source)
        names.append(name)
        return name

    yield _save
    for name in names:
        scripting.delete_script(name)


def _run(tools: dict, name: str, ctx=None, **args):
    return tools["script_run"].handler({"name": name, **args}, ctx or M._ToolContext())


def _gone(pid: int, within: float = 5.0) -> bool:
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


# -- happy --------------------------------------------------------------------------


def test_happy_the_script_runs_in_a_child_and_the_reply_is_structured(tools, script) -> None:
    name = script(
        "import os, sys\nresult = 42\nprint(os.getpid())\nprint('warn', file=sys.stderr)\n"
    )
    reply = _run(tools, name)
    assert int(reply["stdout"].strip()) != os.getpid()
    assert reply["exit"] == 0 and reply["timed_out"] is False
    assert isinstance(reply["duration_ms"], int) and reply["duration_ms"] >= 0
    assert "warn" in reply["stderr"]
    assert "result" in reply["namespace_keys"]
    assert "error_type" not in reply and "traceback" not in reply


def test_happy_args_reach_the_script_as_sys_argv(tools, script) -> None:
    name = script("import sys, json\nprint(json.dumps(sys.argv[1:]))\n")
    reply = _run(tools, name, args=["a", "b c", "--flag=1", ""])
    assert json.loads(reply["stdout"]) == ["a", "b c", "--flag=1", ""]


def test_happy_the_child_knows_it_is_unattended(tools, script) -> None:
    name = script(
        "import os\nprint(axross.is_interactive(), os.environ.get('AXROSS_NONINTERACTIVE'),"
        " 'AXROSS_SCRIPT_RESULT_FD' in os.environ)\n"
    )
    assert _run(tools, name)["stdout"].split() == ["False", "1", "False"]


def test_happy_a_large_exit_status_is_reported_exactly(tools, script) -> None:
    # An OS exit status is 0..255; the child reports the SystemExit code itself.
    assert _run(tools, script("raise SystemExit(300)\n"))["exit"] == 300


# -- sad ----------------------------------------------------------------------------


def test_sad_an_uncaught_exception_is_reported_with_type_message_and_traceback(
    tools, script
) -> None:
    name = script("def f():\n    return 1 / 0\n\nf()\n")
    reply = _run(tools, name)
    assert reply["exit"] == 1 and reply["timed_out"] is False
    assert reply["error_type"] == "ZeroDivisionError"
    assert reply["error"] == "division by zero"
    path = os.path.join(scripting.script_dir(), f"{name}.py")
    assert f'File "{path}", line 2' in reply["traceback"]
    assert "script_runner" not in reply["traceback"]


def test_sad_a_looping_script_is_stopped_at_its_timeout(tools, script, tmp_path) -> None:
    pidfile = tmp_path / "grandchild.pid"
    name = script(
        "import subprocess, time\n"
        f"p = subprocess.Popen(['sleep', '300'])\nopen({str(pidfile)!r}, 'w').write(str(p.pid))\n"
        "while True:\n    time.sleep(0.05)\n"
    )
    started = time.monotonic()
    reply = _run(tools, name, timeout_s=1.5)
    elapsed = time.monotonic() - started
    assert reply["timed_out"] is True
    assert reply["exit"] == -signal.SIGTERM
    assert elapsed < 1.5 + SR.STOP_GRACE_SECONDS + SR.OUTPUT_DRAIN_SECONDS + 2
    # The process group went down with it: no grandchild survives the run.
    assert _gone(int(pidfile.read_text()))


def test_sad_a_script_ignoring_sigterm_is_killed_after_the_grace(tools, script) -> None:
    name = script(
        "import signal, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "while True:\n    time.sleep(0.05)\n"
    )
    reply = _run(tools, name, timeout_s=0.5)
    assert reply["timed_out"] is True and reply["exit"] == -signal.SIGKILL


def test_sad_input_gets_end_of_file_instead_of_blocking(tools, script) -> None:
    reply = _run(tools, script("x = input()\n"), timeout_s=30)
    assert reply["timed_out"] is False
    assert reply["error_type"] == "EOFError"


def test_sad_confirm_without_assume_yes_is_refused_in_the_child(tools, script) -> None:
    reply = _run(tools, script("axross.confirm('wipe?', default_yes=True)\n"))
    assert reply["exit"] == 1 and reply["error_type"] == "NonInteractiveError"


def test_sad_a_flooding_script_is_stopped_at_the_output_cap(tools, script, monkeypatch) -> None:
    monkeypatch.setattr(M, "MAX_SCRIPT_OUTPUT_CHARS", 10_000)
    name = script("while True:\n    print('x' * 1000)\n")
    started = time.monotonic()
    with pytest.raises(RuntimeError, match="output exceeded 10000 characters"):
        _run(tools, name, timeout_s=60)
    assert time.monotonic() - started < 15


def test_sad_a_cancelled_call_kills_the_child(tools, script, tmp_path) -> None:
    pidfile = tmp_path / "child.pid"
    name = script(
        f"import os, time\nopen({str(pidfile)!r}, 'w').write(str(os.getpid()))\n"
        "while True:\n    time.sleep(0.05)\n"
    )
    ctx = M._ToolContext(cancel_event=threading.Event())
    threading.Timer(1.0, ctx.cancel_event.set).start()
    with pytest.raises(M.CancelledError):
        _run(tools, name, ctx=ctx, timeout_s=60)
    assert _gone(int(pidfile.read_text()))


@pytest.mark.parametrize(
    "bad",
    [
        {"args": "not-a-list"},
        {"args": [1]},
        {"args": ["x"] * (M.MAX_SCRIPT_ARGS + 1)},
        {"args": ["x" * (M.MAX_SCRIPT_ARG_CHARS + 1)]},
        {"args": ["nul\x00byte"]},
        {"timeout_s": 0},
        {"timeout_s": -1},
        {"timeout_s": M.MAX_SCRIPT_TIMEOUT_S + 1},
        {"timeout_s": True},
        {"timeout_s": "10"},
        {"timeout_s": float("nan")},
    ],
)
def test_sad_bad_arguments_are_refused_before_anything_runs(tools, script, tmp_path, bad) -> None:
    marker = tmp_path / "ran"
    name = script(f"open({str(marker)!r}, 'w').write('x')\n")
    with pytest.raises(ValueError):
        _run(tools, name, **bad)
    assert not marker.exists()


# -- edge ---------------------------------------------------------------------------


def test_edge_os_exit_without_a_report_uses_the_process_status(tools, script) -> None:
    reply = _run(tools, script("import os\nprint('bye', flush=True)\nos._exit(7)\n"))
    assert reply["exit"] == 7 and reply["stdout"] == "bye\n"
    assert reply["namespace_keys"] == []


def test_edge_namespace_keys_and_traceback_are_bounded(tools, script) -> None:
    many = SR.MAX_NAMESPACE_KEYS + 50
    name = script(
        f"for i in range({many}):\n    globals()[f'v{{i}}'] = i\n"
        "def deep(n):\n    return deep(n + 1)\ndeep(0)\n"
    )
    reply = _run(tools, name)
    assert reply["error_type"] == "RecursionError"
    assert len(reply["namespace_keys"]) == SR.MAX_NAMESPACE_KEYS
    assert len(reply["traceback"]) <= SR.MAX_TRACEBACK_CHARS + len(SR.TRACEBACK_CUT_MARKER)


def test_edge_the_tool_deadline_outlasts_the_longest_script_run() -> None:
    assert 0 < M.DEFAULT_SCRIPT_TIMEOUT_S <= M.MAX_SCRIPT_TIMEOUT_S
    built = {t.name: t for t in M._build_tools(LocalFS(), allow_write=False, allow_scripts=True)}
    tool = built["script_run"]
    assert tool.timeout_class == "script"
    assert tool.timeout_seconds > (
        M.MAX_SCRIPT_TIMEOUT_S + SR.STOP_GRACE_SECONDS + SR.OUTPUT_DRAIN_SECONDS
    )
    props = tool.schema["properties"]
    assert props["timeout_s"]["maximum"] == M.MAX_SCRIPT_TIMEOUT_S
    assert props["args"]["maxItems"] == M.MAX_SCRIPT_ARGS


def test_edge_input_in_a_script_never_eats_the_next_request(script) -> None:
    """The stdio reproducer: script_run of a script calling input(), then a
    tools/list request on the same line stream. In-process, input() read
    the tools/list line and id 99 was never answered."""
    name = script("x = input()\nprint('read', len(x))\n")
    reqs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": M.PROTOCOL_VERSION, "capabilities": {},
            "clientInfo": {"name": "t", "version": "0"}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "script_run", "arguments": {"name": name}}},
        {"jsonrpc": "2.0", "id": 99, "method": "tools/list"},
    ]
    env = {k: v for k, v in os.environ.items() if not k.startswith("AXROSS_MCP")}
    env.update(QT_QPA_PLATFORM="offscreen", PYTHON_KEYRING_BACKEND="keyring.backends.null.Keyring")
    proc = subprocess.run(
        [sys.executable, str(ROOT / "main.py"), "--mcp-server", "--mcp-allow-scripts"],
        input="".join(json.dumps(r) + "\n" for r in reqs),
        capture_output=True, text=True, timeout=120, env=env, cwd=ROOT,
    )
    replies = {m["id"]: m for m in map(json.loads, proc.stdout.splitlines()) if "id" in m}
    assert set(replies) == {1, 2, 99}, proc.stderr[-2000:]
    run = json.loads(replies[2]["result"]["content"][0]["text"])
    assert run["error_type"] == "EOFError" and "read" not in run["stdout"]
    assert replies[99]["result"]["tools"]
