"""Round 1 of the adversarial review of the headless MCP server: the
JSON-RPC layer, axross's background tasks, read_file paging and names that
are not UTF-8.

- M5: a notification (no id) never runs a tool and is never answered; an
  id of null, a wrong ``jsonrpc``, a request before ``initialize`` are
  refused; a client's response object is ignored.
- M9: the background tasks are ``axross/tasks/*`` (MCP 2025-11-25 has a
  tasks/* of its own); the bare names stay for older sessions.
- M1 / H3: a cancelled task stops (checksum hashes chunk by chunk now), a
  task that does not stop is abandoned after a grace and frees its slot;
  the running cap is per session and per server; finished results are
  capped in bytes and age out in every scope.
- M4: read_file text paging always moves on, by at least one character.
- H1: a file name that is not UTF-8 goes out as U+FFFD plus ``*_b64`` (raw
  bytes), and the ``*_b64`` twin of every path argument names the file.
- LOW: an unknown tool and an unknown task are -32602, an unsafe archive is
  a tool error, every audit line is forwarded once, a closed stdout ends
  the stdio server quietly.
"""

from __future__ import annotations

import base64
import io
import json
import logging
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from core import mcp_server as M
from core.local_fs import LocalFS

ROOT = Path(__file__).resolve().parents[1]


def _tools(root, **kw):
    return M._build_tools(LocalFS(), allow_write=True, root=str(root), **kw)


def _session(tools, version="2025-11-25"):
    state = M.ProtocolState()
    M._handle_request({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                       "params": {"protocolVersion": version}}, tools, protocol=state)
    return state


def _req(tools, msg, state=None, **kw):
    return M._handle_request(msg, tools, protocol=state, **kw)


# --- M5: JSON-RPC and the MCP lifecycle --------------------------------------------


def test_sad_a_tools_call_without_id_runs_nothing_and_gets_no_answer(tmp_path):
    tools = _tools(tmp_path)
    state = _session(tools)
    target = tmp_path / "x.txt"
    note = {"jsonrpc": "2.0", "method": "tools/call",
            "params": {"name": "write_file", "arguments": {"path": str(target), "content": "x"}}}
    assert _req(tools, note, state) is None
    assert not target.exists()
    for method in ("ping", "initialize", "tools/list"):
        assert _req(tools, {"jsonrpc": "2.0", "method": method}, state) is None


def test_sad_an_id_of_null_is_refused_and_runs_nothing(tmp_path):
    tools = _tools(tmp_path)
    state = _session(tools)
    target = tmp_path / "y.txt"
    resp = _req(tools, {"jsonrpc": "2.0", "id": None, "method": "tools/call",
                        "params": {"name": "write_file",
                                   "arguments": {"path": str(target), "content": "x"}}}, state)
    assert resp["error"]["code"] == M.ERR_INVALID_REQUEST and resp["id"] is None
    assert not target.exists()


def test_sad_jsonrpc_must_be_2_0(tmp_path):
    tools = _tools(tmp_path)
    state = _session(tools)
    assert _req(tools, {"id": 3, "method": "ping"}, state)["error"]["code"] == -32600
    assert _req(tools, {"jsonrpc": "1.0", "id": 3, "method": "ping"},
                state)["error"]["code"] == -32600


def test_sad_requests_before_initialize_are_refused_but_ping(tmp_path):
    tools = _tools(tmp_path)
    state = M.ProtocolState()
    resp = _req(tools, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, state)
    assert resp["error"]["code"] == M.ERR_INVALID_REQUEST and "initialize" in \
        resp["error"]["message"]
    assert _req(tools, {"jsonrpc": "2.0", "id": 2, "method": "ping"}, state)["result"] == {}


def test_edge_a_clients_response_object_is_not_answered(tmp_path):
    tools = _tools(tmp_path)
    state = _session(tools)
    assert _req(tools, {"jsonrpc": "2.0", "id": 9, "result": {}}, state) is None
    assert _req(tools, {"jsonrpc": "2.0", "id": 9, "error": {"code": 1, "message": "x"}},
                state) is None


# --- M9: axross/tasks/* --------------------------------------------------------------


def test_happy_axross_tasks_run_in_every_session(tmp_path):
    (tmp_path / "f").write_bytes(b"abc")
    tools = _tools(tmp_path)
    tasks = M._TaskRegistry()
    state = _session(tools)
    started = _req(tools, {"jsonrpc": "2.0", "id": 1, "method": "axross/tasks/start",
                           "params": {"name": "stat", "arguments": {"path": str(tmp_path / "f")}}},
                   state, tasks=tasks)
    tid = started["result"]["task_id"]
    for _ in range(100):
        status = _req(tools, {"jsonrpc": "2.0", "id": 2, "method": "axross/tasks/status",
                              "params": {"task_id": tid}}, state, tasks=tasks)["result"]
        if status["status"] != "running":
            break
        time.sleep(0.02)
    assert status["status"] == "done" and status["result"]["size"] == 3


def test_sad_bare_tasks_methods_are_not_offered_to_2025_11_25(tmp_path):
    tools = _tools(tmp_path)
    tasks = M._TaskRegistry()
    new = _session(tools)
    resp = _req(tools, {"jsonrpc": "2.0", "id": 1, "method": "tasks/list"}, new, tasks=tasks)
    assert resp["error"]["code"] == M.ERR_METHOD_NOT_FOUND
    old = _session(tools, "2024-11-05")
    assert _req(tools, {"jsonrpc": "2.0", "id": 1, "method": "tasks/list"}, old,
                tasks=tasks)["result"] == {"tasks": []}


def test_sad_an_unknown_task_or_tool_is_invalid_params(tmp_path):
    tools = _tools(tmp_path)
    tasks = M._TaskRegistry()
    state = _session(tools)
    for method in ("axross/tasks/status", "axross/tasks/cancel"):
        resp = _req(tools, {"jsonrpc": "2.0", "id": 1, "method": method,
                            "params": {"task_id": "nope"}}, state, tasks=tasks)
        assert resp["error"]["code"] == M.ERR_INVALID_PARAMS
    resp = _req(tools, {"jsonrpc": "2.0", "id": 1, "method": "axross/tasks/start",
                        "params": {"name": "nope"}}, state, tasks=tasks)
    assert resp["error"]["code"] == M.ERR_INVALID_PARAMS


# --- M1 / H3: tasks stop, are capped, and are freed -----------------------------------


def _wait(predicate, seconds=10.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def _slow_tool(release: threading.Event, cooperative: bool) -> M._Tool:
    def handler(args, ctx):
        while not release.is_set():
            if cooperative:
                ctx.check_cancel()
            time.sleep(0.01)
        return {"ok": True}

    return M._Tool(name="slow", description="", schema={"type": "object"}, handler=handler,
                   timeout_seconds=60)


def _start(tasks, tool, scope=""):
    task = tasks.start(scope, tool.name, {})
    thread = threading.Thread(target=M._run_task, args=(task, tool, None, tasks), daemon=True)
    task.thread = thread
    thread.start()
    return task


def test_happy_a_cancelled_task_stops(tmp_path):
    release = threading.Event()
    tasks = M._TaskRegistry()
    task = _start(tasks, _slow_tool(release, cooperative=True))
    assert tasks.cancel(task.task_id, "")
    assert _wait(lambda: task.status == "cancelled")
    assert not task.abandoned and _wait(lambda: not task.thread.is_alive())
    release.set()


def test_sad_a_task_that_ignores_cancel_is_abandoned_and_frees_its_slot():
    release = threading.Event()
    tasks = M._TaskRegistry(stop_grace=0.2, max_running_per_scope=1)
    tool = _slow_tool(release, cooperative=False)
    task = _start(tasks, tool)
    with pytest.raises(M.TaskLimitError):
        tasks.start("", "slow", {})
    tasks.cancel(task.task_id, "")
    assert _wait(lambda: task.status == "cancelled")
    assert task.abandoned and task.thread.is_alive()
    second = _start(tasks, tool)  # the slot is free again
    release.set()
    assert _wait(lambda: second.status == "done")
    assert task.status == "cancelled"  # the late worker changed nothing


def test_sad_a_task_past_its_timeout_is_ended_hard():
    release = threading.Event()
    tasks = M._TaskRegistry(stop_grace=0.2)
    tool = _slow_tool(release, cooperative=False)
    tool.timeout_seconds = 0.2
    task = _start(tasks, tool)
    assert _wait(lambda: task.status == "error", 5)
    assert task.abandoned and "timeout" in task.error
    release.set()


def test_sad_the_running_cap_is_per_server_too():
    release = threading.Event()
    tasks = M._TaskRegistry(max_running_per_scope=2, max_running_total=3)
    tool = _slow_tool(release, cooperative=True)
    _start(tasks, tool, "a")
    _start(tasks, tool, "a")
    _start(tasks, tool, "b")
    with pytest.raises(M.TaskLimitError, match="server"):
        tasks.start("c", "slow", {})
    release.set()


def test_happy_drop_scope_cancels_and_forgets_a_sessions_tasks():
    release = threading.Event()
    tasks = M._TaskRegistry()
    tool = _slow_tool(release, cooperative=True)
    task = _start(tasks, tool, "sess")
    assert tasks.drop_scope("sess") == 1
    assert task.status == "cancelled" and tasks.get(task.task_id, "sess") is None
    assert _wait(lambda: not task.thread.is_alive())
    release.set()


def test_happy_finished_results_are_capped_in_bytes_across_scopes():
    tasks = M._TaskRegistry(max_result_bytes=1000)
    for scope in ("a", "b", "c"):
        t = tasks.start(scope, "x", {})
        t.finish("done", result="x" * 600, result_bytes=600)
        tasks.note_finished()
    kept = [t for t in tasks.list_all()]
    assert sum(t.result_bytes for t in kept) <= 1000 and kept[-1].scope == "c"


def test_happy_finished_tasks_age_out_in_every_scope():
    tasks = M._TaskRegistry(retention_seconds=0.0)
    old = tasks.start("gone-session", "x", {})
    old.finish("done", result={}, result_bytes=2)
    time.sleep(0.01)
    tasks.start("other", "x", {})  # any call evicts every scope's stale tasks
    assert all(t.scope != "gone-session" for t in tasks.list_all())


def test_happy_checksum_of_a_local_file_stops_at_cancel(tmp_path):
    big = tmp_path / "big.bin"
    with open(big, "wb") as fh:
        fh.truncate(64 * 1024 * 1024)  # sparse
    tools = {t.name: t for t in _tools(tmp_path)}
    cancel = threading.Event()
    cancel.set()
    ctx = M._ToolContext(cancel_event=cancel)
    with pytest.raises(M.CancelledError):
        tools["checksum"].handler({"path": str(big)}, ctx)


def test_happy_stdio_eof_stops_running_tasks(tmp_path):
    release = threading.Event()
    stopped = threading.Event()

    def handler(args, ctx):
        try:
            while not release.is_set():
                ctx.check_cancel()
                time.sleep(0.01)
        finally:
            stopped.set()
        return {}

    tool = M._Tool(name="slow", description="", schema={"type": "object"}, handler=handler,
                   timeout_seconds=60)
    lines = [{"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}},
             {"jsonrpc": "2.0", "id": 1, "method": "axross/tasks/start",
              "params": {"name": "slow", "arguments": {}}}]
    stdin = io.StringIO("".join(json.dumps(x) + "\n" for x in lines))
    real_build = M._build_tools
    try:
        M._build_tools = lambda *a, **k: [tool]
        M.serve(M.ServerConfig(backend=LocalFS(), stdin=stdin, stdout=io.StringIO(),
                               rate_limit_enabled=False))
    finally:
        M._build_tools = real_build
    assert stopped.wait(5), "the task was left running after the client went away"
    release.set()


# --- M4: read_file text paging -------------------------------------------------------


@pytest.mark.parametrize("max_bytes", [1, 2, 3])
def test_sad_text_paging_moves_on_through_a_four_byte_character(tmp_path, max_bytes):
    text = "a\U0001F600b"
    (tmp_path / "e.txt").write_text(text, encoding="utf-8")
    tools = {t.name: t for t in _tools(tmp_path)}
    offset, got = 0, ""
    for _ in range(20):
        r = tools["read_file"].handler({"path": str(tmp_path / "e.txt"), "encoding": "text",
                                        "max_bytes": max_bytes, "offset": offset},
                                       M._ToolContext())
        got += r["text"]
        if not r["truncated"]:
            break
        assert r["next_offset"] > offset, r
        offset = r["next_offset"]
    assert got == text


# --- H1: names that are not UTF-8 ------------------------------------------------------


@pytest.mark.skipif(sys.platform == "darwin", reason="APFS refuses names that are not UTF-8")
def test_happy_a_name_that_is_not_utf8_goes_out_readable_and_comes_back_by_b64(tmp_path):
    raw = os.fsencode(tmp_path) + b"/bad\xff.txt"
    with open(raw, "wb") as fh:
        fh.write(b"payload")
    tools = _tools(tmp_path)
    state = _session(tools)
    resp = _req(tools, {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": "list_dir", "arguments": {"path": str(tmp_path)}}},
                state)
    line = M._dumps_wire(resp)
    line.encode("utf-8")  # strict: no lone surrogate anywhere
    assert "\\udc" not in line.lower()
    entry = json.loads(json.loads(line)["result"]["content"][0]["text"])[0]
    assert entry["name"] == "bad�.txt"
    assert base64.b64decode(entry["name_b64"]) == b"bad\xff.txt"
    path_b64 = base64.b64encode(raw).decode()
    read = _req(tools, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                        "params": {"name": "read_file", "arguments": {"path_b64": path_b64}}},
                state)
    assert base64.b64decode(read["result"]["structuredContent"]["content_b64"]) == b"payload"
    err = _req(tools, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                       "params": {"name": "read_file", "arguments": {"path": os.fsdecode(raw)
                                                                     + "x"}}}, state)
    M._dumps_wire(err).encode("utf-8")  # error texts too


def test_edge_malformed_b64_is_refused(tmp_path):
    tools = _tools(tmp_path)
    state = _session(tools, "2025-06-18")
    resp = _req(tools, {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": "stat", "arguments": {"path_b64": "%%%"}}}, state)
    assert resp["error"]["code"] == M.ERR_INVALID_PARAMS


def test_happy_every_path_argument_has_its_b64_twin(tmp_path):
    from core import mcp_groups as G

    for tool in M._build_tools(LocalFS(), allow_write=True, root=str(tmp_path),
                               tool_groups=frozenset(G.GROUPS)):
        props = tool.schema.get("properties", {})
        for name in M.PATH_ARGUMENTS:
            if props.get(name, {}).get("type") == "string":
                assert f"{name}_b64" in props, (tool.name, name)


# --- LOW --------------------------------------------------------------------------


def test_sad_an_unsafe_archive_is_a_tool_error_not_bad_arguments(tmp_path):
    from core.archive import UnsafeArchive

    assert M._is_tool_failure(UnsafeArchive("zip slip"))
    assert not M._is_tool_failure(ValueError("bad argument"))


def test_happy_an_audit_line_is_forwarded_once(tmp_path):
    sink = io.StringIO()
    forwarder = M._LogForwarder(sink, min_level=logging.INFO)
    M._attach_log_forwarder(forwarder)
    audit = logging.getLogger("core.mcp_server.audit")
    old = audit.level
    audit.setLevel(logging.INFO)
    try:
        audit.info("write_file ok path=/x")
    finally:
        audit.setLevel(old)
        M._detach_log_forwarder(forwarder)
    assert sum("write_file ok" in line for line in sink.getvalue().splitlines()) == 1


def test_happy_set_level_is_per_session():
    forwarder = M._LogForwarder(None, min_level=logging.WARNING)
    forwarder.set_min_level(logging.DEBUG, session_id="a")
    assert forwarder.level_for("a") == logging.DEBUG
    assert forwarder.level_for("b") == logging.WARNING


def test_sad_a_closed_stdout_ends_the_server_quietly(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith("AXROSS_")}
    env.update(HOME=str(home), XDG_CONFIG_HOME=str(home / ".config"),
               XDG_STATE_HOME=str(home / ".state"))
    proc = subprocess.Popen([sys.executable, str(ROOT / "main.py"), "--mcp-server",
                             "--mcp-root", str(tmp_path)],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=env, cwd=ROOT)
    proc.stdout.close()
    proc.stdin.write(b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n')
    proc.stdin.flush()
    try:
        proc.stdin.close()
    except BrokenPipeError:
        pass
    code = proc.wait(60)
    err = proc.stderr.read().decode(errors="replace")
    assert code == 0, err
    assert "Traceback" not in err and "BrokenPipeError" not in err
