"""The stdio MCP transport serialises every write to its one stdout.

Three kinds of writer share that stream: the request loop (responses), the
tasks/start worker threads (notifications/progress) and the log forwarder
(notifications/message). io.TextIOWrapper is documented as not thread-safe,
so without one shared lock two frames can interleave inside one line and the
client receives garbage JSON. The sink below makes that interleaving
deterministic by yielding the GIL after every character.
"""

from __future__ import annotations

import json
import logging
import threading
import time

import pytest

from core import mcp_server as M
from core.local_fs import LocalFS

PROGRESS_FRAMES = 60
PINGS = 60


class _InterleavingSink:
    """A stream whose write() is visibly non-atomic across threads."""

    def __init__(self) -> None:
        self.chars: list[str] = []

    def write(self, text: str) -> int:
        for ch in text:
            self.chars.append(ch)
            time.sleep(0)  # hand the GIL to any other writer mid-frame
        return len(text)

    def flush(self) -> None:
        return None

    def lines(self) -> list[str]:
        return [ln for ln in "".join(self.chars).split("\n") if ln]


class _ScriptedStdin:
    """Feeds tasks/start, waits until the task is emitting, then pings.

    EOF is only returned after the task finished, so the loop and the task
    worker are guaranteed to write at the same time.
    """

    def __init__(self, started: threading.Event, finished: threading.Event) -> None:
        start = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/start",
            "params": {"name": "chatty", "arguments": {}},
        }
        self._lines = [json.dumps(start) + "\n"]
        self._lines += [
            json.dumps({"jsonrpc": "2.0", "id": 100 + i, "method": "ping"}) + "\n"
            for i in range(PINGS)
        ]
        self._started = started
        self._finished = finished

    def readline(self, limit: int = -1) -> str:
        if len(self._lines) == PINGS:  # tasks/start already handed out
            assert self._started.wait(10), "task never started"
        if self._lines:
            return self._lines.pop(0)
        assert self._finished.wait(30), "task never finished"
        return ""


def _chatty_tool(started: threading.Event, finished: threading.Event) -> M._Tool:
    def _handler(args, ctx):
        started.set()
        for i in range(PROGRESS_FRAMES):
            ctx.progress(i + 1, PROGRESS_FRAMES, f"frame {i}")
            # Also drive the log forwarder, the third writer on stdout.
            M.log.warning("chatty warning %d", i)
        finished.set()
        return {"frames": PROGRESS_FRAMES}

    return M._Tool(
        name="chatty",
        description="emits progress and warnings",
        schema={"type": "object", "properties": {}},
        handler=_handler,
        timeout_seconds=30.0,
    )


def _serve_with(monkeypatch, tmp_path, sink) -> None:
    started, finished = threading.Event(), threading.Event()
    tool = _chatty_tool(started, finished)
    monkeypatch.setattr(M, "_build_tools", lambda *a, **k: [tool])
    rc = M.serve(
        M.ServerConfig(
            backend=LocalFS(),
            root=str(tmp_path),
            stdin=_ScriptedStdin(started, finished),
            stdout=sink,
        )
    )
    assert rc == 0


def test_concurrent_stdio_writers_never_interleave_inside_a_line(monkeypatch, tmp_path) -> None:
    sink = _InterleavingSink()
    _serve_with(monkeypatch, tmp_path, sink)
    lines = sink.lines()
    broken = []
    frames = []
    for line in lines:
        try:
            frames.append(json.loads(line))
        except json.JSONDecodeError:
            broken.append(line[:120])
    assert broken == [], f"{len(broken)} of {len(lines)} lines are not JSON: {broken[:3]}"
    progress = [f for f in frames if f.get("method") == "notifications/progress"]
    messages = [f for f in frames if f.get("method") == "notifications/message"]
    responses = [f for f in frames if "id" in f]
    assert len(progress) == PROGRESS_FRAMES
    assert len(messages) == PROGRESS_FRAMES
    assert len(responses) == PINGS + 1  # every ping plus tasks/start


def test_serialized_writer_releases_the_lock_when_the_stream_raises() -> None:
    # Sad path: a broken pipe on one write must not wedge every later writer.
    class _FailsOnce:
        def __init__(self) -> None:
            self.calls = 0
            self.data: list[str] = []

        def write(self, text: str) -> int:
            self.calls += 1
            if self.calls == 1:
                raise BrokenPipeError("client went away")
            self.data.append(text)
            return len(text)

        def flush(self) -> None:
            return None

    stream = _FailsOnce()
    writer = M._SerializedWriter(stream)
    with pytest.raises(BrokenPipeError):
        writer.write("first\n")
    done = threading.Event()

    def _other_thread() -> None:
        writer.write("second\n")
        writer.flush()
        done.set()

    threading.Thread(target=_other_thread, daemon=True).start()
    assert done.wait(5), "lock stayed held after the failed write"
    assert stream.data == ["second\n"]


def test_serialized_writer_passes_text_and_empty_writes_through() -> None:
    # Edge: an empty write and the return value behave like the stream's.
    sink = _InterleavingSink()
    writer = M._SerializedWriter(sink)
    assert writer.write("") == 0
    assert writer.write('{"a": 1}\n') == 9
    writer.flush()
    assert sink.lines() == ['{"a": 1}']


def test_serve_without_tasks_still_answers_in_order(monkeypatch, tmp_path) -> None:
    # Happy single-writer path: plain request/response is unchanged.
    sink = _InterleavingSink()

    class _Stdin:
        def __init__(self) -> None:
            self._lines = [
                json.dumps({"jsonrpc": "2.0", "id": i, "method": "ping"}) + "\n" for i in range(3)
            ]

        def readline(self, limit: int = -1) -> str:
            return self._lines.pop(0) if self._lines else ""

    rc = M.serve(M.ServerConfig(backend=LocalFS(), root=str(tmp_path), stdin=_Stdin(), stdout=sink))
    assert rc == 0
    assert [json.loads(ln)["id"] for ln in sink.lines()] == [0, 1, 2]


@pytest.fixture(autouse=True)
def _quiet_root_logger():
    # The chatty tool logs warnings; keep them off the test's stderr.
    logger = logging.getLogger("core.mcp_server")
    previous = logger.propagate
    logger.propagate = False
    yield
    logger.propagate = previous
