"""MCP tasks/start obeys the same limits as tools/call: rate limit, a cap on
concurrently running tasks, and the tool's wall-clock timeout."""

from __future__ import annotations

import threading
import time
import unittest

from core import mcp_server as M


def _blocking_tool(release: threading.Event, *, timeout: float | None = None) -> M._Tool:
    def handler(args, ctx):
        while not release.wait(0.02):
            ctx.check_cancel()
        return {"ok": True}

    return M._Tool(
        name="slow",
        description="blocks until released",
        schema={"type": "object"},
        handler=handler,
        timeout_seconds=timeout,
    )


def _start(tools, tasks, *, scope="s1", rate_limiter=None, rid=1) -> dict:
    return M._handle_request(
        {"jsonrpc": "2.0", "id": rid, "method": "tasks/start", "params": {"name": "slow"}},
        tools,
        tasks=tasks,
        session_id=scope,
        rate_limiter=rate_limiter,
    )


def _status(tools, tasks, task_id: str, scope="s1") -> dict:
    return M._handle_request(
        {
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tasks/status",
            "params": {"task_id": task_id},
        },
        tools,
        tasks=tasks,
        session_id=scope,
    )["result"]


class TaskLimitsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.release = threading.Event()
        self.addCleanup(self.release.set)

    def test_sad_tasks_start_is_rate_limited_like_tools_call(self) -> None:
        tools = [_blocking_tool(self.release)]
        tasks = M._TaskRegistry()
        limiter = M._RateLimiter(burst=1, refill_per_sec=0.0)
        first = _start(tools, tasks, rate_limiter=limiter)
        self.assertIn("result", first)
        second = _start(tools, tasks, rate_limiter=limiter, rid=2)
        self.assertEqual(second["error"]["code"], M.ERR_RATE_LIMITED)
        self.assertEqual(len(tasks.list_scope("s1")), 1)

    def test_sad_running_tasks_are_capped_per_scope(self) -> None:
        tools = [_blocking_tool(self.release)]
        tasks = M._TaskRegistry()
        cap = M.MAX_RUNNING_TASKS_PER_SCOPE
        for i in range(cap):
            self.assertIn("result", _start(tools, tasks, rid=i))
        refused = _start(tools, tasks, rid=cap)
        self.assertEqual(refused["error"]["code"], M.ERR_RATE_LIMITED)
        self.assertIn("running", refused["error"]["message"])
        # Another session has its own allowance.
        self.assertIn("result", _start(tools, tasks, scope="s2", rid=cap + 1))
        alive = sum(1 for t in threading.enumerate() if t.name.startswith("mcp-task-"))
        self.assertLessEqual(alive, cap + 1)

    def test_edge_finished_tasks_free_their_slot(self) -> None:
        tools = [_blocking_tool(self.release)]
        tasks = M._TaskRegistry()
        cap = M.MAX_RUNNING_TASKS_PER_SCOPE
        started = [_start(tools, tasks, rid=i)["result"]["task_id"] for i in range(cap)]
        self.release.set()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if all(_status(tools, tasks, t)["status"] == "done" for t in started):
                break
            time.sleep(0.02)
        self.assertIn("result", _start(tools, tasks, rid=cap))

    def test_sad_task_honours_the_tool_timeout(self) -> None:
        tools = [_blocking_tool(self.release, timeout=0.3)]
        tasks = M._TaskRegistry()
        task_id = _start(tools, tasks)["result"]["task_id"]
        deadline = time.monotonic() + 5
        status = {}
        while time.monotonic() < deadline:
            status = _status(tools, tasks, task_id)
            if status["status"] != "running":
                break
            time.sleep(0.05)
        self.assertEqual(status["status"], "error")
        self.assertIn("timeout", status["error"])

    def test_happy_task_without_limits_completes(self) -> None:
        self.release.set()
        tools = [_blocking_tool(self.release, timeout=5)]
        tasks = M._TaskRegistry()
        limiter = M._RateLimiter(burst=5, refill_per_sec=0.0)
        task_id = _start(tools, tasks, rate_limiter=limiter)["result"]["task_id"]
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and _status(tools, tasks, task_id)["status"] == "running":
            time.sleep(0.02)
        status = _status(tools, tasks, task_id)
        self.assertEqual((status["status"], status["result"]), ("done", {"ok": True}))


if __name__ == "__main__":
    unittest.main()
