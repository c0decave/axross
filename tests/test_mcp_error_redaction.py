"""Backend error text the MCP server hands to a client is redacted.

Backend exceptions routinely carry a connection URL with userinfo, a
``password=`` assignment or an ``Authorization`` header. The MCP client
is an LLM agent and its transcript is logged elsewhere; secrets must not
travel there verbatim.
"""

from __future__ import annotations

import os
import tempfile
import threading
import time
import unittest

from core import mcp_server as M
from core.local_fs import LocalFS

_SECRET = "hun" + "ter2"
_LEAKY = (
    f"connect sftp://alice:{_SECRET}@files.example/x failed; "
    f"password={_SECRET} Authorization: Bearer {_SECRET}tok"
)


def _raising_tool(exc: BaseException) -> M._Tool:
    def handler(args, ctx):
        raise exc

    return M._Tool(
        name="boom",
        description="raises",
        schema={"type": "object"},
        handler=handler,
    )


def _call(tools, name="boom", args=None) -> dict:
    return M._handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": args or {}},
        },
        tools,
    )


class ToolsCallErrorRedactionTest(unittest.TestCase):
    def test_backend_oserror_message_is_redacted(self) -> None:
        resp = _call([_raising_tool(OSError(_LEAKY))])
        message = resp["error"]["message"]
        self.assertNotIn(_SECRET, message)
        self.assertIn("files.example", message)
        self.assertIn("<redacted>", message)

    def test_value_error_message_is_redacted_too(self) -> None:
        resp = _call([_raising_tool(ValueError(_LEAKY))])
        self.assertEqual(resp["error"]["code"], M.ERR_INVALID_PARAMS)
        self.assertNotIn(_SECRET, resp["error"]["message"])

    def test_message_without_secrets_is_unchanged(self) -> None:
        resp = _call([_raising_tool(OSError("No such file: /tmp/a b.txt"))])
        self.assertEqual(resp["error"]["message"], "tool 'boom' failed: No such file: /tmp/a b.txt")


class TaskErrorRedactionTest(unittest.TestCase):
    def test_task_error_text_is_redacted(self) -> None:
        tools = [_raising_tool(OSError(_LEAKY))]
        tasks = M._TaskRegistry()
        started = M._handle_request(
            {"jsonrpc": "2.0", "id": 1, "method": "tasks/start", "params": {"name": "boom"}},
            tools,
            tasks=tasks,
            session_id="s1",
        )
        task_id = started["result"]["task_id"]
        deadline = time.monotonic() + 5
        status: dict = {}
        while time.monotonic() < deadline:
            status = M._handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tasks/status",
                    "params": {"task_id": task_id},
                },
                tools,
                tasks=tasks,
                session_id="s1",
            )["result"]
            if status.get("status") == "error":
                break
            time.sleep(0.01)
        self.assertEqual(status.get("status"), "error")
        self.assertNotIn(_SECRET, status["error"])
        self.assertIn("<redacted>", status["error"])
        # No worker thread from the task outlives the test.
        for t in threading.enumerate():
            if t.name.startswith("mcp-task"):
                t.join(timeout=2)


class _FailingReadFS(LocalFS):
    def checksum(self, path, algorithm="sha256"):
        return ""

    def open_read(self, path, *a, **kw):
        raise OSError(_LEAKY)


class PerEntryErrorRedactionTest(unittest.TestCase):
    def test_recursive_checksum_entry_error_is_redacted(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with open(os.path.join(tmp.name, "a.txt"), "w", encoding="utf-8") as fh:
            fh.write("x")
        tools = M._build_tools(
            _FailingReadFS(), allow_write=False, backend_id="local", root=tmp.name
        )
        tool = next(t for t in tools if t.name == "recursive_checksum")
        result = tool.handler({"path": tmp.name}, M._ToolContext())
        entries = result["entries"] if isinstance(result, dict) else result
        errors = [e["error"] for e in entries if "error" in e]
        self.assertEqual(len(errors), 1)
        self.assertNotIn(_SECRET, errors[0])
        self.assertIn("<redacted>", errors[0])


if __name__ == "__main__":
    unittest.main()
