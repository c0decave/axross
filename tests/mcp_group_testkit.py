"""Helpers for the MCP capability-group tests: build a tool catalogue for a
root and some groups, call a tool through the real JSON-RPC dispatcher (so
the input schema is enforced exactly as for a client), read the audit
trail."""

from __future__ import annotations

import json
import logging
import threading

from core import mcp_server as M
from core.local_fs import LocalFS

AUDIT = "core.mcp_server.audit"


class RpcError(Exception):
    def __init__(self, code: int, message: str, data=None) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.data = data


def build(root, groups, *, allow_write: bool = False, backend=None, **kw) -> dict:
    tools = M._build_tools(
        backend if backend is not None else LocalFS(),
        allow_write=allow_write,
        root=str(root),
        tool_groups=frozenset(groups),
        **kw,
    )
    return {t.name: t for t in tools}


def call(tools: dict, name: str, args: dict | None = None, *, session_id=None):
    """tools/call through the dispatcher; returns the decoded result or
    raises :class:`RpcError`."""
    resp = M._handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": args or {}},
        },
        list(tools.values()),
        cancels=M._CancelRegistry(),
        session_id=session_id,
    )
    if "error" in resp:
        err = resp["error"]
        raise RpcError(err["code"], err["message"], err.get("data"))
    return json.loads(resp["result"]["content"][0]["text"])


def run_handler(tools: dict, name: str, args: dict, *, cancel: threading.Event | None = None):
    """Call the handler directly with a progress-recording context."""
    frames: list[tuple] = []
    ctx = M._ToolContext(cancel_event=cancel)
    ctx.progress = lambda p, t=None, m="": frames.append((p, t, m))  # type: ignore[method-assign]
    return tools[name].handler(args, ctx), frames


def audit_lines(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.name == AUDIT]


def capture_audit(caplog):
    caplog.set_level(logging.INFO, logger=AUDIT)
    return caplog
