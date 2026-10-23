"""Why axross refused a tool call travels with the tool_result event, so the
Agent dock's voice can say it (read-only, not allowed, permission)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import agent as A  # noqa: E402
from core import agent_sandbox as SB  # noqa: E402
from tests.test_agent_files_read_only import _config, _Script  # noqa: E402
from tests.test_agent_loop import _call  # noqa: E402


@pytest.mark.parametrize("outcome,text,read_only,reason", [
    ("declined", A.READ_ONLY_REFUSAL, False, "read_only"),
    ("declined", "declined: the user did not allow this call", False, "declined"),
    ("unavailable", "error: the tool 'write_file' is not available to you", True, "read_only"),
    ("error", "error: [Errno 13] Permission denied: '/etc/shadow'", False, "permission"),
    ("error", "error: PermissionError: not allowed", False, "permission"),
])
def test_happy_refusals_have_a_reason(outcome, text, read_only, reason):
    assert A.refusal_reason(outcome, text, files_read_only=read_only) == reason


@pytest.mark.parametrize("outcome,text,read_only", [
    ("ok", "Permission denied appears in a file's text", False),
    ("error", "error: no such file", False),
    ("unavailable", "error: the tool 'x' is not available to you", False),
    ("", "", False),
])
def test_sad_no_refusal_no_reason(outcome, text, read_only):
    assert A.refusal_reason(outcome, text, files_read_only=read_only) == ""


def test_happy_a_run_reports_the_reason_with_the_tool_result(tmp_path):
    (tmp_path / "keep.txt").write_text("x")
    events = []
    model = _Script([_call("write_file", {"path": str(tmp_path / "keep.txt"), "content": "y"},
                           "w1")])
    A.Agent(_config(tmp_path, files_read_only=True), transport=model, confirm=lambda *_: True,
            on_event=events.append).run("change it")
    results = [e for e in events if e["type"] == "tool_result"]
    assert [{k: v for k, v in r.items() if k != "detail"} for r in results] == [
        {"type": "tool_result", "name": "write_file", "outcome": "unavailable",
         "reason": "read_only"}]
    assert results[0]["detail"]  # the reason in words, test_agent_tool_result_detail


def test_happy_a_declined_call_reports_declined(tmp_path):
    events = []
    model = _Script([_call("write_file", {"path": str(tmp_path / "n.txt"), "content": "y"},
                           "w1")])
    A.Agent(_config(tmp_path), transport=model, confirm=lambda *_: False,
            on_event=events.append).run("write")
    assert [e.get("reason") for e in events if e["type"] == "tool_result"] == ["declined"]


def test_edge_a_sandbox_worker_passes_only_known_reasons():
    ok = SB._clean_event({"type": "tool_result", "name": "x", "outcome": "declined",
                          "reason": "read_only"})
    assert ok["reason"] == "read_only"
    odd = SB._clean_event({"type": "tool_result", "name": "x", "outcome": "error",
                           "reason": "<script>"})
    assert odd["reason"] == ""
    none = SB._clean_event({"type": "tool_result", "name": "x", "outcome": "ok"})
    assert none["reason"] == ""
