"""The MCP script tools land on the same audit trail as the write tools.

script_write / script_delete / script_run mutate state or execute code
(script_run in a child process), so each call leaves an attempt line and
an ok/refused line on ``core.mcp_server.audit`` — names, sizes, the exit
status and an exception type only, never the script source, its
arguments or what the script printed.
"""

from __future__ import annotations

import logging

import pytest

from core import mcp_server as M
from core.local_fs import LocalFS

AUDIT = "core.mcp_server.audit"
SOURCE_MARKER = "SOURCE-MARKER-must-not-be-audited"
OUTPUT_MARKER = "OUTPUT-MARKER-must-not-be-audited"


def _tools(tmp_path, *, allow_write: bool = False) -> dict:
    tools = M._build_tools(
        LocalFS(), allow_write=allow_write, root=str(tmp_path), allow_scripts=True
    )
    return {t.name: t for t in tools}


def _call(tools: dict, name: str, args: dict):
    return tools[name].handler(args, M._ToolContext())


def _audit_lines(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.name == AUDIT]


@pytest.fixture
def audit(caplog):
    caplog.set_level(logging.INFO, logger=AUDIT)
    return caplog


def test_script_write_is_audited_without_source(tmp_path, audit) -> None:
    tools = _tools(tmp_path)
    source = f"x = {SOURCE_MARKER!r}\n"
    _call(tools, "script_write", {"name": "audited_write", "source": source})
    lines = _audit_lines(audit)
    assert lines == [
        "tool=script_write outcome=attempt name='audited_write'",
        f"tool=script_write outcome=ok name='audited_write' size={len(source)}",
    ]
    assert not any(SOURCE_MARKER in line for line in lines)


def test_script_run_is_audited_without_output(tmp_path, audit) -> None:
    tools = _tools(tmp_path)
    _call(tools, "script_write", {"name": "audited_run", "source": f"print({OUTPUT_MARKER!r})\n"})
    audit.clear()
    result = _call(tools, "script_run", {"name": "audited_run"})
    assert OUTPUT_MARKER in result["stdout"]
    lines = _audit_lines(audit)
    assert lines == [
        "tool=script_run outcome=attempt name='audited_run'",
        "tool=script_run outcome=ok name='audited_run' exit=0",
    ]
    assert not any(OUTPUT_MARKER in line for line in lines)


def test_script_delete_is_audited(tmp_path, audit) -> None:
    tools = _tools(tmp_path)
    _call(tools, "script_write", {"name": "audited_delete", "source": "pass\n"})
    audit.clear()
    _call(tools, "script_delete", {"name": "audited_delete"})
    assert _audit_lines(audit) == [
        "tool=script_delete outcome=attempt name='audited_delete'",
        "tool=script_delete outcome=ok name='audited_delete'",
    ]


def test_script_write_with_invalid_name_is_audited_as_refused(tmp_path, audit) -> None:
    tools = _tools(tmp_path)
    with pytest.raises(ValueError):
        _call(tools, "script_write", {"name": "../escape", "source": SOURCE_MARKER})
    lines = _audit_lines(audit)
    assert lines == [
        "tool=script_write outcome=attempt name='../escape'",
        "tool=script_write outcome=refused name='../escape' error='ValueError'",
    ]
    assert not any(SOURCE_MARKER in line for line in lines)


def test_script_run_of_missing_script_is_audited_as_refused(tmp_path, audit) -> None:
    tools = _tools(tmp_path)
    with pytest.raises(FileNotFoundError):
        _call(tools, "script_run", {"name": "never_written"})
    assert _audit_lines(audit) == [
        "tool=script_run outcome=attempt name='never_written'",
        "tool=script_run outcome=refused name='never_written' error='FileNotFoundError'",
    ]


def test_script_run_that_raises_logs_only_the_exception_type(tmp_path, audit) -> None:
    tools = _tools(tmp_path)
    _call(
        tools,
        "script_write",
        {"name": "audited_raise", "source": f"raise RuntimeError({OUTPUT_MARKER!r})\n"},
    )
    audit.clear()
    # The script ran and failed: a structured reply, not a refusal of the call.
    result = _call(tools, "script_run", {"name": "audited_raise", "args": [OUTPUT_MARKER]})
    assert result["error_type"] == "RuntimeError" and OUTPUT_MARKER in result["error"]
    lines = _audit_lines(audit)
    assert lines[-1] == (
        "tool=script_run outcome=ok name='audited_raise' exit=1 error='RuntimeError'"
    )
    assert not any(OUTPUT_MARKER in line for line in lines)


def test_script_run_that_exits_is_audited_with_its_exit_code(tmp_path, audit) -> None:
    # Edge: SystemExit is a normal return path of script_run, not a refusal.
    tools = _tools(tmp_path)
    _call(
        tools,
        "script_write",
        {"name": "audited_exit", "source": f"print({OUTPUT_MARKER!r})\nraise SystemExit(3)\n"},
    )
    audit.clear()
    result = _call(tools, "script_run", {"name": "audited_exit"})
    assert result["exit"] == 3
    lines = _audit_lines(audit)
    assert lines == [
        "tool=script_run outcome=attempt name='audited_exit'",
        "tool=script_run outcome=ok name='audited_exit' exit=3",
    ]
    assert not any(OUTPUT_MARKER in line for line in lines)


def _run_exit(tools: dict, name: str, exit_expr: str) -> dict:
    _call(tools, "script_write", {"name": name, "source": f"raise SystemExit({exit_expr})\n"})
    return _call(tools, "script_run", {"name": name})


def test_script_run_with_a_text_exit_reports_it_like_python(tmp_path, audit) -> None:
    # Sad: sys.exit("message") made script_run raise ValueError from
    # int("message") and left an attempt line with no outcome. Python
    # itself prints the message to stderr and exits with 1.
    tools = _tools(tmp_path)
    audit.clear()
    result = _run_exit(tools, "audited_text_exit", "'bye'")
    assert result["exit"] == 1
    assert result["stderr"] == "bye\n"
    assert _audit_lines(audit)[-1] == "tool=script_run outcome=ok name='audited_text_exit' exit=1"


@pytest.mark.parametrize(
    ("exit_expr", "code", "stderr"),
    [("None", 0, ""), ("0", 0, ""), ("True", 1, ""), ("''", 1, "\n"), ("[2]", 1, "[2]\n")],
)
def test_script_run_exit_codes_follow_python(tmp_path, exit_expr, code, stderr) -> None:
    # Edge: bool counts as an int; any other non-int object is printed.
    result = _run_exit(_tools(tmp_path), "audited_exit_kinds", exit_expr)
    assert (result["exit"], result["stderr"]) == (code, stderr)


def test_read_only_script_tools_leave_no_audit_line(tmp_path, audit) -> None:
    # Edge: script_list / script_read do not mutate; they stay off the
    # audit trail just like list_dir / read_file.
    tools = _tools(tmp_path)
    _call(tools, "script_write", {"name": "audited_read", "source": "pass\n"})
    audit.clear()
    _call(tools, "script_list", {})
    _call(tools, "script_read", {"name": "audited_read"})
    assert _audit_lines(audit) == []


def test_script_audit_works_with_write_tools_enabled_too(tmp_path, audit) -> None:
    # Edge: the audit helper must not depend on which opt-in built it.
    tools = _tools(tmp_path, allow_write=True)
    _call(tools, "script_delete", {"name": "absent_is_fine"})
    assert _audit_lines(audit) == [
        "tool=script_delete outcome=attempt name='absent_is_fine'",
        "tool=script_delete outcome=ok name='absent_is_fine'",
    ]


def test_script_run_that_times_out_is_audited_as_such(tmp_path, audit) -> None:
    # Edge: a stopped run is still an outcome of the run, with its marker.
    tools = _tools(tmp_path)
    _call(tools, "script_write", {"name": "audited_loop", "source": "while True:\n    pass\n"})
    audit.clear()
    result = _call(tools, "script_run", {"name": "audited_loop", "timeout_s": 0.5})
    assert result["timed_out"] is True
    assert _audit_lines(audit)[-1] == (
        f"tool=script_run outcome=ok name='audited_loop' exit={result['exit']} timed_out=True"
    )
