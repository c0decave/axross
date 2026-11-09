"""A tool failure answered as an isError result is an error for the agent.

The MCP server answers a failing tool with a result whose isError is true
(so the model sees why). The agent's callers - in process and in the
sandbox - only looked for a JSON-RPC error and counted such a result as
"ok": in the run's outcomes, the transcript and the audit log (a refused
host copy into the local files read as done).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import agent as A  # noqa: E402
from core.llm_profiles import LLMProfile  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_agent_remote import _Fake, _call  # noqa: E402


@pytest.fixture
def server():
    made = []

    def make(*replies):
        made.append(_Fake(replies))
        return made[-1]
    yield make
    for s in made:
        s.close()


def _agent(srv, root, events):
    profile = LLMProfile(name="local", provider="lmstudio", endpoint=srv.url, model="tiny")
    return A.Agent(A.AgentConfig(profile=profile, root=str(root)), on_event=events.append)


def test_sad_a_failing_tool_is_an_error_not_ok(server, tmp_path):
    srv = server({"tool_calls": [_call("read_file", {"path": str(tmp_path / "missing.txt"),
                                                     "encoding": "text"})]},
                 {"content": "done"})
    events: list = []
    agent = _agent(srv, tmp_path, events)
    result = agent.run("read it")
    assert result.calls[0]["outcome"] == "error"
    shown = [e for e in events if e.get("type") == "tool_result"]
    assert shown and shown[0]["outcome"] == "error"


def test_happy_a_working_tool_stays_ok(server, tmp_path):
    (tmp_path / "here.txt").write_text("hello", encoding="utf-8")
    srv = server({"tool_calls": [_call("read_file", {"path": str(tmp_path / "here.txt"),
                                                     "encoding": "text"})]},
                 {"content": "done"})
    events: list = []
    result = _agent(srv, tmp_path, events).run("read it")
    assert result.calls[0]["outcome"] == "ok"
