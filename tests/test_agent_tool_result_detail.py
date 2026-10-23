"""A refused or failed tool call says why in the Agent dock's transcript.

The transcript showed "← remote_exec: error" and nothing else: the
tool_result event carried the outcome and a reason category, never the
tool's own text - and that is where the reason is ("error: this sandbox
reaches no remote host", "error: [Errno 2] No such file ..."). The event
now carries the first line of that text for every outcome but "ok" (an ok
result is file contents or command output and stays out of the
transcript), bounded and stripped of control characters, also across the
sandbox worker's event filter.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import agent as A  # noqa: E402
from core import agent_sandbox as SB  # noqa: E402
from tests.test_agent_files_read_only import _config, _Script  # noqa: E402
from tests.test_agent_loop import _call  # noqa: E402
from tests.test_agent_tabs import env  # noqa: E402,F401 - the dock fixture


def _results(tmp_path, *calls, confirm=True, **config):
    events = []
    A.Agent(_config(tmp_path, **config), transport=_Script(list(calls)),
            confirm=lambda *_: confirm, on_event=events.append).run("go")
    return [e for e in events if e["type"] == "tool_result"]


# --- happy ----------------------------------------------------------------


def test_happy_an_error_says_its_first_line(tmp_path):
    [result] = _results(tmp_path, _call("read_file", {"path": str(tmp_path / "missing.txt")}, "r1"))
    assert result["outcome"] == "error"
    assert result["detail"].startswith("error:")
    assert "missing.txt" in result["detail"]


def test_happy_a_refusal_says_why(tmp_path):
    (tmp_path / "keep.txt").write_text("x")
    [result] = _results(tmp_path, _call("write_file", {"path": str(tmp_path / "keep.txt"),
                                                       "content": "y"}, "w1"),
                        files_read_only=True)
    assert result["outcome"] == "unavailable" and result["detail"]


def test_happy_e2e_the_dock_shows_the_reason(env):
    env.fake()
    dock = env.dock()
    tab = dock.current_tab() or dock.new_tab()
    tab._on_event({"type": "tool_result", "name": "remote_exec", "outcome": "error",
                   "reason": "", "detail": "error: this sandbox reaches no remote host"})
    text = tab.transcript.toPlainText()
    assert "remote_exec: error - error: this sandbox reaches no remote host" in text


# --- sad ------------------------------------------------------------------


def test_sad_an_ok_result_carries_no_text(tmp_path):
    # File contents and command output never go into the transcript.
    (tmp_path / "a.txt").write_text("secret contents")
    [result] = _results(tmp_path, _call("read_file", {"path": str(tmp_path / "a.txt")}, "r1"))
    assert result["outcome"] == "ok"
    assert "detail" not in result or result["detail"] == ""


def test_sad_the_sandbox_filter_drops_a_detail_that_is_no_text():
    out = SB._clean_event({"type": "tool_result", "name": "x", "outcome": "error",
                           "detail": {"evil": 1}})
    assert out["detail"] == ""


def test_sad_markup_in_a_detail_is_shown_literally(env):
    env.fake()
    dock = env.dock()
    tab = dock.current_tab() or dock.new_tab()
    tab._on_event({"type": "tool_result", "name": "x", "outcome": "error",
                   "detail": "error: <b>bold</b> & <script>"})
    assert "<b>bold</b> & <script>" in tab.transcript.toPlainText()


# --- edge -----------------------------------------------------------------


def test_edge_a_long_multi_line_text_is_cut_to_its_first_line():
    assert A.tool_result_detail("error", "error: first\nsecond\nthird") == "error: first"
    long = A.tool_result_detail("error", "error: " + "x" * 5000)
    assert len(long) <= A.MAX_TOOL_DETAIL and long.endswith("…")


def test_edge_control_characters_are_removed():
    assert A.tool_result_detail("declined", "declined:\x1b[31m red\x07 ‮evil") == \
        "declined: red evil"


def test_edge_the_sandbox_filter_bounds_and_cleans_the_detail():
    out = SB._clean_event({"type": "tool_result", "name": "x", "outcome": "error",
                           "detail": "error: " + "y" * 5000 + "\nmore"})
    assert len(out["detail"]) <= A.MAX_TOOL_DETAIL and "\n" not in out["detail"]
    ok = SB._clean_event({"type": "tool_result", "name": "x", "outcome": "ok",
                          "detail": "should not travel"})
    assert ok["detail"] == ""


def test_edge_an_old_event_without_detail_still_shows(env):
    # A session saved by an older version, or a worker without the field.
    env.fake()
    dock = env.dock()
    tab = dock.current_tab() or dock.new_tab()
    tab._on_event({"type": "tool_result", "name": "list_dir", "outcome": "error"})
    assert "list_dir: error" in tab.transcript.toPlainText()
