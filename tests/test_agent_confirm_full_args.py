"""The agent's confirmation shows all of what the user allows.

The model (or a prompt hidden in a file it read) chooses a tool call's
arguments. Every string argument longer than 200 characters was cut
before the confirmation - the dialog, its preview and its Show Details
alike - so a command padded with spaces past the cut, a script or a
file's content had a tail the user approved without any way to see it:
``ls -la /var/log`` + 200 spaces + ``; curl … | sh`` asked as
``ls -la /var/log      … (243 characters)``.

The transcript still shows the cut form; the question shows the whole
arguments (secrets of the schema still masked), with a preview that says
when it is cut.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import agent as A  # noqa: E402
from core.llm_profiles import LLMProfile  # noqa: E402
from tests.test_agent_loop import _call, _Fake  # noqa: E402

#: A command whose dangerous part sits past the transcript's cut.
PADDED = "ls -la /var/log" + " " * 200 + "; rm -rf ~/projects"


_APP = []


def _dock_module():
    pytest.importorskip("PyQt6.QtWidgets")
    from PyQt6.QtWidgets import QApplication

    if not _APP:
        _APP.append(QApplication.instance() or QApplication([]))
    from ui import agent_dock

    return agent_dock


@pytest.fixture(autouse=True)
def _no_proxy(monkeypatch):
    for name in ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY",
                 "ALL_PROXY"):
        monkeypatch.delenv(name, raising=False)


def _external_tool(seen: list) -> A.FunctionTool:
    return A.FunctionTool(
        name="ext_shell__run", description="", write=True,
        handler=lambda args: seen.append(args) or "ran",
        schema={"type": "object", "properties": {
            "command": {"type": "string"},
            "token": {"type": "string", "writeOnly": True}}})


def test_sad_a_padded_command_is_asked_for_in_full(tmp_path):
    """The confirmation of an external tool gets the whole command; only
    the schema's secret stays masked."""
    server = _Fake([{"tool_calls": [_call("ext_shell__run",
                                          {"command": PADDED, "token": "s3cret"})]},
                    {"content": "done"}])
    asked, ran, events = [], [], []
    try:
        config = A.AgentConfig(
            profile=LLMProfile(name="l", provider="lmstudio", endpoint=server.url, model="m"),
            root=str(tmp_path), external_tools=lambda: ([_external_tool(ran)], []))
        A.Agent(config, confirm=lambda n, a: asked.append(a) or True,
                on_event=events.append).run("list the logs")
    finally:
        server.close()
    assert asked == [{"command": PADDED, "token": "•••"}]
    # The transcript keeps its short form.
    call = next(e for e in events if e.get("type") == "tool_call")
    assert call["args"]["command"].endswith("(234 characters)")


def test_happy_the_transcript_form_is_still_cut():
    assert A._shown({"c": PADDED}, {})["c"] != PADDED
    assert A._shown({"c": PADDED}, {}, cut=False)["c"] == PADDED
    assert A._shown({"c": PADDED}, {"properties": {"c": {"writeOnly": True}}},
                    cut=False) == {"c": "•••"}


def test_sad_the_question_box_hides_no_part_of_the_arguments():
    """The dialog's details hold all of it, and its preview says when it is
    cut rather than ending mid-argument without a word."""
    D = _dock_module()

    box = D.call_box(None, "remote_exec", {"backend": "pane:prod", "command": PADDED})
    try:
        assert PADDED in box.detailedText().replace("\\n", "\n")
        assert "rm -rf ~/projects" in box.detailedText()
        box_short = D.call_box(None, "write_file", {"path": "a.txt", "content": "hi"})
        assert "cut" not in box_short.informativeText()
        box_short.deleteLater()
        long_args = {"command": "x" * 1000 + "; rm -rf ~"}
        long_box = D.call_box(None, "remote_exec", long_args)
        assert "Show Details" in long_box.informativeText()
        assert "rm -rf ~" in long_box.detailedText()
        long_box.deleteLater()
    finally:
        box.deleteLater()


def test_sad_the_dock_asks_with_the_whole_arguments():
    """The in-process agent's question reaches the dock's dialog uncut."""
    D = _dock_module()

    asked = []

    class _Dock:
        def confirm_call(self, name, args):
            asked.append((name, args))
            return False

        def emit_event(self, *_a):
            pass

    import threading

    tab = D.AgentTab.__new__(D.AgentTab)
    tab._pending = []
    tab._cancel = threading.Event()
    tab._agent = None
    tab.dock = _Dock()
    pending = {"done": threading.Event(), "yes": True}
    tab._on_confirm("remote_exec", {"command": PADDED}, pending)
    assert asked == [("remote_exec", {"command": PADDED})]
    assert pending["done"].is_set() and pending["yes"] is False
