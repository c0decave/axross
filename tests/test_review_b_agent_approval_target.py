"""Review B, items 12 and 1 (Ask mode): the agent's approval shows where a
write really goes.

12 - approving ``proj/NOTES.md`` overwrote the file its symlink points to
(``Documents/thesis.txt``): the question showed the model's path only. Now
the question shows the resolved target, and a target that changed between
the question and the write is refused.
1 - a file of a host-run MCP server's folder: the question says that it
belongs to that server, which runs on this machine.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import agent as A  # noqa: E402
from core.llm_profiles import LLMProfile  # noqa: E402


@pytest.fixture
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    root = tmp_path / "root"
    (root / "Documents").mkdir(parents=True)
    (root / "proj").mkdir()
    (root / "Documents" / "thesis.txt").write_text("three years of work\n")
    os.symlink("../Documents/thesis.txt", root / "proj" / "NOTES.md")
    return root


def _agent(root, confirm):
    agent = A.Agent(A.AgentConfig(profile=LLMProfile(name="x"), root=str(root), allow_write=True),
                    confirm=confirm)
    agent._ensure_built()
    return agent


def _write(path, content="# notes\n"):
    return {"function": {"name": "write_file", "arguments": json.dumps(
        {"path": str(path), "content": content})}}


def test_sad_the_question_names_the_symlinks_target(root):
    shown = []
    agent = _agent(root, lambda n, a: shown.append(dict(a)) or False)
    agent._run_tool(_write(root / "proj" / "NOTES.md"))
    text = json.dumps(shown, ensure_ascii=False)
    assert str(root / "Documents" / "thesis.txt") in text
    assert (root / "Documents" / "thesis.txt").read_text() == "three years of work\n"


def test_sad_a_target_changed_after_the_question_is_refused(root):
    other = root / "Documents" / "other.txt"
    other.write_text("keep me\n")

    def confirm(name, args):
        os.unlink(root / "proj" / "NOTES.md")
        os.symlink("../Documents/other.txt", root / "proj" / "NOTES.md")
        return True

    agent = _agent(root, confirm)
    _name, outcome, text = agent._run_tool(_write(root / "proj" / "NOTES.md"))
    assert outcome != "ok" and "changed" in text
    assert other.read_text() == "keep me\n"
    assert (root / "Documents" / "thesis.txt").read_text() == "three years of work\n"


def test_happy_a_plain_file_is_asked_as_it_is_and_written(root):
    shown = []
    agent = _agent(root, lambda n, a: shown.append(dict(a)) or True)
    target = root / "proj" / "plain.md"
    _name, outcome, _text = agent._run_tool(_write(target))
    assert outcome == "ok" and target.read_text() == "# notes\n"
    assert shown[0]["path"] == str(target)


def test_sad_a_file_of_a_host_run_mcp_server_says_so(root, tmp_path, monkeypatch):
    from core import mcp_client as C
    from core import mcp_runner as R
    from core import mcp_script_pin as PIN
    from core.agent_settings import AgentSettings

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "home" / ".local" / "state"))
    monkeypatch.setattr(R, "launcher_place_problem", lambda *a, **k: "")
    server = root / "srv" / "server.py"
    server.parent.mkdir()
    server.write_text("print(1)\n")
    settings = AgentSettings()
    settings.mcp_servers = [C.McpServerConfig(name="my-tools", enabled=False, command=(
        os.path.realpath(sys.executable), str(server)))]
    settings.save()
    PIN._GUARD_CACHE.clear()
    shown = []
    agent = _agent(root, lambda n, a: shown.append(dict(a)) or False)
    agent._run_tool(_write(root / "srv" / "helper.py"))
    text = json.dumps(shown, ensure_ascii=False)
    assert "my-tools" in text and "runs on this machine" in text


def test_happy_the_dialog_says_the_note_in_its_text():
    import os as _os

    _os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PyQt6.QtWidgets import QApplication

    from ui import agent_dock as D

    _app = QApplication.instance() or QApplication([])  # noqa: F841
    box = D.call_box(None, "write_file", {"path": "a → b", "content": "x",
                                          A.APPROVAL_NOTE: "a is a link: the call changes b."})
    try:
        assert "the call changes b" in box.text()
        assert A.APPROVAL_NOTE not in box.detailedText()
    finally:
        box.deleteLater()
