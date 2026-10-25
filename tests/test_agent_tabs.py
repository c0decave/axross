"""The Agent dock's tabs: sessions kept as JSON, protection modes, keys,
attachments and a sandbox per tab.

The model is the scripted fake of test_agent_loop; the dialogs are
injected, so every path runs without a human.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QMimeData, Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import agent_settings as AGS  # noqa: E402
from core import llm_profiles as LP  # noqa: E402
from core.agent_sandbox import SandboxProfile  # noqa: E402
from core.agent_session import SessionStore  # noqa: E402
from tests.test_agent_loop import _call, _Fake  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def _no_proxy(monkeypatch):
    for name in (
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
    ):
        monkeypatch.delenv(name, raising=False)


class Env:
    def __init__(self, tmp_path):
        self.root = tmp_path / "work"
        self.root.mkdir()
        self.store_dir = tmp_path / "sessions"
        self.servers = []
        self.asked = []
        self.answer = True
        self.settings = AGS.AgentSettings()
        # The tests of the tools: axross functions on (core.agent_access has
        # the default, closed, and tests/test_agent_tab_access.py the switch).
        self.settings.access.axross_functions = True
        self.pane = {"selection": None, "folder": None}
        self.remote = []
        self.docks = []
        #: What the dock's agent_settings_saver was handed.
        self.saved = []
        #: No MCP servers found on this machine (tests/test_mcp_detect_ui.py sets one).
        self.mcp_detector = lambda **kw: __import__(
            "core.mcp_detect", fromlist=["DetectResult"]).DetectResult()

    def fake(self, *replies):
        server = _Fake(replies)
        self.servers.append(server)
        self.llm = LP.LLMSettings(
            [LP.LLMProfile(name="local", provider="lmstudio", endpoint=server.url, model="tiny")],
            "local",
        )
        return server

    def dock(self):
        from ui.agent_dock import AgentDock

        dock = AgentDock(
            settings_loader=lambda: self.llm,
            settings_saver=lambda s: None,
            key_lookup=lambda name: "",
            confirm_remote=lambda p, h: True,
            confirm_call=lambda n, a: self.asked.append((n, a)) or self.answer,
            root_provider=lambda: str(self.root),
            agent_settings_loader=lambda: self.settings,
            session_store=SessionStore(self.store_dir),
            pane_items=lambda kind: self.pane.get(kind),
            pane_backend=lambda pane_id: (
                ("sftp: alex@nas", False) if pane_id == "remote-pane" else (None, True)
            ),
            remote_backends=lambda: list(self.remote),
            mcp_pool=getattr(self, "mcp_pool", None),
            agent_settings_saver=self.saved.append,
            mcp_detector=self.mcp_detector,
        )
        self.docks.append(dock)
        return dock

    def close(self):
        for dock in self.docks:
            dock.shutdown()
            dock.deleteLater()
        APP.processEvents()
        for server in self.servers:
            server.close()


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    yield e
    e.close()


def wait_idle(tab, seconds=30.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        if not tab.busy():
            APP.processEvents()
            return
        time.sleep(0.01)
    raise AssertionError("the agent did not finish")


def say(tab, text):
    tab.input.setPlainText(text)
    tab.send()
    wait_idle(tab)


def _tools_of(request):
    return {t["function"]["name"] for t in request["tools"]}


# -- happy ---------------------------------------------------------------------


def test_happy_tabs_are_sessions_that_come_back_after_a_restart(env):
    server = env.fake({"content": "One."}, {"content": "Two."})
    dock = env.dock()
    tab = dock.current_tab()
    say(tab, "first question")
    second = dock.new_tab()
    say(second, "second question")
    files = sorted(env.store_dir.glob("*.json"))
    assert len(files) == 2
    data = [json.loads(f.read_text()) for f in files]
    assert {d["title"] for d in data} == {"first question", "second question"}
    dock.shutdown()

    reopened = env.dock()
    assert reopened.tabs.count() == 2
    titles = [reopened.tabs.tabText(i) for i in range(2)]
    assert titles == ["first question", "second question"]
    first = reopened.tabs.widget(0)
    assert "One." in first.transcript.toPlainText()
    server.replies.append({"content": "Three."})
    say(first, "and now?")
    roles = [m["role"] for m in server.requests[-1]["messages"]]
    assert roles == ["system", "user", "assistant", "user"]


def test_happy_plan_mode_reads_only_and_runs_the_plan_after_ok(env):
    server = env.fake(
        {"content": "1. write todo.txt with 'renew'"},
        {
            "tool_calls": [
                _call("write_file", {"path": str(env.root / "todo.txt"), "content": "renew"})
            ]
        },
        {"content": "Done."},
    )
    tab = env.dock().current_tab()
    tab.allow_write.setChecked(True)
    tab.mode_combo.setCurrentIndex(tab.mode_combo.findData("plan"))
    say(tab, "make a todo")
    assert "write_file" not in _tools_of(server.requests[0])
    assert "Plan mode" in server.requests[0]["messages"][0]["content"]
    assert tab.plan_button.isVisibleTo(tab)
    tab.run_plan()
    wait_idle(tab)
    assert (env.root / "todo.txt").read_text() == "renew"
    assert [n for n, _ in env.asked] == ["write_file"]  # back in Ask: it asked
    assert tab.session.mode == "ask"
    assert "write_file" in _tools_of(server.requests[1])


def test_happy_auto_mode_runs_changes_without_asking(env):
    env.fake(
        {"tool_calls": [_call("write_file", {"path": str(env.root / "a.txt"), "content": "x"})]},
        {"content": "ok"},
    )
    tab = env.dock().current_tab()
    tab.allow_write.setChecked(True)
    tab.mode_combo.setCurrentIndex(tab.mode_combo.findData("auto"))
    say(tab, "write")
    assert (env.root / "a.txt").read_text() == "x"
    assert env.asked == []
    assert "ran without asking" in tab.transcript.toPlainText()


def test_happy_ctrl_enter_sends_and_up_recalls_the_last_task(env):
    server = env.fake({"content": "a"}, {"content": "b"})
    tab = env.dock().current_tab()
    tab.show()
    tab.input.setPlainText("check the disk")
    QTest.keyClick(tab.input, Qt.Key.Key_Return, Qt.KeyboardModifier.ControlModifier)
    wait_idle(tab)
    assert server.requests and server.requests[0]["messages"][-1]["content"] == "check the disk"
    assert tab.input.toPlainText() == ""
    QTest.keyClick(tab.input, Qt.Key.Key_Up)
    assert tab.input.toPlainText() == "check the disk"


def test_happy_files_dropped_from_a_pane_become_attachments_the_agent_can_read(env, tmp_path):
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "report.txt").write_text("quarterly numbers")
    server = env.fake({"tool_calls": [_call("read_file", {"path": str(outside / "report.txt"),
                                                           "encoding": "text"})]},
                      {"content": "Read it."})
    tab = env.dock().current_tab()
    from ui.file_pane import TRANSFER_MIME_TYPE

    mime = QMimeData()
    mime.setData(
        TRANSFER_MIME_TYPE,
        json.dumps(
            {"paths": [str(outside / "report.txt")], "source_pane_id": "local-pane", "dirs": []}
        ).encode(),
    )
    tab.input.insertFromMimeData(mime)
    assert tab.chips_box.isVisibleTo(tab)
    say(tab, "summarise it")
    first = server.requests[0]["messages"][-1]["content"]
    assert str(outside / "report.txt") in first and first.endswith("summarise it")
    assert "quarterly numbers" in server.requests[1]["messages"][-1]["content"]
    assert tab.session.extra_folders == [(str(outside), False)]
    assert not tab.chips_box.isVisibleTo(tab)  # attachments go with the task


# -- sad -----------------------------------------------------------------------


def test_sad_auto_still_asks_before_a_remote_command(env):
    tab_env = env
    tab_env.settings.access.remote_commands = True
    env.fake(
        {"tool_calls": [_call("remote_exec", {"backend": "x", "command": "id"})]}, {"content": "ok"}
    )
    tab = env.dock().current_tab()
    tab._mode_of_run = "auto"
    assert tab._needs_user("remote_exec") is True
    assert tab._needs_user("write_file") is False


def test_sad_bypass_needs_the_setting_and_never_runs_in_paranoid(env, monkeypatch):
    env.fake({"content": "x"})
    tab = env.dock().current_tab()
    modes = [tab.mode_combo.itemData(i) for i in range(tab.mode_combo.count())]
    assert "bypass" not in modes
    env.settings.allow_bypass = True
    tab.dock.reload_settings()
    modes = [tab.mode_combo.itemData(i) for i in range(tab.mode_combo.count())]
    assert "bypass" in modes
    tab.mode_combo.setCurrentIndex(tab.mode_combo.findData("bypass"))
    assert tab.bypass_label.isVisibleTo(tab)
    tab._mode_of_run = "bypass"
    assert tab._needs_user("remote_exec") is False
    from core import security_mode

    monkeypatch.setattr(security_mode, "is_paranoid", lambda: True)
    assert tab._needs_user("remote_exec") is True  # paranoid: bypass is ignored
    tab.dock.reload_settings()
    modes = [tab.mode_combo.itemData(i) for i in range(tab.mode_combo.count())]
    assert "bypass" not in modes and tab.session.mode == "ask"


def test_sad_closing_a_tab_deletes_its_session_after_asking(env, monkeypatch):
    from PyQt6.QtWidgets import QMessageBox

    env.fake({"content": "x"})
    dock = env.dock()
    tab = dock.current_tab()
    say(tab, "hello")
    path = env.store_dir / f"{tab.session.id}.json"
    assert path.exists()
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.No)
    dock.close_tab(0)
    assert path.exists() and dock.tabs.count() == 1
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    dock.close_tab(0)
    assert not path.exists()
    assert dock.tabs.count() == 1 and dock.current_tab() is not tab  # a fresh tab


def test_sad_without_keep_tabs_nothing_is_written(env):
    env.settings.keep_sessions = False
    env.fake({"content": "x"})
    tab = env.dock().current_tab()
    say(tab, "hello")
    assert not env.store_dir.exists() or not list(env.store_dir.glob("*.json"))


# -- edge ----------------------------------------------------------------------


def test_edge_esc_stops_a_running_task(env):
    loop = {"tool_calls": [_call("stat", {"path": str(env.root)})]}
    env.fake(*[loop] * 60)
    tab = env.dock().current_tab()
    tab.show()
    tab.input.setPlainText("loop")
    tab.send()
    for _ in range(10):
        APP.processEvents()
        time.sleep(0.01)
    QTest.keyClick(tab.input, Qt.Key.Key_Escape)
    wait_idle(tab)
    assert "Stopped" in tab.transcript.toPlainText()


def test_edge_a_remote_attachment_names_its_backend(env):
    env.fake({"content": "x"})
    tab = env.dock().current_tab()
    tab._on_dropped(
        {"paths": ["/volume1/photos/a.jpg"], "source_pane_id": "remote-pane", "dirs": []}
    )
    assert "(backend \"sftp: alex@nas\")" in tab._context_text()
    assert tab.session.extra_folders == []  # nothing local to open up


def test_edge_the_plus_menu_attaches_the_pane_selection(env, tmp_path):
    (env.root / "a.txt").write_text("a")
    env.pane["selection"] = {"paths": [str(env.root / "a.txt")], "backend": None, "local": True}
    env.fake({"content": "x"})
    tab = env.dock().current_tab()
    tab.attach_from_pane("selection")
    assert tab._attachments[0]["path"] == str(env.root / "a.txt")
    assert tab.session.extra_folders == []  # inside the folder already


def test_edge_every_event_reaches_the_dock_signal(env):
    env.fake({"tool_calls": [_call("stat", {"path": str(env.root)})]}, {"content": "done"})
    dock = env.dock()
    seen = []
    dock.agent_event.connect(lambda sid, event: seen.append(event["type"]))
    say(dock.current_tab(), "go")
    assert seen[0] == "run_started" and seen[-1] == "run_finished"
    assert {"tool_call", "tool_result", "assistant"} <= set(seen)


def _bwrap_works() -> bool:
    if not shutil.which("bwrap"):
        return False
    return subprocess.run(["bwrap", "--unshare-all", "--ro-bind", "/", "/", "true"],
                          capture_output=True, timeout=20).returncode == 0


@pytest.mark.skipif(not _bwrap_works(), reason="bubblewrap cannot create a sandbox here")
def test_edge_a_tab_with_a_paranoid_sandbox_reads_but_cannot_write(env):
    (env.root / "notes.txt").write_text("in the sandbox")
    env.settings.sandboxes = [SandboxProfile(name="Locked", engine="bubblewrap", level="paranoid")]
    server = env.fake({"tool_calls": [_call("read_file", {"path": str(env.root / "notes.txt"),
                                                           "encoding": "text"})]},
                      {"content": "read"})
    tab = env.dock().current_tab()
    tab.sandbox_combo.setCurrentIndex(tab.sandbox_combo.findData("Locked"))
    assert not tab.allow_write.isEnabled()
    say(tab, "read notes")
    assert "in the sandbox" in server.requests[1]["messages"][-1]["content"]
    assert "write_file" not in _tools_of(server.requests[0])
    from core.agent_sandbox import SandboxedAgent

    assert isinstance(tab._agent, SandboxedAgent)


def test_sad_a_renamed_sandbox_profile_is_not_quietly_dropped(env):
    from core.agent_sandbox import SandboxProfile

    env.settings.sandboxes = [SandboxProfile(name="Paranoid", level="paranoid")]
    server = env.fake({"content": "never"})
    dock = env.dock()
    tab = dock.current_tab()
    tab.sandbox_combo.setCurrentIndex(tab.sandbox_combo.findData("Paranoid"))
    env.settings.sandboxes = [SandboxProfile(name="Paranoid (ro)", level="paranoid")]
    dock.reload_settings()
    assert tab.session.sandbox == "Paranoid" and tab.sandbox_combo.currentData() == "Paranoid"
    say(tab, "go")
    assert server.requests == [] and tab._agent is None
    assert (
        "Paranoid" in tab.transcript.toPlainText()
        and "no longer exists" in tab.transcript.toPlainText()
    )


def test_edge_two_questions_at_once_each_get_their_answer(env):
    """A dialog runs a nested event loop: a second question arriving while
    the first is open must not take the first one's answer."""
    import threading as th

    env.fake({"content": "ok"})
    dock = env.dock()
    tab = dock.current_tab()
    tab._mode_of_run = "ask"

    def slow_yes(name, args):
        end = time.monotonic() + 0.4
        while time.monotonic() < end:  # what a modal dialog does
            APP.processEvents()
            time.sleep(0.01)
        return name == "first"

    dock.confirm_call = slow_yes
    answers = {}
    threads = [th.Thread(target=lambda n=n: answers.__setitem__(n, tab._wait_for_answer(n, {})))
               for n in ("first", "second")]
    for t in threads:
        t.start()
        time.sleep(0.05)
    end = time.monotonic() + 5
    while any(t.is_alive() for t in threads) and time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.01)
    assert answers == {"first": True, "second": False}
