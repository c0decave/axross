"""The Agent dock against a REAL LLM server - opt-in, never in the normal run.

The unit tests talk to fake servers only: a profile endpoint typed
without /v1 broke LM Studio (fixed in 0.13.29) and none of them saw it.
This module drives every Agent dock function against a real server.

Run it with the server named in ``AXROSS_LIVE_LLM``::

    AXROSS_LIVE_LLM="lmstudio|http://192.168.1.10:1234|qwen3.6-35b-a3b-mlx@4bit"
    AXROSS_LIVE_LLM="ollama|http://127.0.0.1:11434|qwen2.5:1.5b"
    AXROSS_LIVE_LLM="openai|http://127.0.0.1:8000|Qwen/Qwen2.5-0.5B-Instruct"

The real MainWindow and AgentDock run offscreen; profiles are made in the
real LLM Profiles dialog, tasks are typed into the tab and sent with
Ctrl+Enter, confirmations are answered by clicking the real dialogs. The
tests assert outcomes - files on disk, refused writes, the tools the model
called and how they ended, saved session files - never the model's wording
beyond a random marker it can only know from a tool. A model that does not
call a tool at all is a model weakness, not an axross defect: such a test
fails with the transcript, so the run says which it was.

``AXROSS_LIVE_LLM_WAIT`` (seconds, default 600) bounds one task. Remote
commands need the lab's ssh-alpha (10.99.0.10:22, ``podman unshare
--rootless-netns``); without it those tests are skipped.
"""

from __future__ import annotations

import json
import os
import secrets
import socket
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

LIVE = os.environ.get("AXROSS_LIVE_LLM", "")
pytestmark = pytest.mark.skipif(
    not LIVE, reason='live LLM run: set AXROSS_LIVE_LLM="provider|endpoint|model"'
)
PROVIDER, ENDPOINT, MODEL = (LIVE.split("|") + ["", "", ""])[:3]
WAIT = float(os.environ.get("AXROSS_LIVE_LLM_WAIT", "600"))
PROFILE = f"live-{PROVIDER or 'none'}"
SSH_HOST, SSH_PORT, SSH_USER, SSH_PASS = "10.99.0.10", 22, "alpha", "alpha123"

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QPoint, Qt, QTimer  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import (  # noqa: E402
    QApplication,
    QInputDialog,
    QMessageBox,
    QPushButton,
)

APP = QApplication.instance() or QApplication([])
#: One line per task: (test, seconds, tool calls, outcome) for EVIDENCE.md.
TIMINGS: list[tuple] = []


def pump(seconds: float = 0.05) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.01)


def wait_until(cond, timeout: float) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.02)
    return bool(cond())


def _reachable(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def _base_endpoint() -> str:
    """The endpoint as an operator types it: without /v1."""
    base = ENDPOINT.rstrip("/")
    return base[: -len("/v1")] if base.endswith("/v1") else base


def _marker(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(4)}"


# -- the dialogs, clicked like a person -----------------------------------------------------


class Dialogs:
    """Answers the dock's dialogs as they open: the confirmation of a tool
    call (Yes or No as told), the agent's question (a typed answer) and the
    remote-LLM consent. Records each one."""

    def __init__(self) -> None:
        self.confirm_yes = True
        self.answer_text = ""
        self.seen: list[dict] = []
        self._timer = QTimer()
        self._timer.setInterval(50)
        self._timer.timeout.connect(self._scan)
        self._timer.start()

    def of(self, title: str) -> list[dict]:
        return [d for d in self.seen if d["title"] == title]

    def _scan(self) -> None:
        for widget in QApplication.topLevelWidgets():
            if not widget.isVisible() or getattr(widget, "_live_answered", False):
                continue
            if isinstance(widget, QMessageBox):
                title = widget.windowTitle()
                entry = {"title": title, "text": widget.text(), "details": widget.detailedText()}
                if title == "Allow this action?":
                    entry["yes"] = self.confirm_yes
                    button = QMessageBox.StandardButton.Yes if self.confirm_yes \
                        else QMessageBox.StandardButton.No
                elif title.startswith("Send "):  # remote LLM / remote voice consent
                    entry["yes"] = True
                    button = QMessageBox.StandardButton.Yes
                else:
                    continue
                widget._live_answered = True
                self.seen.append(entry)
                widget.button(button).click()
            elif isinstance(widget, QInputDialog) and widget.windowTitle() == "The agent asks":
                widget._live_answered = True
                self.seen.append({"title": "The agent asks", "text": widget.labelText()})
                widget.setTextValue(self.answer_text)
                widget.accept()

    def stop(self) -> None:
        self._timer.stop()


# -- one task ---------------------------------------------------------------------------------


@dataclass
class Run:
    calls: list = field(default_factory=list)      # (name, args)
    results: list = field(default_factory=list)    # (name, outcome)
    answers: list = field(default_factory=list)    # the assistant texts
    finished: dict = field(default_factory=dict)
    seconds: float = 0.0
    transcript: str = ""

    @property
    def answer(self) -> str:
        return "\n".join(self.answers)

    def outcomes(self, name: str) -> list[str]:
        return [o for n, o in self.results if n == name]

    def summary(self) -> str:
        return (f"calls={[(n, a) for n, a in self.calls]} results={self.results} "
                f"finished={self.finished} answer={self.answer[:600]!r}\n"
                f"transcript:\n{self.transcript[-3000:]}")


class Live:
    def __init__(self, win, dialogs: Dialogs, work_root: Path) -> None:
        self.win = win
        self.dock = win._agent_dock
        self.dialogs = dialogs
        self.work_root = work_root
        self.events: list[tuple[str, dict]] = []
        self.dock.agent_event.connect(lambda sid, event: self.events.append((sid, dict(event))))

    def folder(self, name: str) -> Path:
        path = self.work_root / f"{name}-{secrets.token_hex(3)}"
        path.mkdir(parents=True)
        return path

    def local_pane(self):
        """The first pane on local files, made the active one."""
        from core.local_fs import LocalFS

        pane = next(p for p in self.win._panes if isinstance(p.backend, LocalFS))
        self.win._set_active_pane(pane)
        return pane

    def start_agent(self, folder: Path):
        """Tools > Start Agent with the active pane on *folder*."""
        self.local_pane().navigate(str(folder))
        pump(0.3)
        action = _menu_action(self.win, "Tools", "Start Agent")
        action.trigger()
        pump(0.2)
        tab = self.dock.current_tab()
        assert tab.root_edit.text() == str(folder)
        _choose_profile(tab)
        return tab

    def send(self, tab, text: str, *, name: str, stop_after: float | None = None) -> Run:
        """Type *text* into the tab and press Ctrl+Enter; wait for the end."""
        start = len(self.events)
        sid = tab.session.id
        tab.input.setFocus()
        tab.input.setPlainText(text)
        began = time.monotonic()
        QTest.keyClick(tab.input, Qt.Key.Key_Return, Qt.KeyboardModifier.ControlModifier)
        if stop_after is not None:
            wait_until(lambda: False, stop_after)
            QTest.mouseClick(tab.stop_button, Qt.MouseButton.LeftButton)

        def finished() -> bool:
            return any(s == sid and e.get("type") == "run_finished" for s, e in self.events[start:])

        done = wait_until(finished, WAIT)
        run = Run(seconds=round(time.monotonic() - began, 1))
        for s, event in self.events[start:]:
            if s != sid:
                continue
            kind = event.get("type")
            if kind == "tool_call":
                run.calls.append((event.get("name"), event.get("args") or {}))
            elif kind == "tool_result":
                run.results.append((event.get("name"), event.get("outcome")))
            elif kind == "assistant":
                run.answers.append(str(event.get("text") or ""))
            elif kind == "run_finished":
                run.finished = event
        run.transcript = tab.transcript.toPlainText()
        TIMINGS.append((name, run.seconds, len(run.calls), run.finished.get("stopped"),
                        run.finished.get("error")))
        assert done, f"the task did not end within {WAIT} s: {run.summary()}"
        assert not run.finished.get("error"), run.summary()
        return run


def _menu_action(win, menu_title: str, text: str):
    for action in win.menuBar().actions():
        if action.text().replace("&", "") == menu_title:
            for sub in action.menu().actions():
                if sub.text().replace("&", "") == text:
                    return sub
    raise AssertionError(f"no {menu_title} > {text}")


def _choose_profile(tab) -> None:
    index = tab.model_combo.findData(PROFILE)
    assert index >= 0, [tab.model_combo.itemText(i) for i in range(tab.model_combo.count())]
    tab.model_combo.setCurrentIndex(index)
    pump(0.05)
    assert tab.profile() is not None and tab.profile().name == PROFILE


def _set_mode(tab, mode: str) -> None:
    tab.mode_combo.setCurrentIndex(tab.mode_combo.findData(mode))
    pump(0.05)
    assert tab.session.mode == mode


def _click_box(box) -> None:
    """Click a check box on its indicator: a click on the empty right part
    of a wide box does not toggle it (QCheckBox.hitButton)."""
    QTest.mouseClick(box, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier,
                     QPoint(6, box.height() // 2))
    pump(0.05)


def _tick(tab, box, on: bool = True) -> None:
    if not tab.tools_button.isChecked():
        QTest.mouseClick(tab.tools_button, Qt.MouseButton.LeftButton)
        pump(0.1)
    assert box.isEnabled(), box.toolTip()
    if box.isChecked() != on:
        _click_box(box)
    assert box.isChecked() == on


# -- the window -------------------------------------------------------------------------------


EXTENSION = '''
EXTENSION = {"name": "Livext", "version": "1.0", "description": "live agent test"}
CALLS = []

def activate(api):
    api.add_agent_tool("vault_code", "Return the code stored under a name.",
                       lambda args: CALLS.append(args) or {"code": "SECRET_CODE"},
                       parameters={"name": {"type": "string"}}, required=("name",))
    api.add_agent_topic("Live vault", "Call the tool that returns the code stored under the "
                        "name {folder} and answer with the code only.", description="live test")
'''


@pytest.fixture(scope="module")
def live(tmp_path_factory):
    from core import agent_settings as AGS
    from core import extensions as EX

    work_root = tmp_path_factory.mktemp("agentlive")
    # axross functions on (the extension's tools and remote commands need
    # them); the rest as a fresh install has it.
    AGS.AgentSettings(access=AGS.Access(axross_functions=True, remote_commands=True,
                                        remote_files=True)).save()
    folder = EX.extensions_dir()
    folder.mkdir(parents=True, exist_ok=True)
    ext_code = _marker("EXT")
    (folder / "livext.py").write_text(EXTENSION.replace("SECRET_CODE", ext_code))
    EX.set_enabled("user:livext", True)
    EX.set_enabled("bundled:agent_stats", True)

    from ui.main_window import MainWindow

    win = MainWindow()
    win._reconnect_timer.stop()
    win.resize(1400, 900)
    win.show()
    pump(0.5)
    dialogs = Dialogs()
    state = Live(win, dialogs, work_root)
    state.ext_code = ext_code
    yield state
    dialogs.stop()
    win._agent_dock.shutdown()
    win.close()
    win.deleteLater()
    pump(0.2)
    _write_timings()


def _write_timings() -> None:
    out = os.environ.get("AXROSS_LIVE_LLM_TIMINGS")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            for row in TIMINGS:
                fh.write(json.dumps({"server": LIVE, "test": row[0], "seconds": row[1],
                                     "tool_calls": row[2], "stopped": row[3],
                                     "error": row[4]}) + "\n")


# -- 1. the profile: made in the LLM Profiles dialog, models fetched ------------------------


def _fetch(dialog, endpoint: str) -> list[str]:
    dialog.endpoint_edit.clear()
    QTest.keyClicks(dialog.endpoint_edit, endpoint)
    button = next(b for b in dialog.findChildren(QPushButton) if b.text() == "Fetch models")
    QTest.mouseClick(button, Qt.MouseButton.LeftButton)
    assert wait_until(lambda: "model(s) on the server" in dialog.status_label.text()
                      or "failed" in dialog.status_label.text(), 30), dialog.status_label.text()
    assert "failed" not in dialog.status_label.text(), dialog.status_label.text()
    return [dialog.model_combo.itemText(i) for i in range(dialog.model_combo.count())]


def test_happy_profile_made_in_the_dialog_fetches_models_with_and_without_v1(live):
    from core import llm_profiles as LP
    from ui.llm_settings_dialog import LLMSettingsDialog

    dialog = LLMSettingsDialog(live.win)
    try:
        QTest.mouseClick(next(b for b in dialog.findChildren(QPushButton) if b.text() == "Add"),
                         Qt.MouseButton.LeftButton)
        QTest.keyClicks(dialog.name_edit, PROFILE)
        dialog.provider_combo.setCurrentText(PROVIDER)
        bare = _fetch(dialog, _base_endpoint())
        assert MODEL in bare, bare
        with_v1 = _fetch(dialog, _base_endpoint() + "/v1")
        assert MODEL in with_v1 and sorted(with_v1) == sorted(bare)
        # The operator types it without /v1: that is what is saved.
        _fetch(dialog, _base_endpoint())
        dialog.model_combo.setEditText(MODEL)
        dialog.advanced_button.setChecked(True)
        dialog.timeout_spin.setValue(int(WAIT))
        assert dialog.save()
    finally:
        dialog.deleteLater()
    saved = LP.LLMSettings.load()
    profile = saved.profile(PROFILE)
    assert profile is not None and profile.model == MODEL
    assert profile.endpoint == _base_endpoint() and saved.active == PROFILE
    live.win.refresh_llm_profiles()
    pump(0.1)


def test_edge_a_lan_or_loopback_server_asks_no_consent(live):
    from core import llm_profiles as LP

    profile = LP.LLMSettings.load().profile(PROFILE)
    assert profile is not None
    assert not profile.is_remote() and not profile.needs_consent(), profile.host()


# -- 2. Start Agent, New Agent Tab Here: the model knows the folder -------------------------


def test_happy_start_agent_the_model_knows_its_folder(live):
    folder = live.folder("start")
    tab = live.start_agent(folder)
    run = live.send(tab, "Without calling any tool: what is the absolute path of the folder "
                         "you work in? Answer with the path only.", name="folder-known")
    assert str(folder) in run.answer, run.summary()
    assert not live.dialogs.of("Send file content to a remote LLM?")


def test_happy_new_agent_tab_here_reads_the_folder(live):
    folder = live.folder("here")
    marker = _marker("file")
    (folder / f"{marker}.txt").write_text("x")
    pane = live.local_pane()
    pane.navigate(str(folder))
    pump(0.3)
    menu = pane._build_context_menu()
    next(a for a in menu.actions() if a.text() == "New Agent Tab Here").trigger()
    pump(0.2)
    tab = live.dock.current_tab()
    assert tab.root_edit.text() == str(folder)
    _choose_profile(tab)
    run = live.send(tab, "Use the list_dir tool on the folder you work in and answer with the "
                         "names of the files in it.", name="list-dir")
    assert "ok" in run.outcomes("list_dir"), run.summary()
    assert marker in run.answer, run.summary()


# -- 3. read, continue, new settings, sessions ---------------------------------------------


@pytest.fixture(scope="module")
def reading(live):
    """A tab that read a code out of a file: later tests continue it."""
    folder = live.folder("read")
    code = _marker("CODE")
    (folder / "notes.txt").write_text(f"Some notes.\nThe code is {code}.\nEnd.\n")
    tab = live.start_agent(folder)
    run = live.send(tab, "Read the file notes.txt in the folder you work in with the read_file "
                         "tool and answer with the code written in it.", name="read-file")
    return tab, code, run


def test_happy_a_read_task_reads_the_file(reading):
    _tab, code, run = reading
    assert "ok" in run.outcomes("read_file"), run.summary()
    assert code in run.answer, run.summary()


def test_happy_the_conversation_continues(live, reading):
    tab, code, _run = reading
    before = len(tab.session.messages)
    run = live.send(tab, "Without calling any tool: which code did you read a moment ago? "
                         "Answer with the code only.", name="continue")
    assert code in run.answer, run.summary()
    assert len(tab.session.messages) > before


def test_edge_new_settings_mid_conversation_keep_the_conversation(live, reading):
    tab, code, _run = reading
    _tick(tab, tab.allow_write, True)
    run = live.send(tab, "Without calling any tool: repeat the code you read from notes.txt. "
                         "Answer with the code only.", name="new-settings")
    assert "New settings: the conversation continues with them." in run.transcript
    assert code in run.answer, run.summary()
    _tick(tab, tab.allow_write, False)


def _plain(content: str) -> str:
    """A read_file result as text: a model that leaves out encoding "text"
    gets content_b64."""
    import base64

    try:
        encoded = json.loads(content).get("content_b64")
        return content + base64.b64decode(encoded).decode("utf-8", "replace")
    except (ValueError, TypeError, AttributeError):
        return content


def test_happy_the_session_is_saved_and_comes_back(live, reading):
    from core.agent_session import SessionStore
    from ui.agent_dock import AgentDock

    tab, code, _run = reading
    path = SessionStore().path(tab.session.id)
    assert path.is_file() and oct(path.stat().st_mode & 0o777) == "0o600"
    data = json.loads(path.read_text())
    assert any(code in str(e.get("text")) for e in data["transcript"])
    assert any(m.get("role") == "tool" and code in _plain(str(m.get("content")))
               for m in data["messages"]), "the tool result the model saw is kept"
    # A new dock - as at the next start - brings the tab back, and its model
    # continues from the saved conversation.
    again = AgentDock(None, root_provider=lambda: str(live.work_root))
    try:
        restored = next(t for t in again.all_tabs() if t.session.id == tab.session.id)
        assert code in restored.transcript.toPlainText()
        _choose_profile(restored)
        again.agent_event.connect(lambda sid, e: live.events.append((sid, dict(e))))
        run = live.send(restored, "Without calling any tool: which code did you read from "
                                  "notes.txt? Answer with the code only.", name="restored")
        assert code in run.answer, run.summary()
    finally:
        again.shutdown()
        again.deleteLater()
        pump(0.1)


# -- 4. writing: Allow changes asks; Yes writes, No does not; Files read-only ----------------


def test_happy_a_write_with_yes_writes_the_file(live):
    folder = live.folder("write-yes")
    tab = live.start_agent(folder)
    _tick(tab, tab.allow_write, True)
    word = _marker("hello")
    live.dialogs.confirm_yes = True
    asked = len(live.dialogs.of("Allow this action?"))
    run = live.send(tab, f"Create the file {folder}/greeting.txt with the write_file tool; its "
                         f"text content is exactly: {word}", name="write-yes")
    confirms = live.dialogs.of("Allow this action?")[asked:]
    assert confirms and "write_file" in confirms[0]["text"], run.summary()
    assert (folder / "greeting.txt").is_file(), run.summary()
    assert word in (folder / "greeting.txt").read_text()
    assert "ok" in run.outcomes("write_file")


def test_sad_a_write_with_no_writes_nothing(live):
    folder = live.folder("write-no")
    tab = live.start_agent(folder)
    _tick(tab, tab.allow_write, True)
    live.dialogs.confirm_yes = False
    asked = len(live.dialogs.of("Allow this action?"))
    try:
        run = live.send(tab, f"Create the file {folder}/refused.txt with the write_file tool; "
                             "its text content is: no", name="write-no")
    finally:
        live.dialogs.confirm_yes = True
    assert live.dialogs.of("Allow this action?")[asked:], run.summary()
    assert not (folder / "refused.txt").exists()
    assert "declined" in run.outcomes("write_file"), run.summary()
    assert "ok" not in run.outcomes("write_file")


def test_sad_files_read_only_refuses_the_write_without_asking(live):
    folder = live.folder("read-only")
    tab = live.start_agent(folder)
    _tick(tab, tab.allow_write, True)
    _click_box(tab.read_only_check)
    assert tab.read_only_check.isChecked() and not tab.allow_write.isEnabled()
    asked = len(live.dialogs.of("Allow this action?"))
    run = live.send(tab, f"Create the file {folder}/blocked.txt with the write_file tool; its "
                         "text content is: blocked", name="read-only")
    assert not (folder / "blocked.txt").exists()
    assert live.dialogs.of("Allow this action?")[asked:] == [], "nothing to confirm"
    assert "write_file" not in tab._agent._tools, "no write tool is offered"
    assert set(run.outcomes("write_file")) <= {"unavailable", "declined"}


# -- 5. plan mode, Run this plan --------------------------------------------------------------


def test_happy_plan_mode_only_plans_then_run_this_plan_writes(live):
    folder = live.folder("plan")
    tab = live.start_agent(folder)
    _tick(tab, tab.allow_write, True)
    _set_mode(tab, "plan")
    assert not tab.allow_write.isEnabled()
    word = _marker("planned")
    run = live.send(tab, f"Create the file {folder}/plan.txt whose text content is exactly: "
                         f"{word}", name="plan")
    assert not (folder / "plan.txt").exists(), run.summary()
    assert "write_file" not in tab._agent._tools
    assert tab.plan_button.isVisible(), run.summary()
    live.dialogs.confirm_yes = True
    start = len(live.events)
    QTest.mouseClick(tab.plan_button, Qt.MouseButton.LeftButton)
    assert tab.session.mode == "ask"
    assert wait_until(lambda: any(s == tab.session.id and e.get("type") == "run_finished"
                                  for s, e in live.events[start:]), WAIT)
    assert (folder / "plan.txt").is_file(), tab.transcript.toPlainText()[-3000:]
    assert word in (folder / "plan.txt").read_text()


# -- 6. the agent asks; topics; work prompts and "/" ---------------------------------------


def test_happy_the_agent_asks_the_user(live):
    folder = live.folder("ask")
    tab = live.start_agent(folder)
    answer = _marker("zebra")
    live.dialogs.answer_text = answer
    run = live.send(tab, "Call the ask_user tool to ask me for a word. Then answer with exactly "
                         "the word I gave you.", name="ask-user")
    assert live.dialogs.of("The agent asks"), run.summary()
    assert "ok" in run.outcomes("ask_user")
    assert answer in run.answer, run.summary()


def test_happy_a_topic_fills_the_task_and_runs(live):
    folder = live.folder("topic")
    marker = _marker("big")
    (folder / f"{marker}.bin").write_bytes(b"\0" * 200_000)
    (folder / "small.txt").write_text("s")
    tab = live.start_agent(folder)
    tab._fill_topics_menu()
    action = next(a for a in tab.topics_menu.actions() if a.text().startswith("Disk usage"))
    action.trigger()
    pump(0.05)
    task = tab.input.toPlainText()
    assert str(folder) in task and "Change nothing" in task
    run = live.send(tab, task, name="topic-disk-usage")
    assert any(o == "ok" for _n, o in run.results), run.summary()
    assert marker in run.answer, run.summary()


def test_happy_a_work_prompt_through_slash_runs(live):
    from core import agent_topics as AT

    folder = live.folder("slash")
    marker = _marker("slashfile")
    (folder / f"{marker}.txt").write_text("x")
    AT.save_user_topics([AT.Topic("Live list", "Use the list_dir tool on {folder} and answer "
                                  "with the names of the files in it.", command="live-list")])
    tab = live.start_agent(folder)
    tab.input.setFocus()
    QTest.keyClicks(tab.input, "/live")
    pump(0.2)
    assert "/live-list" in tab.slash_model.stringList()
    assert tab.slash_completer.popup().isVisible()
    QTest.keyClick(tab.slash_completer.popup(), Qt.Key.Key_Return)
    pump(0.1)
    task = tab.input.toPlainText()
    assert task == f"Use the list_dir tool on {folder} and answer with the names of the files in it."
    run = live.send(tab, task, name="work-prompt")
    assert "ok" in run.outcomes("list_dir"), run.summary()
    assert marker in run.answer, run.summary()


# -- 7. attachments ------------------------------------------------------------------------


def test_happy_an_attached_file_outside_the_folder_is_read(live):
    folder = live.folder("attach")
    outside = live.folder("outside")
    code = _marker("ATT")
    (outside / "secret.txt").write_text(f"The code is {code}.\n")
    tab = live.start_agent(folder)
    pane = live.local_pane()
    pane.navigate(str(outside))
    pump(0.4)
    pane._table.selectAll()
    pump(0.1)
    tab._fill_attach_menu()
    next(a for a in tab.attach_menu.actions()
         if a.text() == "Selected files of the active pane").trigger()
    pump(0.1)
    assert [a["path"] for a in tab._attachments] == [str(outside / "secret.txt")]
    assert (str(outside), False) in [tuple(f) for f in tab.session.extra_folders]
    run = live.send(tab, "Read the file I attached with read_file and answer with the code "
                         "written in it.", name="attachment")
    assert "ok" in run.outcomes("read_file"), run.summary()
    assert code in run.answer, run.summary()


# -- 8. extension tools and topics, Agent Stats ---------------------------------------------


def test_happy_an_extensions_agent_tool_is_called(live):
    folder = live.folder("ext")
    tab = live.start_agent(folder)
    host = live.win.extension_host
    assert host.error("user:livext") == ""
    module = host.module("user:livext")
    item = next(tab.groups.item(i) for i in range(tab.groups.count())
                if tab.groups.item(i).text() == "ext:user:livext")
    item.setCheckState(Qt.CheckState.Checked)
    pump(0.05)
    run = live.send(tab, "Call the tool that returns the code stored under the name 'alpha' "
                         "and answer with the code only.", name="extension-tool")
    assert module.CALLS, run.summary()
    assert live.ext_code in run.answer, run.summary()


def test_happy_agent_stats_counts_the_runs(live):
    module = live.win.extension_host.module("bundled:agent_stats")
    assert module is not None and module.WINDOW is not None
    stats = module.WINDOW.stats()
    assert stats["runs"] >= 1 and stats["tool_calls"] >= 1 and stats["answers"] >= 1, stats
    assert stats["prompt_tokens"] > 0 and stats["completion_tokens"] > 0, stats


# -- 9. Stop during a long answer -------------------------------------------------------------


def test_edge_stop_during_a_long_answer_ends_the_run_at_once(live):
    folder = live.folder("stop")
    tab = live.start_agent(folder)
    began = time.monotonic()
    run = live.send(tab, "Without calling any tool: write a very long essay, at least 3000 "
                         "words, on the history of file managers.", name="stop",
                    stop_after=2.0)
    idle_after_stop = time.monotonic() - began - 2.0
    assert run.finished.get("stopped") == "cancelled", run.summary()
    assert idle_after_stop < 5.0, f"the tab was busy {idle_after_stop:.1f} s after Stop"
    assert not tab.busy() and tab.send_button.isEnabled()
    assert "Stopped." in run.transcript


# -- 10. remote commands (the lab's ssh-alpha) -----------------------------------------------


@pytest.fixture(scope="module")
def ssh_pane(live):
    if not _reachable(SSH_HOST, SSH_PORT):
        pytest.skip("lab ssh-alpha not reachable (podman unshare --rootless-netns)")
    from core.profiles import ConnectionProfile
    from core.ssh_client import SSHSession

    profile = ConnectionProfile(name="lab-alpha", protocol="sftp", host=SSH_HOST,
                                port=SSH_PORT, username=SSH_USER, auth_type="password")
    session = SSHSession(profile)
    session.connect(password=SSH_PASS, on_unknown_host=lambda _err: True)
    # A pane of its own beside the local one, as a split makes it.
    live.local_pane()
    live.win._split_pane(Qt.Orientation.Horizontal)
    pump(0.3)
    pane = live.win._panes[-1]
    pane.set_backend(session, "~")
    pump(0.5)
    yield pane
    session.disconnect()


def test_happy_a_remote_command_asks_and_runs(live, ssh_pane):
    folder = live.folder("exec")
    tab = live.start_agent(folder)
    _tick(tab, tab.allow_exec, True)
    live.dialogs.confirm_yes = True
    asked = len(live.dialogs.of("Allow this action?"))
    run = live.send(tab, "Call exec_backends, then run the command 'cat /etc/hostname' with "
                         "remote_exec on the backend it lists (copy its id exactly) and answer "
                         "with the output.",
                    name="remote-exec")
    confirms = live.dialogs.of("Allow this action?")[asked:]
    assert any("remote_exec" in c["text"] for c in confirms), run.summary()
    assert "ok" in run.outcomes("remote_exec"), run.summary()
    assert "alpha" in run.answer.lower(), run.summary()


def test_sad_a_remote_command_with_no_does_not_run(live, ssh_pane):
    folder = live.folder("exec-no")
    tab = live.start_agent(folder)
    _tick(tab, tab.allow_exec, True)
    live.dialogs.confirm_yes = False
    try:
        run = live.send(tab, "Call exec_backends, then run 'touch /tmp/axross-live-refused' with "
                             "remote_exec on the backend it lists (copy its id exactly).",
                        name="remote-exec-no")
    finally:
        live.dialogs.confirm_yes = True
    assert "declined" in run.outcomes("remote_exec"), run.summary()
    assert "ok" not in run.outcomes("remote_exec")


# -- 11. voice ---------------------------------------------------------------------------------


def test_edge_speaking_needs_piper(live):
    import importlib.util

    if importlib.util.find_spec("piper") is None:
        pytest.skip("piper-tts is not installed in this venv: answers cannot be spoken")
    raise AssertionError("piper is installed: extend this test to speak an answer")


def test_edge_server_speech_recognition_reports_what_the_server_says(live):
    """The profile set to server recognition: a recording goes to
    /audio/transcriptions of the same server. LM Studio and Ollama have
    none; the tab must say so, not hang or crash."""
    from core import llm_profiles as LP

    settings = LP.LLMSettings.load()
    profile = settings.profile(PROFILE)
    profile.stt_engine = "server"
    settings.save()
    live.win.refresh_llm_profiles()
    folder = live.folder("voice")
    tab = live.start_agent(folder)
    voice = live.dock.voice
    live.dock.voice_tab = tab
    pcm = b"\0\0" * 16000  # one second of silence
    voice._transcribe(pcm)
    try:
        assert wait_until(lambda: voice.state == "idle", 60)
        pump(0.2)
        shown = tab.transcript.toPlainText()
        assert "Speech recognition failed" in shown or "Nothing was recognised" in shown, shown
        print(f"\nserver speech recognition on {ENDPOINT}: {shown.splitlines()[-1]!r}")
    finally:
        profile.stt_engine = "local"
        settings.save()
        live.win.refresh_llm_profiles()


# -- 12. a model that is not loaded is not loaded behind the user's back ---------------------


def _cold_model(profile) -> str:
    """A model the server has but has not loaded ("" when there is none)."""
    from core import agent as A

    root = A._server_root(profile)
    if PROVIDER == "lmstudio":
        data = A._get_json(profile, "", root + "/api/v0/models")
        return next((e["id"] for e in data.get("data", []) if e.get("state") == "not-loaded"
                     and e.get("type") in ("llm", "vlm")), "")
    data = A._get_json(profile, "", root + "/api/tags")
    loaded, _mine = A._loaded_models(profile, "")
    return next((m["name"] for m in data.get("models", []) if m["name"] not in loaded), "")


def test_sad_a_cold_model_is_refused_before_anything_is_sent(live):
    import dataclasses

    from core import agent as A
    from core import llm_profiles as LP

    if PROVIDER not in ("lmstudio", "ollama"):
        pytest.skip(f"{PROVIDER} reports no loaded models")
    settings = LP.LLMSettings.load()
    profile = settings.profile(PROFILE)
    cold = _cold_model(profile)
    if not cold:
        pytest.skip("the server has no model that is not loaded")
    probe = dataclasses.replace(profile, name="live-cold", model=cold)
    # Checked first without the dock: should this not refuse, nothing is
    # sent at all - the server must not load a model for this test.
    assert A.model_load_refusal(probe, ""), "the guard would let the load happen"
    settings.profiles.append(probe)
    settings.save()
    live.win.refresh_llm_profiles()
    try:
        folder = live.folder("cold")
        live.local_pane().navigate(str(folder))
        pump(0.3)
        _menu_action(live.win, "Tools", "Start Agent").trigger()
        pump(0.2)
        tab = live.dock.current_tab()
        tab.model_combo.setCurrentIndex(tab.model_combo.findData("live-cold"))
        pump(0.05)
        start = len(live.events)
        tab.input.setPlainText("hello")
        QTest.keyClick(tab.input, Qt.Key.Key_Return, Qt.KeyboardModifier.ControlModifier)
        assert wait_until(lambda: any(e.get("type") == "run_finished"
                                      for _s, e in live.events[start:]), 60)
        finished = next(e for _s, e in live.events[start:] if e.get("type") == "run_finished")
        assert finished.get("error") and "not loaded" in finished["error"], finished
        assert "not loaded" in tab.transcript.toPlainText()
        _loaded, mine = A._loaded_models(probe, "")
        assert mine is False, f"{cold} was loaded"
        print(f"\ncold model {cold!r} refused: {finished['error'][:200]!r}")
    finally:
        settings.profiles = [p for p in settings.profiles if p.name != "live-cold"]
        settings.save()
        live.win.refresh_llm_profiles()
