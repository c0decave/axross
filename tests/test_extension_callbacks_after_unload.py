"""No callback reaches an extension after it was switched off or reloaded.

Before: ``ExtensionAPI.run_agent`` wrapped *on_done* without the "still
loaded" check that run_in_background's ``_deliver`` makes. An agent task
outlives a switch-off or Reload, so the old extension got the callback
and touched its deleted panel ("wrapped C/C++ object of type QLabel has
been deleted", recorded as the extension's error). The same held for an
entry of the pane's right-click menu clicked after its extension was
gone, and for pane and agent events: the host called every extension of
a list taken before the first handler ran, also one that handler had
switched off.
"""

from __future__ import annotations

import os
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMainWindow, QMenu  # noqa: E402

from core import extensions as EX  # noqa: E402
from ui.extension_host import ExtensionHost  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def own_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    EX.clear_manifest_cache()
    monkeypatch.setattr(EX, "_SAFE_MODE", False)


class _AgentDock:
    """Stands for the Agent panel: keeps each task's on_done."""

    def __init__(self):
        self.tasks: list = []

    def start_task(self, task, **kw):
        self.tasks.append(kw["on_done"])
        return SimpleNamespace(session=SimpleNamespace(id=f"s{len(self.tasks)}"))


@pytest.fixture
def host():
    window = QMainWindow()
    window._agent_dock = _AgentDock()
    menu = window.menuBar().addMenu("Extensions")
    yield ExtensionHost(window, menu)
    window.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def _settle() -> None:
    APP.processEvents()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def _write_ext(name: str, body: str) -> None:
    folder = EX.extensions_dir()
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{name}.py").write_text(
        f'EXTENSION = {{"name": "{name.title()}"}}\n' + textwrap.dedent(body))


LATE = """
    from PyQt6.QtWidgets import QLabel
    HITS = []
    def activate(api):
        label = QLabel("x")
        api.add_dock("Late", label)
        def done(answer, error):
            HITS.append(answer)
            label.setText(answer)
        api.run_agent("hi", on_done=done)
"""


def test_happy_a_task_that_ends_after_the_switch_off_does_not_call_back(host):
    _write_ext("late", LATE)
    host.set_enabled("user:late", True)
    module = host.module("user:late")
    assert module is not None, host.error("user:late")
    host.set_enabled("user:late", False)
    _settle()                                              # its panel is deleted
    host.window._agent_dock.tasks[0]("the answer", "")
    assert module.HITS == []
    assert host.error("user:late") == ""


def test_sad_after_reload_only_the_new_instance_gets_its_own_task_s_end(host):
    _write_ext("late", LATE)
    host.set_enabled("user:late", True)
    old = host.module("user:late")
    host.reload()
    _settle()
    new = host.module("user:late")
    assert new is not old and new is not None
    first, second = host.window._agent_dock.tasks
    first("old answer", "")
    second("new answer", "")
    assert old.HITS == [] and new.HITS == ["new answer"]
    assert host.error("user:late") == ""


def test_edge_a_context_entry_clicked_after_the_switch_off_and_events_after_one_do_nothing(host):
    _write_ext("ctx", """
        HITS = []
        def activate(api):
            api.add_context_action("Do it", lambda ctx: HITS.append("ctx"))
            api.on("path_changed", lambda ctx: HITS.append("event"))
            api.on_agent_event(lambda session, event: HITS.append("agent"))
    """)
    _write_ext("aaa_off", """
        def activate(api):
            # Runs first (loaded first) and switches the other one off.
            api.on("path_changed", lambda ctx: api._host.set_enabled("user:ctx", False))
            api.on_agent_event(lambda session, event: api._host.set_enabled("user:ctx", False))
    """)
    host.set_enabled("user:aaa_off", True)
    host.set_enabled("user:ctx", True)
    module = host.module("user:ctx")
    assert module is not None, host.error("user:ctx")
    pane = SimpleNamespace(backend=None, current_path="/", selected_items=lambda: [],
                           selected_file_items=lambda: [])
    menu = QMenu()
    host.add_context_actions(pane, menu)
    entry = next(a for a in menu.actions() if a.text() == "Do it")
    host.emit("path_changed", pane)                        # aaa_off switches ctx off first
    assert module.HITS == []
    entry.trigger()                                        # the menu was still open
    assert module.HITS == []
    host.set_enabled("user:ctx", True)
    again = host.module("user:ctx")
    host.emit_agent_event("s1", {"type": "run_started"})
    assert again.HITS == []
    assert host.error("user:ctx") == ""
