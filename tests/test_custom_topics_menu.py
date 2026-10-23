"""Own topics are written from the Topics menu: "+ New Topic…".

Operator: *„wo kann man sich eigene topic schreiben? uU option in topics
anbiten topics+ um eigenes topic zu schreiben"*

Own topics existed already (core/agent_topics.py, ui/work_prompts_dialog.py)
but were called "work prompts" and hid behind "Manage Work Prompts…" at
the end of the menu, which opened the first stored one rather than an empty
form. Now the menu says what it does: "+ New Topic…" opens an empty form,
"Save This Task as Topic…" and "Edit or Delete My Topics…" the rest; the
store stays ``~/.config/axross/agent/work_prompts.json``.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import agent_topics as AT  # noqa: E402
from tests.test_agent_tabs import APP, Env  # noqa: E402

NEW = "+ New Topic…"
SAVE = "Save This Task as Topic…"
EDIT = "Edit or Delete My Topics…"


@pytest.fixture
def store(tmp_path, monkeypatch):
    path = tmp_path / "agent" / "work_prompts.json"
    monkeypatch.setattr(AT, "user_topics_file", lambda: path)
    return path


@pytest.fixture
def env(tmp_path, store):
    e = Env(tmp_path)
    yield e
    e.close()


def _tab(env):
    env.fake({"content": "ok"})
    return env.dock().current_tab()


def _action(tab, text):
    tab._fill_topics_menu()
    for action in tab.topics_menu.actions():
        if action.text() == text:
            return action
    raise AssertionError(f"no menu entry {text!r} in {[a.text() for a in tab.topics_menu.actions()]}")


def _mine(title="Mine", command="mine"):
    return AT.Topic(title=title, task="Do {folder}", source="user", command=command)


class _Driven:
    """Patches the dialog's exec: *handler(dialog)* drives it like a user.
    An error in the handler is raised after the menu action returned - an
    exception inside a Qt slot would abort the process."""

    def __init__(self, handler):
        self.handler = handler
        self.seen: list = []
        self.error: BaseException | None = None

    def __enter__(self):
        from ui.work_prompts_dialog import WorkPromptsDialog

        def fake_exec(dialog):
            self.seen.append(dialog)
            dialog.show()
            APP.processEvents()
            try:
                self.handler(dialog)
            except BaseException as exc:  # noqa: BLE001 - re-raised in __exit__
                self.error = exc
            return 0

        self._patch = mock.patch.object(WorkPromptsDialog, "exec", fake_exec)
        self._patch.start()
        return self

    def __exit__(self, *exc):
        self._patch.stop()
        if self.error is not None and exc[0] is None:
            raise self.error
        return False


def _run_dialog(handler):
    driven = _Driven(handler)
    return driven, driven.seen


def test_happy_the_menu_offers_new_save_and_edit(env):
    tab = _tab(env)
    tab._fill_topics_menu()
    texts = [a.text() for a in tab.topics_menu.actions()]
    assert NEW in texts and SAVE in texts and EDIT in texts
    assert not any("Work Prompt" in t for t in texts)


def test_e2e_new_topic_typed_in_the_form_joins_the_menu_and_fills_the_task(env, store):
    from PyQt6.QtCore import Qt
    from PyQt6.QtTest import QTest

    tab = _tab(env)

    def write(dialog):
        assert dialog.windowTitle() == "My Topics"
        QTest.keyClicks(dialog.title_edit, "Check SSH config")
        QTest.keyClicks(dialog.command_edit, "ssh")
        QTest.keyClicks(dialog.task_edit, "Read {folder}/sshd_config and list weak options.")
        QTest.mouseClick(dialog.save_button, Qt.MouseButton.LeftButton)

    patch, seen = _run_dialog(write)
    with patch:
        _action(tab, NEW).trigger()
    assert len(seen) == 1 and seen[0].error_label.text() == ""
    assert [(t.title, t.command) for t in AT.load_user_topics()] == [("Check SSH config", "ssh")]
    assert stat.S_IMODE(store.stat().st_mode) == 0o600
    _action(tab, "Check SSH config\t/ssh").trigger()
    assert tab.input.toPlainText() == f"Read {env.root}/sshd_config and list weak options."


def test_edge_new_topic_opens_an_empty_form_although_topics_exist(env, store):
    AT.save_user_topics([_mine()])
    tab = _tab(env)
    patch, seen = _run_dialog(lambda d: None)
    with patch:
        _action(tab, NEW).trigger()
    dialog = seen[0]
    assert dialog.title_edit.text() == "" and dialog.task_edit.toPlainText() == ""
    assert dialog._row == -1


def test_happy_edit_or_delete_opens_the_stored_topics_and_deletes(env, store):
    AT.save_user_topics([_mine(), _mine("Second", "second")])
    tab = _tab(env)

    def delete_first(dialog):
        assert dialog.title_edit.text() == "Mine"
        with mock.patch("ui.work_prompts_dialog.QMessageBox.question", return_value=dialog.YES):
            dialog.delete_button.click()

    patch, _seen = _run_dialog(delete_first)
    with patch:
        _action(tab, EDIT).trigger()
    assert [t.title for t in AT.load_user_topics()] == ["Second"]
    tab._fill_topics_menu()
    texts = [a.text() for a in tab.topics_menu.actions()]
    assert "Second\t/second" in texts and "Mine\t/mine" not in texts


def test_sad_an_invalid_new_topic_is_refused_and_not_in_the_menu(env, store):
    tab = _tab(env)

    def write(dialog):
        dialog.title_edit.setText("No prompt text")
        dialog.save_button.click()

    patch, seen = _run_dialog(write)
    with patch:
        _action(tab, NEW).trigger()
    assert "task" in seen[0].error_label.text()
    assert not store.exists()
    tab._fill_topics_menu()
    assert not any(a.text().startswith("No prompt text") for a in tab.topics_menu.actions())


def test_edge_an_unknown_command_points_to_new_topic(env):
    tab = _tab(env)
    tab.input.setPlainText("/nope")
    tab.send()
    APP.processEvents()
    assert NEW.rstrip("…") in tab.transcript.toPlainText()


def test_edge_save_this_task_prefills_a_new_topic(env, store):
    tab = _tab(env)
    tab.input.setPlainText("Count the PDFs.")
    patch, seen = _run_dialog(lambda d: None)
    with patch:
        _action(tab, SAVE).trigger()
    assert seen[0].task_edit.toPlainText() == "Count the PDFs." and seen[0]._row == -1
