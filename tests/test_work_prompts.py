"""Work prompts: the user's own prepared agent tasks, picked by "/" or menu.

Operator: *„ein feature, dass man dem llm aufgaben geben kann, die
man auch selber durch prompts definieren bzw. konfigurieren kann, sozusagen
"arbeitsprompts". die sollen dann direkt per / oder dropdown im agent dock
wählbar sein sowas wie "analysiere /etc" und suche punkte die verbessert
werden sollten, "prüfe den plattenplatz wo kann eingesparrt werden, nimm das
axross duplicate finder feature"..."*

Built on the existing topics (core/agent_topics.py, the dock's "Topics ▸"
menu): a topic gains a slash command and the tool groups it needs; the
user's own topics live in ~/.config/axross/agent/work_prompts.json and are
made, changed and deleted in Topics ▸ + New Topic… / Edit or Delete My
Topics…; typing "/" in
the task field offers every command.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import agent_topics as AT  # noqa: E402
from tests.test_agent_tabs import APP, Env, wait_idle  # noqa: E402


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


def _mine(**kw):
    base = dict(title="Review /etc", task="Analyse {folder} and list what should be improved.",
                description="Config review", command="etc-review", groups=("filetype",))
    base.update(kw)
    return AT.Topic(source="user", **base)


# -- the store -----------------------------------------------------------------


class TestStore:
    def test_happy_round_trip_and_private_file(self, store):
        AT.save_user_topics([_mine(), _mine(title="Second", command="second", mode="plan",
                                            needs=("write",))])
        got = AT.load_user_topics()
        assert [t.title for t in got] == ["Review /etc", "Second"]
        assert got[0].groups == ("filetype",) and got[1].mode == "plan" and got[1].needs == ("write",)
        assert all(t.source == "user" for t in got)
        assert stat.S_IMODE(store.stat().st_mode) == 0o600

    def test_happy_the_operators_two_examples_are_built_in(self):
        commands = {t.command: t for t in AT.BUILTIN_TOPICS}
        review = commands["review-config"]
        assert "improve" in review.task and "{folder}" in review.task
        space = commands["free-space"]
        assert "duplicates" in space.groups and "duplicate" in space.task.lower()
        assert all(t.command for t in AT.BUILTIN_TOPICS)
        assert len(commands) == len(AT.BUILTIN_TOPICS)  # unique

    def test_sad_a_missing_or_corrupt_file_reads_as_none(self, store):
        assert AT.load_user_topics() == []
        store.parent.mkdir(parents=True)
        store.write_text("{not json")
        assert AT.load_user_topics() == []
        store.write_text(json.dumps({"topics": "nope"}))
        assert AT.load_user_topics() == []

    def test_sad_bad_entries_are_skipped_good_ones_kept(self, store):
        store.parent.mkdir(parents=True)
        store.write_text(json.dumps({"topics": [
            {"title": "ok", "task": "do it", "command": "ok"},
            {"title": "", "task": "x"},
            {"title": "bad mode", "task": "x", "mode": "root"},
            {"title": "bad group", "task": "x", "groups": ["scripts"]},
            {"title": "bad cmd", "task": "x", "command": "Rm -rf"},
            "a string",
        ]}))
        assert [t.title for t in AT.load_user_topics()] == ["ok"]

    @pytest.mark.parametrize("field,value", [
        ("title", ""), ("title", "x" * 81), ("task", ""), ("task", "x" * 20_001),
        ("command", "has space"), ("command", "/slash"), ("command", "UPPER"), ("command", "x" * 33),
        ("mode", "root"), ("needs", ("sudo",)), ("groups", ("scripts",)),
    ])
    def test_sad_validation_names_the_field(self, field, value):
        with pytest.raises(ValueError, match=field):
            AT.validate_topic(_mine(**{field: value}))

    def test_sad_a_command_may_not_shadow_another(self, store):
        with pytest.raises(ValueError, match="free-space"):
            AT.save_user_topics([_mine(command="free-space")])
        with pytest.raises(ValueError, match="twice"):
            AT.save_user_topics([_mine(), _mine(title="Other")])

    def test_edge_an_empty_command_is_derived_from_the_title(self):
        assert AT.command_of(_mine(command="", title="Check SSH keys & certs!")) == "check-ssh-keys-certs"
        assert AT.command_of(_mine(command="", title="Ärger über Ö")) == "rger-ber"

    def test_edge_lookup_by_command_with_or_without_slash(self):
        topics = [*AT.BUILTIN_TOPICS, _mine()]
        assert AT.find_topic(topics, "/etc-review").title == "Review /etc"
        assert AT.find_topic(topics, "free-space").command == "free-space"
        assert AT.find_topic(topics, "/nothing") is None


# -- the dock ------------------------------------------------------------------


class TestDock:
    def test_happy_user_prompts_join_the_topics_menu_with_manage_entries(self, env, store):
        AT.save_user_topics([_mine()])
        env.fake({"content": "ok"})
        tab = env.dock().current_tab()
        tab._fill_topics_menu()
        texts = [a.text() for a in tab.topics_menu.actions()]
        assert "Review /etc\t/etc-review" in texts and "System inventory\t/inventory" in texts
        assert any("Edit or Delete My Topics" in t for t in texts)
        assert any("Save This Task as Topic" in t for t in texts)

    def test_happy_a_topic_ticks_its_tool_groups(self, env, store):
        env.fake({"content": "ok"})
        tab = env.dock().current_tab()
        tab.use_topic(AT.find_topic(AT.BUILTIN_TOPICS, "free-space"))
        assert "duplicates" in tab.selected_groups()
        assert str(env.root) in tab.input.toPlainText()

    def test_happy_slash_completion_offers_and_fills(self, env, store):
        AT.save_user_topics([_mine()])
        env.fake({"content": "ok"})
        tab = env.dock().current_tab()
        tab.input.setPlainText("/fr")
        offered = tab.slash_matches()
        assert "/free-space" in offered and "/etc-review" not in offered
        tab.input.setPlainText("/")
        assert {"/free-space", "/etc-review", "/review-config"} <= set(tab.slash_matches())
        tab.apply_slash("/etc-review")
        assert tab.input.toPlainText() == f"Analyse {env.root} and list what should be improved."

    def test_happy_send_of_a_bare_command_expands_instead_of_sending(self, env, store):
        server = env.fake({"content": "ok"})
        tab = env.dock().current_tab()
        tab.input.setPlainText("/review-config")
        tab.send()
        APP.processEvents()
        assert server.requests == []
        assert "improve" in tab.input.toPlainText()

    def test_happy_text_after_a_command_is_kept_below_the_prompt(self, env, store):
        env.fake({"content": "ok"})
        tab = env.dock().current_tab()
        tab.input.setPlainText("/review-config focus on sshd")
        tab.send()
        text = tab.input.toPlainText()
        assert "improve" in text and text.rstrip().endswith("focus on sshd")

    def test_sad_an_unknown_command_is_said_and_not_sent(self, env, store):
        server = env.fake({"content": "ok"})
        tab = env.dock().current_tab()
        tab.input.setPlainText("/no-such-thing")
        tab.send()
        APP.processEvents()
        assert server.requests == []
        assert "/no-such-thing" in tab.transcript.toPlainText()
        assert tab.input.toPlainText() == "/no-such-thing"

    def test_edge_an_unknown_word_with_text_after_it_is_a_normal_task(self, env, store):
        """"/tmp is full, why?" is a question, not a command."""
        server = env.fake({"content": "fine"})
        tab = env.dock().current_tab()
        tab.input.setPlainText("/tmp is full, why?")
        tab.send()
        wait_idle(tab)
        assert len(server.requests) == 1

    def test_edge_a_path_typed_at_the_start_is_a_normal_task(self, env, store):
        """"/etc/ssh: what is wrong?" starts with a slash but is no command."""
        server = env.fake({"content": "fine"})
        tab = env.dock().current_tab()
        tab.input.setPlainText("/etc/ssh/sshd_config: what is wrong?")
        tab.send()
        wait_idle(tab)
        assert len(server.requests) == 1

    def test_edge_keyboard_slash_popup(self, env, store):
        from PyQt6.QtCore import Qt
        from PyQt6.QtTest import QTest

        env.fake({"content": "ok"})
        dock = env.dock()
        dock.show()
        tab = dock.current_tab()
        tab.input.setFocus()
        QTest.keyClicks(tab.input, "/free")
        APP.processEvents()
        popup = tab.slash_completer.popup()
        assert popup.isVisible()
        QTest.keyClick(popup, Qt.Key.Key_Return)
        APP.processEvents()
        assert "duplicate" in tab.input.toPlainText().lower()


# -- the manage dialog -----------------------------------------------------------


class TestManageDialog:
    def test_happy_create_edit_delete(self, store):
        from ui.work_prompts_dialog import WorkPromptsDialog

        dlg = WorkPromptsDialog()
        dlg.new_prompt()
        dlg.title_edit.setText("Logs of today")
        dlg.command_edit.setText("today-logs")
        dlg.task_edit.setPlainText("Read the logs in {folder} from today and summarise errors.")
        dlg.mode_combo.setCurrentIndex(dlg.mode_combo.findData("plan"))
        dlg.group_checks["index"].setChecked(True)
        assert dlg.save()
        got = AT.load_user_topics()
        assert [(t.title, t.command, t.mode, t.groups) for t in got] == [
            ("Logs of today", "today-logs", "plan", ("index",))]
        dlg.list.setCurrentRow(0)
        dlg.title_edit.setText("Logs of the day")
        assert dlg.save()
        assert AT.load_user_topics()[0].title == "Logs of the day"
        with mock.patch("ui.work_prompts_dialog.QMessageBox.question",
                        return_value=dlg.YES):
            dlg.delete_prompt()
        assert AT.load_user_topics() == []
        dlg.close()

    def test_sad_invalid_input_is_shown_and_not_stored(self, store):
        from ui.work_prompts_dialog import WorkPromptsDialog

        dlg = WorkPromptsDialog()
        dlg.new_prompt()
        dlg.title_edit.setText("x")
        dlg.command_edit.setText("free-space")  # a built-in's
        dlg.task_edit.setPlainText("y")
        assert not dlg.save()
        assert "free-space" in dlg.error_label.text()
        assert not store.exists()
        dlg.close()

    def test_edge_save_this_task_prefills_the_dialog(self, env, store):
        env.fake({"content": "ok"})
        tab = env.dock().current_tab()
        tab.input.setPlainText("Count the PDFs in the folder.")
        with mock.patch("ui.work_prompts_dialog.WorkPromptsDialog.exec", return_value=0) as run:
            dlg = tab.save_task_as_prompt()
        run.assert_called_once()
        assert dlg.task_edit.toPlainText() == "Count the PDFs in the folder."
        assert dlg.title_edit.text() == ""


def test_e2e_free_space_prompt_reaches_the_model_with_the_duplicate_tools(env, store):
    """Operator's example: "/free-space" -> the prompt in the field -> sent:
    the model gets the task with the folder and the Duplicate Finder tools."""
    server = env.fake({"content": "Here is what can go."})
    tab = env.dock().current_tab()
    tab.input.setPlainText("/free-space")
    tab.send()  # expands
    assert server.requests == []
    tab.send()  # sends
    wait_idle(tab)
    assert len(server.requests) == 1
    request = server.requests[0]
    user_text = " ".join(m.get("content") or "" for m in request["messages"] if m["role"] == "user")
    assert "duplicate" in user_text.lower() and str(env.root) in user_text
    tools = {t["function"]["name"] for t in request.get("tools", [])}
    assert any(name.startswith("duplicates_") for name in tools), sorted(tools)


def test_e2e_a_user_prompt_made_in_the_dialog_runs_from_the_slash(env, store):
    from ui.work_prompts_dialog import WorkPromptsDialog

    dlg = WorkPromptsDialog()
    dlg.title_edit.setText("Etc review")
    dlg.command_edit.setText("etc")
    dlg.task_edit.setPlainText("Analyse /etc on {backend} and list what should be improved.")
    assert dlg.save()
    dlg.close()
    server = env.fake({"content": "ok"})
    tab = env.dock().current_tab()
    tab.input.setPlainText("/etc only sshd please")
    tab.send()
    assert tab.input.toPlainText() == (
        "Analyse /etc on the remote host and list what should be improved.\n\nonly sshd please")
    tab.send()
    wait_idle(tab)
    assert "only sshd please" in str(server.requests[0]["messages"])


# -- round-2 verification: a save never drops what the reader skipped -------------------


@pytest.mark.parametrize("old", [
    "{not json - a hand edit with a missing quote",
    json.dumps({"topics": [{"title": "ok", "task": "do it", "command": "ok"},
                           {"title": "mine", "task": "x" * 20_001, "command": "long"}]}),
])
def test_sad_saving_over_a_file_with_unreadable_entries_keeps_a_backup(store, old):
    """The file is hand-editable; what the reader skipped (a broken file, an
    entry that does not validate) was silently gone after the next save."""
    store.parent.mkdir(parents=True)
    store.write_text(old)
    AT.save_user_topics([*AT.load_user_topics(), _mine()])
    backup = store.with_name(store.name + ".bak")
    assert backup.read_text() == old
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    assert [t.command for t in AT.load_user_topics()][-1] == "etc-review"


def test_edge_a_clean_file_is_replaced_without_a_backup(store):
    AT.save_user_topics([_mine()])
    AT.save_user_topics([_mine(title="Renamed")])
    assert not store.with_name(store.name + ".bak").exists()
    assert [t.title for t in AT.load_user_topics()] == ["Renamed"]


# -- bughunt 2026-10-22 ----------------------------------------------------------------------


def test_sad_a_second_broken_hand_edit_keeps_the_first_backup(store):
    """Each save over a file with unreadable entries keeps them in a backup;
    a later one must not overwrite the earlier backup - it held the only
    copy of what that save dropped."""
    store.parent.mkdir(parents=True)
    first = "{first broken hand edit"
    store.write_text(first)
    AT.save_user_topics([_mine()])
    second = json.dumps({"topics": [{"title": "t", "task": "x" * 20_001, "command": "big"}]})
    store.write_text(second)
    AT.save_user_topics([_mine()])
    backups = sorted(p for p in store.parent.iterdir() if p.name.startswith(store.name + ".bak"))
    assert [p.read_text() for p in backups] == [first, second]
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in backups)


def test_edge_the_same_unreadable_file_is_backed_up_once(store, monkeypatch):
    """A save that fails after its backup and is tried again does not pile
    up copies of the same bytes."""
    store.parent.mkdir(parents=True)
    store.write_text("{broken")
    real_replace = os.replace
    monkeypatch.setattr(AT.os, "replace", lambda *a: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        AT.save_user_topics([_mine()])
    monkeypatch.setattr(AT.os, "replace", real_replace)
    AT.save_user_topics([_mine()])
    backups = [p for p in store.parent.iterdir() if p.name.startswith(store.name + ".bak")]
    assert len(backups) == 1 and backups[0].read_text() == "{broken"


def test_sad_no_free_backup_name_leaves_the_file_as_it_is(store, monkeypatch):
    monkeypatch.setattr(AT, "MAX_BACKUPS", 3)
    store.parent.mkdir(parents=True)
    for name in (".bak", ".bak.1", ".bak.2"):
        store.with_name(store.name + name).write_text(f"older {name}")
    store.write_text("{broken")
    with pytest.raises(OSError, match="not overwritten"):
        AT.save_user_topics([_mine()])
    assert store.read_text() == "{broken"


def test_sad_the_dialog_keeps_prompts_added_while_it_was_open(store):
    """A prompt added to the file while the window is open (a hand edit,
    another window) survives the window's save; before, the window wrote its
    own old list over it."""
    from ui.work_prompts_dialog import WorkPromptsDialog

    AT.save_user_topics([_mine()])
    dlg = WorkPromptsDialog()
    try:
        AT.save_user_topics([_mine(), _mine(title="Added elsewhere", command="elsewhere")])
        dlg.list.setCurrentRow(0)
        dlg.title_edit.setText("Review /etc again")
        assert dlg.save()
        assert [t.title for t in AT.load_user_topics()] == ["Review /etc again",
                                                             "Added elsewhere"]
        assert dlg.list.count() == 2
        dlg.new_prompt()
        dlg.title_edit.setText("New one")
        dlg.task_edit.setPlainText("Do it.")
        AT.save_user_topics([*AT.load_user_topics(), _mine(title="Third", command="third")])
        assert dlg.save()
        assert [AT.command_of(t) for t in AT.load_user_topics()] == [
            "etc-review", "elsewhere", "third", "new-one"]
    finally:
        dlg.close()


def test_edge_deleting_in_the_dialog_removes_only_that_prompt(store):
    from ui.work_prompts_dialog import WorkPromptsDialog

    AT.save_user_topics([_mine()])
    dlg = WorkPromptsDialog()
    try:
        AT.save_user_topics([_mine(), _mine(title="Added elsewhere", command="elsewhere")])
        dlg.list.setCurrentRow(0)
        with mock.patch("ui.work_prompts_dialog.QMessageBox.question", return_value=dlg.YES):
            dlg.delete_prompt()
        assert [t.command for t in AT.load_user_topics()] == ["elsewhere"]
        assert dlg.list.count() == 1
    finally:
        dlg.close()


def test_edge_a_prompt_changed_elsewhere_and_here_keeps_both(store):
    """Changed in the file and in the window: the window's version is added
    rather than lost, and a command both use is reported, not overwritten."""
    from ui.work_prompts_dialog import WorkPromptsDialog

    AT.save_user_topics([_mine()])
    dlg = WorkPromptsDialog()
    try:
        AT.save_user_topics([_mine(task="Changed elsewhere.")])
        dlg.list.setCurrentRow(0)
        dlg.title_edit.setText("Changed here")
        assert not dlg.save()
        assert "etc-review" in dlg.error_label.text()
        assert AT.load_user_topics()[0].task == "Changed elsewhere."
    finally:
        dlg.close()
