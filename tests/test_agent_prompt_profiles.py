"""System and user prompt in Edit > Settings > Agent > Prompts, as named
prompt profiles.

Operator: *„wo ist der user und system prompt konfiguriert? bitte auch in
settings verfügbar machen und auch verschiedene user/system prompt profile
anbieten."*

Before: the system prompt was the constant core/agent.py SYSTEM_PROMPT,
which ui/agent_dock.py AgentTab._config put into every request (plus the
plan and voice additions); there was no user prompt at all - the task went
to the model as typed (with the attachments' context in front). Now
core/agent_prompts.py holds the profiles (stored in agent/settings.json
under "prompt_profiles" / "prompt_profile"); the built-in "Default" is
SYSTEM_PROMPT with no user prompt and cannot be changed or deleted.
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

from core import agent as A  # noqa: E402
from core import agent_prompts as AP  # noqa: E402
from core import agent_settings as AGS  # noqa: E402
from tests.test_agent_tabs import APP, Env, wait_idle  # noqa: E402

TERSE = AP.PromptProfile("Terse", "You are terse. Rules: read only.", "Answer in one line: {task}")


# -- core ------------------------------------------------------------------------------


class TestRender:
    def test_happy_task_field_is_filled(self):
        assert AP.render_task("Answer in one line: {task}", "what is here?") == \
            "Answer in one line: what is here?"

    def test_happy_a_template_without_the_field_goes_in_front(self):
        assert AP.render_task("Answer in German.", "what is here?") == \
            "Answer in German.\n\nwhat is here?"

    def test_edge_empty_or_blank_template_leaves_the_task_alone(self):
        assert AP.render_task("", "x {task} y") == "x {task} y"
        assert AP.render_task("  \n ", "task") == "task"

    def test_edge_braces_in_the_task_are_not_expanded_again(self):
        assert AP.render_task("<{task}>", "use {task} and {folder}") == "<use {task} and {folder}>"

    def test_edge_the_field_twice_is_filled_twice(self):
        assert AP.render_task("{task} / {task}", "a") == "a / a"


class TestProfile:
    def test_happy_default_is_the_built_in_system_prompt(self):
        d = AP.default_profile()
        assert (d.name, d.system_prompt, d.user_prompt, d.builtin) == \
            ("Default", A.SYSTEM_PROMPT, "", True)

    @pytest.mark.parametrize("profile,needle", [
        (AP.PromptProfile("", "s"), "name"),
        (AP.PromptProfile("x" * (AP.MAX_NAME + 1), "s"), "name"),
        (AP.PromptProfile("default", "s"), "Default"),
        (AP.PromptProfile("p", "  "), "system prompt"),
        (AP.PromptProfile("p", "s" * (AP.MAX_SYSTEM + 1)), "system prompt"),
        (AP.PromptProfile("p", "s", "u" * (AP.MAX_USER + 1)), "user prompt"),
    ])
    def test_sad_problems_name_the_field(self, profile, needle):
        assert any(needle in p for p in profile.problems()), profile.problems()

    def test_happy_a_valid_profile_has_no_problems(self):
        assert TERSE.problems() == []


class TestSettingsStore:
    def test_happy_round_trip_with_the_active_profile(self, tmp_path):
        path = tmp_path / "settings.json"
        s = AGS.AgentSettings()
        s.prompt_profiles = [TERSE, AP.PromptProfile("German", "Antworte deutsch.", "")]
        s.prompt_profile = "Terse"
        s.save(path)
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        raw = json.loads(path.read_text())
        assert raw["prompt_profile"] == "Terse"
        assert raw["prompt_profiles"][0] == {"name": "Terse", "system_prompt": TERSE.system_prompt,
                                             "user_prompt": TERSE.user_prompt}
        back = AGS.AgentSettings.load(path)
        assert [p.name for p in back.prompt_profiles] == ["Terse", "German"]
        assert back.active_prompts() == TERSE

    def test_happy_no_choice_is_the_default(self):
        s = AGS.AgentSettings()
        assert s.prompt_profile == "" and s.prompt_profiles == []
        assert s.active_prompts().system_prompt == A.SYSTEM_PROMPT

    def test_sad_broken_entries_are_skipped(self):
        s = AGS.AgentSettings.from_dict({"prompt_profiles": [
            {"name": "ok", "system_prompt": "s"},
            {"name": "", "system_prompt": "s"},
            {"name": "Default", "system_prompt": "s"},
            {"name": "ok", "system_prompt": "twice"},
            {"name": "no system", "system_prompt": ""},
            {"name": "bad type", "system_prompt": 5},
            {"name": "bad user", "system_prompt": "s", "user_prompt": ["x"]},
            "junk",
        ], "prompt_profile": "ok"})
        assert [(p.name, p.system_prompt) for p in s.prompt_profiles] == [("ok", "s")]
        assert s.prompt_profile == "ok"

    def test_edge_an_active_name_that_is_gone_falls_back_to_default(self):
        s = AGS.AgentSettings.from_dict({"prompt_profiles": [], "prompt_profile": "Gone"})
        assert s.prompt_profile == ""
        assert s.active_prompts().builtin
        s.prompt_profile = "Gone"  # set by hand after loading
        assert s.active_prompts().builtin

    def test_edge_not_a_list_keeps_none(self):
        assert AGS.AgentSettings.from_dict({"prompt_profiles": "x"}).prompt_profiles == []


# -- the settings page -----------------------------------------------------------------


def _page(tmp_path, settings=None):
    from ui.agent_settings_dialog import AgentSettingsPage

    path = tmp_path / "settings.json"
    if settings is not None:
        settings.save(path)
    page = AgentSettingsPage(settings_path=path, llm_settings=mock.Mock(profiles=[]))
    page.show_tab("prompts")
    page.show()
    APP.processEvents()
    return page, path


def _names(page):
    return [page.prompt_list.item(i).text() for i in range(page.prompt_list.count())]


class TestPage:
    def test_happy_prompts_is_a_tab_and_a_settings_sub_page(self):
        from ui import settings_dialog
        from ui.agent_settings_dialog import AGENT_TABS

        assert ("prompts", "Prompts") in AGENT_TABS
        assert ("prompts", "Prompts") in settings_dialog._agent_sub_pages()

    def test_e2e_create_type_choose_and_save(self, tmp_path):
        from PyQt6.QtCore import Qt
        from PyQt6.QtTest import QTest

        page, path = _page(tmp_path)
        assert page.tabs.tabText(page.tabs.currentIndex()) == "Prompts"
        assert _names(page)[0].startswith("Default")
        QTest.mouseClick(page.prompt_new_button, Qt.MouseButton.LeftButton)
        page.prompt_name_edit.selectAll()
        QTest.keyClicks(page.prompt_name_edit, "Terse")
        page.prompt_system_edit.selectAll()
        QTest.keyClicks(page.prompt_system_edit, "You are terse.")
        QTest.keyClicks(page.prompt_user_edit, "Answer in one line: {task}")
        page.prompt_active_combo.setCurrentIndex(page.prompt_active_combo.findData("Terse"))
        assert page.is_dirty()
        assert page.save()
        back = AGS.AgentSettings.load(path)
        assert back.active_prompts() == AP.PromptProfile(
            "Terse", "You are terse.", "Answer in one line: {task}")
        assert not page.is_dirty()

    def test_happy_default_is_shown_read_only_and_cannot_be_deleted(self, tmp_path):
        page, _path = _page(tmp_path)
        page.prompt_list.setCurrentRow(0)
        assert page.prompt_system_edit.isReadOnly() and page.prompt_user_edit.isReadOnly()
        assert page.prompt_name_edit.isReadOnly()
        assert page.prompt_system_edit.toPlainText() == A.SYSTEM_PROMPT
        assert not page.prompt_delete_button.isEnabled()
        page.delete_prompt_profile()
        assert _names(page)[0].startswith("Default") and len(_names(page)) == 1

    def test_happy_duplicate_default_starts_from_the_built_in_prompt(self, tmp_path):
        page, _path = _page(tmp_path)
        page.prompt_list.setCurrentRow(0)
        page.duplicate_prompt_profile()
        assert page.prompt_list.currentRow() == 1
        assert not page.prompt_system_edit.isReadOnly()
        assert page.prompt_system_edit.toPlainText() == A.SYSTEM_PROMPT
        assert page.prompt_name_edit.text() not in ("", "Default")

    def test_happy_rename_keeps_it_active_and_delete_falls_back(self, tmp_path):
        s = AGS.AgentSettings()
        s.prompt_profiles = [TERSE]
        s.prompt_profile = "Terse"
        page, path = _page(tmp_path, s)
        page.prompt_list.setCurrentRow(1)
        page.prompt_name_edit.setText("Short")
        assert "Short" in _names(page)[1]
        assert page.prompt_active_combo.currentData() == "Short"
        assert page.save()
        assert AGS.AgentSettings.load(path).prompt_profile == "Short"
        page.prompt_list.setCurrentRow(1)
        page.delete_prompt_profile()
        assert page.prompt_active_combo.currentData() == ""
        assert page.save()
        back = AGS.AgentSettings.load(path)
        assert back.prompt_profiles == [] and back.prompt_profile == ""

    @pytest.mark.parametrize("name,system,needle", [
        ("", "s", "name"),
        ("Default", "s", "Default"),
        ("Other", "", "system prompt"),
        ("Terse", "s", "Two prompt profiles"),
    ])
    def test_sad_invalid_profiles_are_not_saved(self, tmp_path, name, system, needle):
        s = AGS.AgentSettings()
        s.prompt_profiles = [TERSE]
        page, path = _page(tmp_path, s)
        before = path.read_text()
        page.add_prompt_profile()
        page.prompt_name_edit.setText(name)
        page.prompt_system_edit.setPlainText(system)
        assert any(needle in p for p in page.problems()), page.problems()
        with mock.patch("ui.agent_settings_dialog.QMessageBox.warning") as warned:
            assert not page.save()
        warned.assert_called_once()
        assert path.read_text() == before


# -- the dock uses the active profile ----------------------------------------------------


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    yield e
    e.close()


def _user_texts(request):
    return [m.get("content") for m in request["messages"] if m["role"] == "user"]


def test_e2e_the_active_profile_reaches_the_model(env):
    env.settings.prompt_profiles = [TERSE]
    env.settings.prompt_profile = "Terse"
    server = env.fake({"content": "one line"})
    tab = env.dock().current_tab()
    tab.input.setPlainText("what is here?")
    tab.send()
    wait_idle(tab)
    request = server.requests[0]
    assert request["messages"][0]["content"].startswith("You are terse. Rules: read only.")
    assert A.SYSTEM_PROMPT not in request["messages"][0]["content"]
    assert _user_texts(request)[-1] == "Answer in one line: what is here?"
    # The transcript shows what was typed, not the template.
    assert "Answer in one line" not in tab.transcript.toPlainText()


def test_happy_default_profile_sends_as_before(env):
    server = env.fake({"content": "ok"})
    tab = env.dock().current_tab()
    tab.input.setPlainText("what is here?")
    tab.send()
    wait_idle(tab)
    assert server.requests[0]["messages"][0]["content"].startswith(A.SYSTEM_PROMPT)
    assert _user_texts(server.requests[0])[-1] == "what is here?"


def test_edge_switching_the_profile_applies_to_the_next_request(env):
    server = env.fake({"content": "first"}, {"content": "second"})
    dock = env.dock()
    tab = dock.current_tab()
    tab.input.setPlainText("one")
    tab.send()
    wait_idle(tab)
    env.settings.prompt_profiles = [TERSE]
    env.settings.prompt_profile = "Terse"
    dock.reload_settings()
    tab.input.setPlainText("two")
    tab.send()
    wait_idle(tab)
    second = server.requests[1]
    assert second["messages"][0]["content"].startswith("You are terse.")
    assert _user_texts(second) == ["one", "Answer in one line: two"]


def test_edge_plan_mode_adds_to_the_profile_and_run_plan_is_not_wrapped(env):
    env.settings.prompt_profiles = [TERSE]
    env.settings.prompt_profile = "Terse"
    server = env.fake({"content": "1. step"}, {"content": "done"})
    tab = env.dock().current_tab()
    tab.mode_combo.setCurrentIndex(tab.mode_combo.findData("plan"))
    tab.input.setPlainText("clean up")
    tab.send()
    wait_idle(tab)
    from ui.agent_dock import PLAN_PROMPT, RUN_PLAN_TASK

    system = server.requests[0]["messages"][0]["content"]
    assert system.startswith("You are terse.") and PLAN_PROMPT.strip() in system
    tab._plan_ready = True
    tab.run_plan()
    wait_idle(tab)
    assert _user_texts(server.requests[1])[-1] == RUN_PLAN_TASK
    APP.processEvents()
