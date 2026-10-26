"""A hand-edited agent store with a list field of the wrong shape starts.

Found by the settings matrix (tests/test_settings_matrix_agent.py, step
"a hand-edited value falls back"): ``"hosts": 5`` in a sandbox profile of
agent/settings.json, or ``"extra_folders": 5`` in a saved Agent tab, made
``SandboxProfile.from_dict`` / ``AgentSession.from_dict`` raise TypeError
(``data.get(...) or ()`` iterated the int) - out of AgentDock.__init__, so
the main window did not start at all. A string was worse than an error:
``"hosts": "db.example:5432"`` was read character by character.

Every other field of these readers takes its default for a value of the
wrong type; the list fields now do too.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.agent_sandbox import SandboxProfile  # noqa: E402
from core.agent_session import AgentSession, SessionStore  # noqa: E402
from core.agent_settings import AgentSettings  # noqa: E402

WRONG = (5, "db.example:5432", {"path": "/srv"}, True, 2.5)
SESSION_ID = "b" * 32


# -- happy ------------------------------------------------------------------------------


def test_happy_valid_lists_still_load() -> None:
    profile = SandboxProfile.from_dict({
        "name": "Box", "hosts": ["db.example:5432"],
        "mounts": [{"path": "/srv/data", "mode": "rw"}]})
    assert profile.hosts == ("db.example:5432",)
    assert profile.mounts == (("/srv/data", True),)
    session = AgentSession.from_dict({
        "id": SESSION_ID, "groups": ["index"], "extra_folders": [{"path": "/srv", "mode": "ro"}],
        "transcript": [{"who": "You:", "text": "hi"}], "messages": [{"role": "user"}]})
    assert session.groups == ["index"] and session.extra_folders == [("/srv", False)]
    assert len(session.transcript) == 1 and session.messages == [{"role": "user"}]


# -- sad --------------------------------------------------------------------------------


@pytest.mark.parametrize("value", WRONG, ids=repr)
@pytest.mark.parametrize("field", ["hosts", "mounts"])
def test_sad_a_sandbox_list_of_the_wrong_type_reads_as_empty(field, value) -> None:
    profile = SandboxProfile.from_dict({"name": "Box", "level": "high", field: value})
    assert profile is not None and profile.level == "high"  # the profile is kept
    assert getattr(profile, field) == ()


@pytest.mark.parametrize("value", WRONG, ids=repr)
@pytest.mark.parametrize("field", ["groups", "extra_folders", "transcript", "messages"])
def test_sad_a_session_list_of_the_wrong_type_reads_as_empty(field, value) -> None:
    session = AgentSession.from_dict({"id": SESSION_ID, "title": "Kept", field: value})
    assert session is not None and session.title == "Kept"
    assert getattr(session, field) == []


# -- edge -------------------------------------------------------------------------------


def test_edge_agent_settings_load_survives_and_keeps_the_rest(tmp_path) -> None:
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"max_steps": 33, "sandboxes": [
        {"name": "Box", "hosts": "db.example:5432", "mounts": 5}]}))
    settings = AgentSettings.load(path)
    assert settings.max_steps == 33
    assert [(p.name, p.hosts, p.mounts) for p in settings.sandboxes] == [("Box", (), ())]


def test_edge_a_session_file_of_the_wrong_shape_is_loaded_not_skipped(tmp_path) -> None:
    (tmp_path / f"{SESSION_ID}.json").write_text(json.dumps({
        "id": SESSION_ID, "title": "Kept", "extra_folders": 5, "groups": "index"}))
    assert [(s.title, s.extra_folders, s.groups) for s in SessionStore(tmp_path).all()] == [
        ("Kept", [], [])]


# -- e2e: the window starts --------------------------------------------------------------


def test_e2e_the_window_starts_and_restores_the_tab(tmp_path, monkeypatch) -> None:
    pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
    from tests.settings_testkit import app, isolate

    app()
    stores = isolate(tmp_path, monkeypatch)
    try:
        stores.agent.parent.mkdir(parents=True)
        stores.agent.write_text(json.dumps({"sandboxes": [{"name": "Box", "hosts": 5}]}))
        sessions = stores.config / "agent" / "sessions"
        sessions.mkdir()
        (sessions / f"{SESSION_ID}.json").write_text(json.dumps(
            {"id": SESSION_ID, "title": "Kept", "extra_folders": 5}))
        win = stores.make_window()
        assert [t.session.title for t in win._agent_dock.all_tabs()] == ["Kept"]
        page = stores.settings_dialog(win).page("agent")
        page.sandbox_list.setCurrentRow(0)
        assert page.name_edit.text() == "Box" and page.hosts_list.count() == 0
    finally:
        stores.restore()
