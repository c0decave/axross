"""The agent's settings file (core.agent_settings): one JSON file whose
broken or missing parts take safe defaults."""

from __future__ import annotations

import json
import stat

from core import agent_settings as S
from core.agent_sandbox import SandboxProfile


# -- happy ---------------------------------------------------------------------


def test_happy_a_fresh_install_has_safe_defaults_and_four_sandbox_presets(tmp_path):
    settings = S.AgentSettings.load(tmp_path / "missing.json")
    assert settings.mode == "ask" and not settings.allow_bypass
    assert settings.sandbox == ""
    assert [p.level for p in settings.sandboxes] == ["lax", "normal", "high", "paranoid"]
    assert not settings.access.remote_files and not settings.access.remote_commands
    assert settings.groups == S.DEFAULT_GROUPS


def test_happy_settings_round_trip(tmp_path):
    path = tmp_path / "agent" / "settings.json"
    settings = S.AgentSettings(mode="plan", max_steps=40, groups=("metadata", "index"),
                               sandbox="Ops",
                               sandboxes=[SandboxProfile(name="Ops", level="high",
                                                         hosts=("db.example:5432",),
                                                         mounts=(("/srv/data", False),))])
    settings.access.remote_files = True
    settings.save(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    back = S.AgentSettings.load(path)
    assert back.to_dict() == settings.to_dict()
    assert back.sandbox_profile().hosts == ("db.example:5432",)
    assert json.loads(path.read_text())["sandboxes"][0]["mounts"] == [
        {"path": "/srv/data", "mode": "ro"}
    ]


# -- sad -----------------------------------------------------------------------


def test_sad_a_broken_file_gives_the_defaults(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text("{not json")
    assert S.AgentSettings.load(path).to_dict() == S.AgentSettings().to_dict()
    path.write_text("[1, 2]")
    assert S.AgentSettings.load(path).mode == "ask"


def test_sad_invalid_values_take_their_defaults():
    settings = S.AgentSettings.from_dict({
        "mode": "yolo", "max_steps": 0, "max_tool_chars": True, "groups": ["exec", "metadata"],
        "keep_sessions": "yes", "access": {"remote_commands": "true"}, "sandbox": "nope",
    })
    assert settings.mode == "ask"
    assert settings.max_steps == S.DEFAULT_MAX_STEPS
    assert settings.max_tool_chars == S.DEFAULT_MAX_TOOL_CHARS
    assert settings.groups == ("metadata",)
    assert settings.keep_sessions is True
    assert settings.access.remote_commands is False
    assert settings.sandbox == ""


def test_sad_bypass_needs_its_switch():
    assert S.AgentSettings.from_dict({"mode": "bypass"}).mode == "ask"
    assert S.AgentSettings.from_dict({"mode": "bypass", "allow_bypass": True}).mode == "bypass"
    assert "bypass" not in S.AgentSettings().modes()
    assert S.AgentSettings(allow_bypass=True).modes() == S.MODES


# -- edge ----------------------------------------------------------------------


def test_edge_duplicate_and_nameless_sandbox_profiles_are_dropped():
    settings = S.AgentSettings.from_dict({"sandboxes": [
        {"name": "A", "level": "high"}, {"name": "A", "level": "lax"}, {"level": "normal"}, 7,
    ], "sandbox": "A"})
    assert [(p.name, p.level) for p in settings.sandboxes] == [("A", "high")]
    assert settings.sandbox_profile().level == "high"
    assert settings.sandbox_profile("") is None


def test_edge_an_empty_sandbox_list_stays_empty():
    assert S.AgentSettings.from_dict({"sandboxes": []}).sandboxes == []
