"""Prompt profiles: the agent's system prompt and user prompt, by name.

A profile has a system prompt (the rules the model gets first; the dock
adds the folder lines, the plan-mode and the voice additions to it) and a
user prompt, a template for every task typed into an Agent tab:
``{task}`` in it becomes the task, and a template without ``{task}`` goes
in front of the task. An empty user prompt sends the task as typed.

The built-in profile "Default" is :data:`core.agent.SYSTEM_PROMPT` with no
user prompt; it is not stored and cannot be changed or deleted. The
user's profiles and the active one live in the agent's settings
(core.agent_settings, ``prompt_profiles`` and ``prompt_profile``) and are
edited in Edit > Settings > Agent > Prompts.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.agent import SYSTEM_PROMPT

DEFAULT_NAME = "Default"
MAX_NAME = 80
MAX_SYSTEM = 50_000
MAX_USER = 20_000
#: What a user prompt's ``{task}`` is replaced with: the typed task.
TASK_FIELD = "{task}"


@dataclass
class PromptProfile:
    name: str
    system_prompt: str
    #: A template for the task: "{task}" is the typed task; without it the
    #: text goes in front of the task; "" sends the task as typed.
    user_prompt: str = ""
    #: The built-in Default (never stored, never changed).
    builtin: bool = False

    def problems(self) -> list[str]:
        """Why the profile cannot be stored ([] when it can)."""
        out = []
        if not isinstance(self.name, str) or not self.name.strip():
            out.append("A prompt profile has no name.")
        elif len(self.name) > MAX_NAME:
            out.append(f"The prompt profile name {self.name[:20]}… is longer than {MAX_NAME} "
                       "characters.")
        elif self.name.strip().casefold() == DEFAULT_NAME.casefold():
            out.append(f"The name {DEFAULT_NAME} belongs to the built-in prompt profile.")
        label = self.name.strip() if isinstance(self.name, str) and self.name.strip() else "?"
        if not isinstance(self.system_prompt, str) or not self.system_prompt.strip():
            out.append(f"The prompt profile {label} has no system prompt.")
        elif len(self.system_prompt) > MAX_SYSTEM:
            out.append(f"The system prompt of {label} is longer than {MAX_SYSTEM} characters.")
        if not isinstance(self.user_prompt, str):
            out.append(f"The user prompt of {label} is not text.")
        elif len(self.user_prompt) > MAX_USER:
            out.append(f"The user prompt of {label} is longer than {MAX_USER} characters.")
        return out

    def to_dict(self) -> dict:
        return {"name": self.name, "system_prompt": self.system_prompt,
                "user_prompt": self.user_prompt}

    @classmethod
    def from_dict(cls, raw) -> PromptProfile | None:
        """A stored profile, or None when the entry is not a valid one."""
        if not isinstance(raw, dict):
            return None
        profile = cls(name=raw.get("name"), system_prompt=raw.get("system_prompt"),
                      user_prompt=raw.get("user_prompt", "") if "user_prompt" in raw else "")
        if profile.problems():
            return None
        profile.name = profile.name.strip()
        return profile


def default_profile() -> PromptProfile:
    """The built-in profile: axross's own rules, no user prompt."""
    return PromptProfile(DEFAULT_NAME, SYSTEM_PROMPT, "", builtin=True)


def render_task(user_prompt: str, task: str) -> str:
    """*task* as the model gets it under *user_prompt* (see the module
    docstring). Braces in the task stay as they are."""
    if not isinstance(user_prompt, str) or not user_prompt.strip():
        return task
    if TASK_FIELD in user_prompt:
        return user_prompt.replace(TASK_FIELD, task)
    return user_prompt.rstrip() + "\n\n" + task
