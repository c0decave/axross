"""The agent's settings (Tools > Agent Settings…), one JSON file.

``~/.config/axross/agent/settings.json``::

    {
      "version": 1,
      "profile": "",              # LLM profile of new tabs; "" = the active one
      "mode": "ask",              # protection mode of new tabs: ask, plan, auto, bypass
      "allow_bypass": false,      # bypass may be chosen at all
      "max_steps": 20,
      "max_tool_chars": 16000,
      "keep_sessions": true,      # tabs are saved and come back at the next start
      "groups": ["metadata", "filetype", "archive"],
      "access": {"axross_functions": false,   # master switch: tools axross runs outside the sandbox
                 "remote_files": false, "saved_profiles": false, "remote_commands": false,
                 "mcp_servers": true, "extensions": true,    # the ceiling of every tab
                 "files_read_only": false},  # true: no tab changes a file
      "sandbox": "",              # sandbox profile of new tabs; "" = no sandbox
      "mcp_servers": [            # further MCP servers (core.mcp_client)
        {"name": "git", "transport": "stdio", "command": ["mcp-git"], "env": {},
         "url": "", "bearer": false, "enabled": true, "confirm": "always",
         "timeout": 120, "sandbox": "",
         "container": false, "secret_env": [], "egress": [], "package": {}}
      ],
      "mcp_sources": {            # where Add from Catalog searches (core.mcp_catalog)
        "builtin": true, "dockerhub": true, "mcpregistry": true,
        "c0decave": true, "discover": true,
        "extra": ["/home/me/security-catalog.json"]},
      "sandboxes": [              # the sandbox profiles (core.agent_sandbox)
        {"name": "Normal", "engine": "auto", "level": "normal",
         "hosts": ["db.example:5432"], "mounts": [{"path": "/srv/data", "mode": "ro"}],
         "image": "localhost/axross-agent:<version>"}
      ],
      "prompt_profile": "",       # prompt profile of new requests; "" = the built-in Default
      "prompt_profiles": [        # system / user prompt profiles (core.agent_prompts)
        {"name": "Terse", "system_prompt": "You operate axross ...",
         "user_prompt": "Answer in one line: {task}"}
      ],
      "agent_profile": "",        # agent profile new tabs start from; "" = none
      "agent_profiles": [         # the user's agent profiles (core.agent_profiles)
        {"name": "Triage", "llm_profile": "", "prompt_profile": "", "mode": "plan",
         "sandbox": "High", "groups": ["metadata"], "axross": true,
         "functions": ["mcp_servers"], "network": "profile", "hosts": [],
         "files_read_only": true, "allow_write": false, "allow_exec": false,
         "mcp_categories": ["Security: Reverse Engineering"], "mcp_servers": ["git"],
         "description": ""}
      ]
    }

A file without "sandboxes" gets the four presets Lax, Normal, High and
Paranoid.

Anything missing or invalid takes its default; nothing here is a secret
(keys stay in the keyring with the LLM profiles, an MCP server's token
under ``axross-mcp-server/<name>``).
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

from core import agent_profiles as AGP
from core.agent import DEFAULT_MAX_STEPS, DEFAULT_MAX_TOOL_CHARS
from core.agent_prompts import DEFAULT_NAME, PromptProfile, default_profile
from core.agent_sandbox import SandboxProfile, default_profiles, sandbox_command
from core.mcp_catalog import CatalogSources
from core.mcp_client import McpServerConfig

#: Protection modes, least to most trusting; the tool groups a tab can
#: offer (core.mcp_groups) - exec and remote follow the access switches.
MODES, OFFERED_GROUPS, DEFAULT_GROUPS = AGP.MODES, AGP.OFFERED_GROUPS, AGP.DEFAULT_GROUPS

MAX_STEPS_LIMIT = 200
MAX_TOOL_CHARS_LIMIT = 1_000_000


def agent_dir() -> Path:
    return Path.home() / ".config" / "axross" / "agent"


def settings_file() -> Path:
    return agent_dir() / "settings.json"


@dataclass
class Access:
    """The ceiling of every tab (core.agent_access) and what a new tab
    starts with."""

    #: The master switch: the agent may use axross functions at all - the
    #: tools axross runs outside the agent's sandbox, with its own rights.
    axross_functions: bool = False
    #: Files of the remote connections open in the panes.
    remote_files: bool = False
    #: Saved connection profiles the agent may open itself.
    saved_profiles: bool = False
    #: Commands on remote hosts (SSH, WinRM, ...); each one still asks
    #: unless the mode is bypass.
    remote_commands: bool = False
    #: Tools of further MCP servers.
    mcp_servers: bool = True
    #: Tools of axross extensions.
    extensions: bool = True
    #: Files read-only in every tab: agents read files but change none
    #: (core.agent.read_only), whatever a tab chooses.
    files_read_only: bool = False


@dataclass
class AgentSettings:
    profile: str = ""
    mode: str = "ask"
    allow_bypass: bool = False
    max_steps: int = DEFAULT_MAX_STEPS
    max_tool_chars: int = DEFAULT_MAX_TOOL_CHARS
    keep_sessions: bool = True
    groups: tuple[str, ...] = DEFAULT_GROUPS
    access: Access = field(default_factory=Access)
    #: The sandbox profile of new tabs; "" runs the agent without one.
    sandbox: str = ""
    sandboxes: list[SandboxProfile] = field(default_factory=default_profiles)
    mcp_servers: list[McpServerConfig] = field(default_factory=list)
    #: Where Add from Catalog searches for MCP servers.
    mcp_sources: CatalogSources = field(default_factory=CatalogSources)
    #: The prompt profile new requests use; "" is the built-in Default.
    prompt_profile: str = ""
    #: The user's prompt profiles (the built-in Default is not among them).
    prompt_profiles: list[PromptProfile] = field(default_factory=list)
    #: The agent profile new tabs start from (a preset's or the user's
    #: name); "" starts them as the General page says.
    agent_profile: str = ""
    #: The user's agent profiles (core.agent_profiles; the presets are not
    #: among them).
    agent_profiles: list[AGP.AgentProfile] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data) -> AgentSettings:
        out = cls()
        if not isinstance(data, dict):
            return out
        if isinstance(data.get("profile"), str):
            out.profile = data["profile"]
        if data.get("mode") in MODES:
            out.mode = data["mode"]
        for name in ("allow_bypass", "keep_sessions"):
            if isinstance(data.get(name), bool):
                setattr(out, name, data[name])
        for name, limit in (
            ("max_steps", MAX_STEPS_LIMIT),
            ("max_tool_chars", MAX_TOOL_CHARS_LIMIT),
        ):
            value = data.get(name)
            if isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= limit:
                setattr(out, name, value)
        if isinstance(data.get("groups"), list):
            out.groups = tuple(g for g in OFFERED_GROUPS if g in data["groups"])
        access = data.get("access")
        if isinstance(access, dict):
            for name in ("axross_functions", "remote_files", "saved_profiles", "remote_commands",
                         "mcp_servers", "extensions", "files_read_only"):
                if isinstance(access.get(name), bool):
                    setattr(out.access, name, access[name])
        if isinstance(data.get("sandboxes"), list):
            profiles: list[SandboxProfile] = []
            for raw in data["sandboxes"]:
                profile = SandboxProfile.from_dict(raw)
                if profile is not None and profile.name not in (p.name for p in profiles):
                    profiles.append(profile)
            out.sandboxes = profiles
        if isinstance(data.get("sandbox"), str) and (
            data["sandbox"] == "" or data["sandbox"] in (p.name for p in out.sandboxes)
        ):
            out.sandbox = data["sandbox"]
        if isinstance(data.get("mcp_servers"), list):
            servers: list[McpServerConfig] = []
            for raw in data["mcp_servers"]:
                server = McpServerConfig.from_dict(raw)
                if server is not None and server.name not in (s.name for s in servers):
                    servers.append(server)
            out.mcp_servers = servers
        out.mcp_sources = CatalogSources.from_dict(data.get("mcp_sources"))
        if isinstance(data.get("prompt_profiles"), list):
            prompts: list[PromptProfile] = []
            for raw in data["prompt_profiles"]:
                prompt = PromptProfile.from_dict(raw)
                if prompt is not None and prompt.name not in (p.name for p in prompts):
                    prompts.append(prompt)
            out.prompt_profiles = prompts
        if isinstance(data.get("prompt_profile"), str) and (
            data["prompt_profile"] in (p.name for p in out.prompt_profiles)
        ):
            out.prompt_profile = data["prompt_profile"]
        out.agent_profiles = AGP.profiles_from(data.get("agent_profiles"))
        if isinstance(data.get("agent_profile"), str) and AGP.find_profile(
                out, data["agent_profile"]) is not None:
            out.agent_profile = data["agent_profile"]
        if out.mode == "bypass" and not out.allow_bypass:
            out.mode = "ask"
        return out

    def to_dict(self) -> dict:
        data = asdict(self)
        data["groups"] = list(self.groups)
        data["sandboxes"] = [p.to_dict() for p in self.sandboxes]
        data["mcp_servers"] = [s.to_dict() for s in self.mcp_servers]
        data["mcp_sources"] = self.mcp_sources.to_dict()
        data["prompt_profiles"] = [p.to_dict() for p in self.prompt_profiles]
        data["agent_profiles"] = [p.to_dict() for p in self.agent_profiles]
        return {"version": 1, **data}

    def active_prompts(self) -> PromptProfile:
        """The prompt profile new requests use: the chosen one, or the
        built-in Default when none (or a gone one) is chosen."""
        chosen = next((p for p in self.prompt_profiles if p.name == self.prompt_profile), None)
        return chosen if self.prompt_profile and chosen is not None else default_profile()

    def prompts_for(self, name: str) -> PromptProfile:
        """A tab's prompt profile: *name* ("Default" the built-in one), or
        - "" or a gone name - the one new requests use (:meth:`active_prompts`)."""
        if name == DEFAULT_NAME:
            return default_profile()
        chosen = next((p for p in self.prompt_profiles if p.name == name), None) if name else None
        return chosen if chosen is not None else self.active_prompts()

    def sandbox_profile(self, name: str | None = None) -> SandboxProfile | None:
        """The sandbox profile *name* (default: new tabs'), None for none."""
        name = self.sandbox if name is None else name
        return next((p for p in self.sandboxes if p.name == name), None) if name else None

    @classmethod
    def load(cls, path: Path | None = None) -> AgentSettings:
        try:
            raw = json.loads(Path(path or settings_file()).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return cls()
        return cls.from_dict(raw)

    def save(self, path: Path | None = None) -> None:
        path = Path(path or settings_file())
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, indent=2)
        os.replace(tmp, path)

    def mcp_wrap(self, server):
        """What runs a stdio MCP server in its sandbox profile: argv -> argv,
        or None without one. A profile that no longer exists refuses the
        start (core.mcp_client.McpClientError) - never a run without it. A
        container server is its own sandbox (podman)."""
        if not server.sandbox or server.container:
            return None
        from core.mcp_client import McpClientError

        profile = self.sandbox_profile(server.sandbox)
        if profile is None:
            raise McpClientError(f"its sandbox profile {server.sandbox!r} does not exist")
        home = agent_dir() / "mcp" / server.name
        home.mkdir(parents=True, exist_ok=True)
        os.chmod(home, 0o700)
        return lambda argv: sandbox_command(profile, str(home), writable=True, inner=argv)

    def modes(self) -> tuple[str, ...]:
        """The modes a tab may choose: bypass only when switched on."""
        return MODES if self.allow_bypass else tuple(m for m in MODES if m != "bypass")
