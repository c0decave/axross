"""Agent profiles: a named bundle of an Agent tab's settings.

An agent profile sets up a tab in one go - for a new tab (*New Tab from
Profile*) or the current one (*Apply Profile…*):

=================  ==========================================================
``llm_profile``    the LLM profile ("" = the default model)
``prompt_profile`` the prompt profile ("" = Agent Settings > Prompts' choice,
                   "Default" = axross's own prompt)
``mode``           ask, plan, auto or bypass (bypass only where allowed)
``sandbox``        the sandbox profile ("" = none)
``groups``         the tool groups (core.agent_settings.OFFERED_GROUPS)
``axross``,        the tab's axross functions (core.agent_access): the master
``functions``,     switch, the functions, the network and its hosts
``network``,
``hosts``
``files_read_only`` the tab's Files read-only switch
``allow_write``,   Allow changes to files / Allow remote commands
``allow_exec``
``mcp_categories`` MCP servers by the catalog category they were installed
                   from ("Security: Reverse Engineering", "Files & Dev", ...)
``mcp_servers``    MCP servers by name (or by the catalog entry they were
                   installed from, so a renamed server still matches)
=================  ==========================================================

The user's profiles live in the agent's settings file
(core.agent_settings, ``agent_profiles``, and ``agent_profile``: the one
new tabs start from). The file is untrusted data like the rest of it:
unknown keys are dropped, a value of the wrong type takes its default, a
name that is taken (also by a preset) drops the entry.

**Presets** (:func:`presets`) are built in, read-only and never stored;
*Copy* makes an editable profile of one.

**Applying never widens Agent Settings > Access**: :func:`resolve` returns
the tab's settings within that ceiling and says what it cut (``notes``)
and which MCP servers the profile wants that are not there or switched
off (``missing``). A preset whose servers are not installed still sets up
the rest of the tab.
"""

from __future__ import annotations

import dataclasses
import functools
import logging
import re
from dataclasses import dataclass, field

from core.agent_access import FUNCTIONS, NETWORKS, SessionAccess, clean_hosts, network_choices
from core.mcp_client import MAX_CATEGORY  # longest category text, as a server keeps it

log = logging.getLogger(__name__)

MAX_NAME = 80
MAX_DESCRIPTION = 500
#: Most categories or server names one profile names, most profiles kept.
MAX_ENTRIES = 50
MAX_PROFILES = 200
#: What a session's tool groups call an MCP server (ui.agent_dock).
MCP_PREFIX = "mcp:"
_SERVER_NAME = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
#: Protection modes, least to most trusting, and the tool groups a tab can
#: offer (core.mcp_groups; exec and remote follow the access switches);
#: core.agent_settings takes them from here.
MODES: tuple[str, ...] = ("ask", "plan", "auto", "bypass")
OFFERED_GROUPS: tuple[str, ...] = ("metadata", "filetype", "archive", "duplicates", "index",
                                   "packer", "crypto", "transfer")
DEFAULT_GROUPS: tuple[str, ...] = ("metadata", "filetype", "archive")

#: The categories of the c0decave MCP Hub (core.mcp_catalog.HUB_URL), as its
#: catalog names them. The shipped catalog's come from the file itself.
HUB_CATEGORIES: tuple[str, ...] = (
    "Security: Code & Secrets",
    "Security: Firmware & Forensics",
    "Security: Network Recon",
    "Security: OSINT",
    "Security: Passwords & Crypto",
    "Security: Reverse Engineering",
    "Security: Web",
)


def _clean(value, limit: int) -> str:
    """*value* when it is clean one-line text of at most *limit* characters
    (nothing a cleaning would change), else ""."""
    from core.mcp_catalog import exact_text

    return exact_text(value, limit)


def _texts(raw, limit: int, *, pattern: re.Pattern | None = None) -> tuple[str, ...]:
    """The clean, distinct texts of the list *raw* (at most MAX_ENTRIES)."""
    if not isinstance(raw, list):
        return ()
    out: list[str] = []
    for value in raw:
        text = _clean(value, limit)
        if not text or (pattern is not None and not pattern.match(text)):
            continue
        if text.casefold() not in (o.casefold() for o in out):
            out.append(text)
    return tuple(out[:MAX_ENTRIES])


@dataclass
class AgentProfile:
    name: str
    llm_profile: str = ""
    prompt_profile: str = ""
    mode: str = "ask"
    sandbox: str = ""
    groups: tuple[str, ...] = DEFAULT_GROUPS
    axross: bool = False
    functions: tuple[str, ...] = ()
    network: str = "profile"
    hosts: tuple[str, ...] = ()
    files_read_only: bool = False
    allow_write: bool = False
    allow_exec: bool = False
    mcp_categories: tuple[str, ...] = ()
    mcp_servers: tuple[str, ...] = ()
    description: str = ""
    #: Built in and read-only; never stored, never read from a file.
    preset: bool = False

    def problems(self) -> list[str]:
        """Why the profile cannot be stored ([] when it can)."""
        name = self.name if isinstance(self.name, str) else ""
        if not name.strip():
            return ["An agent profile has no name."]
        if len(name.strip()) > MAX_NAME:
            return [f"The agent profile name {name[:20]}… is longer than {MAX_NAME} characters."]
        if not _clean(name, MAX_NAME):
            return [f"The agent profile name {name[:20]!r} has characters a name cannot have."]
        if not self.preset and name.strip().casefold() in (n.casefold() for n in preset_names()):
            return [f"The name {name.strip()} belongs to a preset."]
        return []

    def to_dict(self) -> dict:
        data = dataclasses.asdict(self)
        data.pop("preset")
        for key in ("groups", "functions", "hosts", "mcp_categories", "mcp_servers"):
            data[key] = list(data[key])
        return data

    @classmethod
    def from_dict(cls, raw) -> AgentProfile | None:
        """A stored profile, or None when the entry is no valid one; any
        other value of the wrong type or shape takes its default."""
        if not isinstance(raw, dict) or not isinstance(raw.get("name"), str):
            return None
        out = cls(name=raw["name"].strip())
        if out.problems():
            return None
        for key, limit in (("llm_profile", MAX_NAME), ("prompt_profile", MAX_NAME),
                           ("sandbox", MAX_NAME)):
            setattr(out, key, _clean(raw.get(key), limit))
        out.description = _clean(raw.get("description"), MAX_DESCRIPTION)
        if raw.get("mode") in MODES:
            out.mode = raw["mode"]
        if isinstance(raw.get("groups"), list):
            out.groups = tuple(g for g in OFFERED_GROUPS if g in raw["groups"])
        for key in ("axross", "files_read_only", "allow_write", "allow_exec"):
            if isinstance(raw.get(key), bool):
                setattr(out, key, raw[key])
        if isinstance(raw.get("functions"), list):
            out.functions = tuple(f for f in FUNCTIONS if f in raw["functions"])
        if raw.get("network") in NETWORKS:
            out.network = raw["network"]
        if isinstance(raw.get("hosts"), list):
            out.hosts = clean_hosts(raw["hosts"])[:MAX_ENTRIES]
        out.mcp_categories = _texts(raw.get("mcp_categories"), MAX_CATEGORY)
        out.mcp_servers = _texts(raw.get("mcp_servers"), 32, pattern=_SERVER_NAME)
        return out

    def copy(self, name: str) -> AgentProfile:
        """An editable copy named *name*."""
        return dataclasses.replace(self, name=name, preset=False)


def _preset(name: str, description: str, **kw) -> AgentProfile:
    return AgentProfile(name=name, description=description, preset=True, **kw)


def presets() -> list[AgentProfile]:
    """The built-in profiles, new objects on every call."""
    return [
        _preset("Files Assistant",
                "axross's file tools on the folder and the remote connections open in the "
                "panes; changes ask first; no MCP servers.",
                groups=("metadata", "filetype", "archive", "duplicates", "index", "packer"),
                axross=True, functions=("remote_files",), allow_write=True),
        _preset("Reverse Engineering",
                "MCP servers of the categories Reverse Engineering and Firmware & Forensics "
                "(radare2, capa, floss, binwalk, yara, ...), in the High sandbox.",
                sandbox="High", axross=True, functions=("mcp_servers",),
                mcp_categories=("Security: Reverse Engineering",
                                "Security: Firmware & Forensics")),
        _preset("Forensics read-only",
                "MCP servers of the category Firmware & Forensics (sleuthkit, exiftool, "
                "tshark, ...); files read-only.",
                groups=("metadata", "filetype", "archive", "duplicates"), axross=True,
                functions=("mcp_servers",), files_read_only=True,
                mcp_categories=("Security: Firmware & Forensics",)),
        _preset("Network & Web Recon",
                "MCP servers of the categories Network Recon, Web and OSINT (nmap, nuclei, "
                "ffuf, crtsh, ...); every change asks.",
                groups=("metadata", "filetype"), axross=True, functions=("mcp_servers",),
                mcp_categories=("Security: Network Recon", "Security: Web",
                                "Security: OSINT")),
        _preset("Code & Secrets",
                "The git and filesystem MCP servers and the category Code & Secrets "
                "(gitleaks).",
                axross=True, functions=("mcp_servers",), mcp_servers=("git", "filesystem"),
                mcp_categories=("Security: Code & Secrets",)),
        _preset("Remote Ops",
                "axross's remote functions: the open connections, saved connections the "
                "agent opens itself and commands on remote hosts; every command asks.",
                groups=("metadata", "filetype", "transfer"), axross=True,
                functions=("remote_files", "saved_profiles", "remote_commands"),
                allow_exec=True),
        _preset("Research",
                "The fetch, memory and sequentialthinking MCP servers. Not Files read-only: "
                "fetch needs network, and under read-only only a container server without "
                "network keeps its tools - so axross changes no file here because Allow "
                "changes to files is off, and every MCP call asks as its server says.",
                groups=("metadata", "filetype"), axross=True, functions=("mcp_servers",),
                mcp_servers=("fetch", "memory", "sequentialthinking")),
    ]


def preset_names() -> tuple[str, ...]:
    return tuple(p.name for p in presets())


def preset(name: str) -> AgentProfile | None:
    return next((p for p in presets() if p.name == name), None)


def all_profiles(settings) -> list[AgentProfile]:
    """The presets, then the user's profiles (the order the menus show)."""
    return [*presets(), *getattr(settings, "agent_profiles", [])]


def find_profile(settings, name: str) -> AgentProfile | None:
    if not name:
        return None
    return next((p for p in all_profiles(settings) if p.name == name), None)


def free_profile_name(base: str, taken) -> str:
    """``"<base> copy"``, numbered when that is taken (presets count)."""
    names = {n.casefold() for n in [*taken, *preset_names()]}
    name, n = f"{base} copy", 1
    while name.casefold() in names:
        n += 1
        name = f"{base} copy {n}"
    return name[:MAX_NAME]


def profiles_from(raw) -> list[AgentProfile]:
    """The valid profiles of a settings file's ``agent_profiles`` list:
    the first of a name wins (case-insensitive), at most MAX_PROFILES."""
    out: list[AgentProfile] = []
    if not isinstance(raw, list):
        return out
    for entry in raw:
        profile = AgentProfile.from_dict(entry)
        if profile is None:
            continue
        if profile.name.casefold() in (p.name.casefold() for p in out):
            log.warning("agent profiles: a second profile named %r is left out", profile.name)
            continue
        out.append(profile)
        if len(out) >= MAX_PROFILES:
            break
    return out


# -- categories of MCP servers ---------------------------------------------------------


@functools.lru_cache(maxsize=1)
def _builtin_entries() -> dict[str, str]:
    """The shipped catalog's entry id -> category."""
    from core import mcp_catalog as M

    try:
        entries, _warnings = M.load_builtin()
    except Exception as exc:  # noqa: BLE001 - a broken catalog file: no categories from it
        log.warning("agent profiles: the built-in catalog is unreadable: %s", exc)
        return {}
    return {e.id: e.category for e in entries}


def server_category(server) -> str:
    """The catalog category of an MCP server: the one recorded at install
    (or set in Agent Settings > MCP Servers), else - a server installed
    before categories were recorded - the shipped catalog's for its entry."""
    category = getattr(server, "category", "") or ""
    if category:
        return category
    package = getattr(server, "package", None) or {}
    if package.get("source") == "builtin":
        return _builtin_entries().get(package.get("entry", ""), "")
    return ""


def known_categories(servers=()) -> list[str]:
    """Every category a profile can name: the shipped catalog's, the
    c0decave hub's and those of the configured *servers*."""
    found = {*_builtin_entries().values(), *HUB_CATEGORIES,
             *(server_category(s) for s in servers)}
    unique: dict[str, str] = {}
    for category in found:
        if category:
            unique.setdefault(category.casefold(), category)
    return sorted(unique.values(), key=str.casefold)


def _key(text: str) -> str:
    return text.strip().casefold()


def _matches_name(server, names: set[str]) -> bool:
    entry = (getattr(server, "package", None) or {}).get("entry", "")
    return _key(server.name) in names or bool(entry and _key(entry) in names)


# -- applying ----------------------------------------------------------------------------


@dataclass
class Missing:
    #: "category" or "server".
    kind: str
    name: str
    #: "not installed" or "switched off".
    why: str


@dataclass
class Resolution:
    """A tab's settings as a profile gives them within the ceiling."""

    profile: str = ""
    prompt_profile: str = ""
    mode: str = "ask"
    sandbox: str = ""
    #: The tool groups and one "mcp:<name>" per chosen MCP server.
    groups: list[str] = field(default_factory=list)
    servers: list[str] = field(default_factory=list)
    allow_write: bool = False
    allow_exec: bool = False
    files_read_only: bool = False
    access: SessionAccess = field(default_factory=SessionAccess)
    #: What Agent Settings (the ceiling) or a gone name changed, one line each.
    notes: list[str] = field(default_factory=list)
    missing: list[Missing] = field(default_factory=list)

    def apply_to(self, session, profile_name: str) -> None:
        """Set *session* (core.agent_session.AgentSession) as resolved; its
        folder, extra folders and conversation stay."""
        session.agent_profile = profile_name
        session.profile = self.profile
        session.prompt_profile = self.prompt_profile
        session.mode = self.mode
        session.sandbox = self.sandbox
        session.groups = list(self.groups)
        session.allow_write = self.allow_write
        session.allow_exec = self.allow_exec
        session.files_read_only = self.files_read_only
        session.access = dataclasses.replace(self.access)


FUNCTION_NAMES = {
    "remote_files": "remote files",
    "saved_profiles": "saved connections",
    "remote_commands": "remote commands",
    "mcp_servers": "MCP servers",
    "extensions": "extension tools",
}


def resolve(profile: AgentProfile, settings, *, llm_names=None, modes=None) -> Resolution:
    """What *profile* gives a tab under *settings* (core.agent_settings):
    never more than Agent Settings > Access allows. *llm_names* are the
    LLM profiles that exist (None: not checked); *modes* the modes a tab
    may choose (default: the settings')."""
    out = Resolution()
    notes = out.notes
    ceiling = settings.access
    if profile.llm_profile and llm_names is not None and profile.llm_profile not in llm_names:
        notes.append(f"The LLM profile {profile.llm_profile} does not exist: the default "
                     "model is used.")
    else:
        out.profile = profile.llm_profile
    from core.agent_prompts import DEFAULT_NAME

    prompt_names = {DEFAULT_NAME, *(p.name for p in settings.prompt_profiles)}
    if profile.prompt_profile and profile.prompt_profile not in prompt_names:
        notes.append(f"The prompt profile {profile.prompt_profile} does not exist: Agent "
                     "Settings > Prompts' choice is used.")
    else:
        out.prompt_profile = profile.prompt_profile
    modes = tuple(modes) if modes is not None else tuple(settings.modes())
    if profile.mode in modes:
        out.mode = profile.mode
    else:
        out.mode = "ask"
        notes.append(f"{profile.mode.capitalize()} mode may not be chosen here (Agent "
                     "Settings > General): the tab asks.")
    out.sandbox = profile.sandbox
    sandbox = settings.sandbox_profile(profile.sandbox) if profile.sandbox else None
    if profile.sandbox and sandbox is None:
        notes.append(f"The sandbox profile {profile.sandbox} does not exist: the tab refuses "
                     "to run until a sandbox is chosen.")
    out.groups = [g for g in OFFERED_GROUPS if g in profile.groups]

    # axross functions, within the ceiling.
    master = profile.axross and bool(getattr(ceiling, "axross_functions", False))
    if profile.axross and not master:
        notes.append("axross functions are off in Agent Settings > Access: the tab gets none "
                     "(" + ", ".join(FUNCTION_NAMES[f] for f in profile.functions) + ")."
                     if profile.functions else
                     "axross functions are off in Agent Settings > Access: the tab gets none.")
    functions = tuple(f for f in profile.functions if getattr(ceiling, f, False))
    cut = [f for f in profile.functions if f not in functions]
    if master and cut:
        notes.append("Off in Agent Settings > Access: "
                     + ", ".join(FUNCTION_NAMES[f] for f in cut) + ".")
    network = profile.network
    choices = network_choices(sandbox) if profile.sandbox else network_choices(None)
    if network not in choices:
        notes.append(f"The sandbox level allows no network {network!r}: the sandbox profile's "
                     "network is used.")
        network = "profile"
    out.access = SessionAccess(axross=master, functions=functions if master else (),
                               network=network,
                               hosts=tuple(profile.hosts) if network == "hosts" else ())

    # Files.
    out.files_read_only = profile.files_read_only
    read_only = profile.files_read_only or bool(getattr(ceiling, "files_read_only", False))
    if getattr(ceiling, "files_read_only", False) and not profile.files_read_only:
        notes.append("Agent Settings > Access makes files read-only in every tab.")
    out.allow_write = profile.allow_write and not read_only
    out.allow_exec = profile.allow_exec and not read_only
    if out.allow_exec and "remote_commands" not in out.access.functions:
        notes.append("Remote commands are not allowed (Agent Settings > Access or the "
                     "profile's functions): Allow remote commands stays off.")
        out.allow_exec = False

    # MCP servers by category and name.
    names = {_key(n) for n in profile.mcp_servers}
    categories = {_key(c) for c in profile.mcp_categories}
    chosen = []
    for server in settings.mcp_servers:
        if not server.enabled:
            continue
        if _matches_name(server, names) or _key(server_category(server)) in categories:
            chosen.append(server.name)
    out.servers = sorted(chosen, key=str.casefold)
    out.groups += [MCP_PREFIX + n for n in out.servers]
    for wanted in profile.mcp_servers:
        if any(_matches_name(s, {_key(wanted)}) for s in settings.mcp_servers if s.enabled):
            continue
        off = any(_matches_name(s, {_key(wanted)}) for s in settings.mcp_servers)
        out.missing.append(Missing("server", wanted, "switched off" if off else "not installed"))
    for wanted in profile.mcp_categories:
        servers = [s for s in settings.mcp_servers if _key(server_category(s)) == _key(wanted)]
        if any(s.enabled for s in servers):
            continue
        out.missing.append(Missing("category", wanted.strip(),
                                   "switched off" if servers else "not installed"))
    if read_only:
        # core.mcp_client marks every tool of an "Every call asks" server as one
        # that may change something; Files read-only keeps those only of a
        # server that cannot change the user's files (McpServerConfig.files_risk).
        for server in settings.mcp_servers:
            if server.name not in out.servers or getattr(server, "confirm", "always") != "always":
                continue
            risk = server.files_risk()
            if risk:
                notes.append(
                    f"Files are read-only: none of {server.name}'s tools is offered - it asks "
                    f"before every call and {risk}. Only a container server without network "
                    "and with read-only folders keeps its tools under Files read-only (each "
                    "call still asks).")
    if out.servers and "mcp_servers" not in out.access.functions:
        notes.append("MCP servers are not allowed (Agent Settings > Access or the profile's "
                     "functions): " + ", ".join(out.servers) + " are not offered.")
    return out


def missing_text(missing: Missing) -> str:
    """One line about a server a profile wants that the tab does not get."""
    what = (f"MCP servers of the category {missing.name}" if missing.kind == "category"
            else f"The MCP server {missing.name}")
    if missing.why == "switched off":
        return f"{what}: switched off in Agent Settings > MCP Servers."
    return f"{what}: not installed."


def summary_lines(profile: AgentProfile, res: Resolution) -> list[str]:
    """What applying *profile* gives a tab (*res*), line by line: the
    settings, then what the ceiling cut, then what is missing."""
    functions = ", ".join(FUNCTION_NAMES[f] for f in res.access.functions)
    lines = [
        f"Mode: {res.mode}" + (f" - sandbox: {res.sandbox}" if res.sandbox else " - no sandbox"),
        "Tool groups: " + (", ".join(g for g in res.groups if not g.startswith(MCP_PREFIX))
                           or "none"),
        "axross functions: " + ((functions or "none") if res.access.axross else "off"),
        "Files: " + ("read-only" if res.files_read_only else
                     "changes allowed (each one asks in Ask mode)" if res.allow_write
                     else "read, no changes"),
        "MCP servers: " + (", ".join(res.servers) or "none"),
    ]
    if res.profile:
        lines.insert(0, f"LLM profile: {res.profile}")
    if res.prompt_profile:
        lines.insert(1 if res.profile else 0, f"Prompt profile: {res.prompt_profile}")
    lines += res.notes
    lines += [missing_text(m) for m in res.missing]
    return lines
