"""What one agent tab may reach: its axross functions, its network, its folders.

Two layers decide, and both must say yes:

* **Agent Settings > Access** is the ceiling (and what a new tab starts
  with). A function switched off there is off in every tab.
* **The tab's session** (:class:`SessionAccess`) chooses within it.

**axross functions** are the tools axross runs itself, on the agent's
behalf, *outside* the agent's sandbox and with axross's own rights:

================  ==================================================
function          what it reaches
================  ==================================================
remote_files      the remote connections open in the panes
saved_profiles    saved connections the agent opens itself
remote_commands   commands on remote hosts (SSH, WinRM, ...)
mcp_servers       further MCP servers (they run beside axross)
extensions        tools of axross extensions (Python in axross)
================  ==================================================

A sandbox keeps the agent's own code in; these functions are the way out
of it, which is why the master switch (``axross``) exists and is off by
default. ask_user and update_plan reach nothing outside and are no
function in this sense.

**Network**: ``profile`` (as the sandbox profile says; without a sandbox:
no limit), ``none``, ``hosts`` (only the tab's own ``host:port`` list) or
``all``. The sandbox level stays the ceiling: a tab only ever narrows
what its level can do (paranoid reaches nothing, normal and high no more
than a host list, only lax and "no sandbox" all hosts). The network
gates the sandbox's own connections, remote work in axross and http MCP
servers alike.

**Folders** are the session's ``extra_folders``: ``(path, writable)``.
Writable only where the level lets extra folders be (lax, normal) and
the tab allows changes.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Callable

from core.agent_net import parse_hosts

#: The axross functions, in the order the dialogs show them.
FUNCTIONS: tuple[str, ...] = (
    "remote_files",
    "saved_profiles",
    "remote_commands",
    "mcp_servers",
    "extensions",
)
#: The network choices of a tab, loosest last.
NETWORKS: tuple[str, ...] = ("profile", "none", "hosts", "all")


def _host_text(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def clean_hosts(entries) -> tuple[str, ...]:
    """The valid ``host:port`` entries of *entries*, normalised, in order."""
    return tuple(
        _host_text(h, p) for h, p in parse_hosts(e for e in entries or () if isinstance(e, str))
    )


@dataclass
class SessionAccess:
    #: The master switch: may the agent use axross functions at all?
    axross: bool = False
    #: The functions this tab allows (when the master switch is on).
    functions: tuple[str, ...] = FUNCTIONS
    network: str = "profile"
    #: The tab's own hosts, used when *network* is "hosts".
    hosts: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_settings(cls, access) -> SessionAccess:
        """A new tab's access: the master switch as Agent Settings has it,
        every function the ceiling allows (now and later)."""
        return cls(axross=bool(getattr(access, "axross_functions", False)))

    def to_dict(self) -> dict:
        return {"axross": self.axross, "functions": list(self.functions), "network": self.network,
                "hosts": list(self.hosts)}

    @classmethod
    def from_dict(cls, data) -> SessionAccess | None:
        if not isinstance(data, dict):
            return None
        out = cls()
        if isinstance(data.get("axross"), bool):
            out.axross = data["axross"]
        if isinstance(data.get("functions"), list):
            out.functions = tuple(f for f in FUNCTIONS if f in data["functions"])
        if data.get("network") in NETWORKS:
            out.network = data["network"]
        if isinstance(data.get("hosts"), list):
            out.hosts = clean_hosts(data["hosts"])
        return out


def allowed_functions(settings_access, access: SessionAccess | None) -> frozenset[str]:
    """The functions a tab may use: on in Agent Settings *and* in the tab."""
    if (
        access is None
        or not access.axross
        or not getattr(settings_access, "axross_functions", False)
    ):
        return frozenset()
    return frozenset(
        f for f in access.functions if f in FUNCTIONS and getattr(settings_access, f, False)
    )


def network_choices(profile) -> tuple[str, ...]:
    """The network choices a tab in *profile* (None: no sandbox) can make."""
    if profile is None:
        return NETWORKS
    level = profile.rules.network
    if level == "none":
        return ("profile", "none")
    if level == "allowlist":
        return ("profile", "none", "hosts")
    return NETWORKS


def session_profile(profile, access: SessionAccess | None):
    """*profile* as the tab's network makes it - a copy, never wider than
    the level. None (no sandbox) stays None: :func:`firewall` covers that."""
    if profile is None or access is None or access.network in ("profile", "all"):
        return profile
    if access.network == "none":
        return dataclasses.replace(profile, net="none", hosts=())
    return dataclasses.replace(profile, net="allowlist", hosts=clean_hosts(access.hosts))


def firewall(access: SessionAccess | None) -> Callable[[str, int], bool] | None:
    """Whether ``(host, port)`` may be reached by a tab without a sandbox
    (remote work and http MCP servers in axross); None: no limit. The
    hosts are read at every call - a removed host is refused at once."""
    if access is None or access.network in ("profile", "all"):
        return None

    def allowed(host: str, port: int) -> bool:
        if access.network == "none":
            return False
        if access.network == "hosts":
            try:
                return (str(host).lower(), int(port)) in parse_hosts(access.hosts)
            except (TypeError, ValueError):
                return False
        return True

    return allowed
