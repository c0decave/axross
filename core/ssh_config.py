"""Parse ~/.ssh/config and extract host definitions."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

MAX_SSH_CONFIG_BYTES = 1024 * 1024


@dataclass
class SSHHostConfig:
    """Parsed SSH host configuration."""

    alias: str = ""
    hostname: str = ""
    port: int = 22
    user: str = ""
    identity_file: str = ""
    proxy_command: str = ""
    address_family: str = "auto"  # "auto", "ipv4", "ipv6"


#: Characters a host or user name must not bring into a ProxyCommand: what
#: OpenSSH 9.6 refuses there (CVE-2023-51385) - shell syntax and quotes.
_PROXY_NAME_FORBIDDEN = frozenset("'`\"$\\;&<>|(){}*?[]!~#")


def _refuse_shell_syntax(value: str, what: str) -> None:
    """ValueError when *value* (the profile's host or user name) would be
    shell syntax or an option in a ProxyCommand: a common one starts a
    shell (``sh -c 'nc %h %p'``) or passes %h as an argument (``nc %h
    %p``), so a host name such as ``x$(touch /tmp/p)`` or ``-e/bin/sh``
    ran a command on this machine."""
    bad = (
        value.startswith("-")
        or any(ch in _PROXY_NAME_FORBIDDEN or ch.isspace() or not ch.isprintable() for ch in value)
    )
    if bad:
        from core.i18n import tr

        text = (
            tr("The host name {value} cannot be put into the ProxyCommand: it holds "
               "characters a shell would interpret, or starts with '-'. Check the "
               "profile's host name; the ProxyCommand runs on this computer.")
            if what == "host name" else
            tr("The user name {value} cannot be put into the ProxyCommand: it holds "
               "characters a shell would interpret, or starts with '-'. Check the "
               "profile's user name; the ProxyCommand runs on this computer.")
        )
        raise ValueError(text.format(value=repr(value)))


def require_confirmed_proxy_command(profile) -> None:
    """PermissionError when *profile*'s ProxyCommand came in through an
    import (an SSH config, a profiles file) and nobody confirmed it yet:
    it is someone else's shell command and runs on this computer. Every
    session that would start it asks this, not only the ConnectionManager
    (Deploy SSH Key builds its own session)."""
    command = getattr(profile, "proxy_command", "")
    if command and not getattr(profile, "proxy_command_confirmed", True):
        raise PermissionError(
            f"profile {getattr(profile, 'name', '')!r} came in through an import and its "
            f"ProxyCommand ({command!r}) has not been confirmed; "
            "confirm it in axross before it can run"
        )


def expand_proxy_command(
    command: str,
    *,
    host: str,
    port: int,
    username: str,
    resolve_profile: object | None = None,
) -> str:
    """Expand the common OpenSSH percent tokens used in ProxyCommand.

    If *resolve_profile* is provided (a callable ``name -> ConnectionProfile | None``),
    bare SSH-config-style aliases in ``ssh … <alias>`` patterns are expanded to their
    full connection parameters so the system SSH can reach them even if the alias only
    exists in the Axross profile database.
    """
    for token, value, what in (("%h", host, "host name"), ("%r", username, "user name")):
        if token in command.replace("%%", ""):
            _refuse_shell_syntax(value, what)
    # For -W flag: IPv6 addresses need bracket notation [addr]:port
    is_ipv6 = ":" in host
    host_for_w = f"[{host}]" if is_ipv6 else host

    tokens = {
        "h": host,
        "p": str(port),
        "r": username,
        "%": "%",
    }
    expanded: list[str] = []
    i = 0
    while i < len(command):
        if command[i] != "%" or i + 1 >= len(command):
            expanded.append(command[i])
            i += 1
            continue
        token = command[i + 1]
        expanded.append(tokens.get(token, f"%{token}"))
        i += 2
    result = "".join(expanded)

    # Fix -W with IPv6: replace -W <ipv6>:<port> with -W [<ipv6>]:<port>
    if is_ipv6:
        result = result.replace(f"-W {host}:{port}", f"-W {host_for_w}:{port}")

    # Resolve Axross profile aliases in "ssh … <alias>" patterns
    if resolve_profile is not None:
        result = _resolve_ssh_aliases(result, resolve_profile)

    return result


def _resolve_ssh_aliases(command: str, resolve_profile) -> str:
    """Replace bare profile-name aliases in ssh sub-commands with full connection details.

    Handles patterns like:
        ssh -W %h:%p bastion
    →   ssh -i /path/key -p 123 root@1.2.3.4 -W %h:%p
    """
    # Match "ssh [options] <alias>" at the end or "ssh [options] <alias> <more>"
    # where <alias> is the last non-flag argument before any trailing flags/args
    import shlex

    parts = shlex.split(command)
    if not parts or parts[0] not in ("ssh", "/usr/bin/ssh"):
        return command

    # Find the last argument that isn't a flag value — that's the target host
    # ssh [-flag value]... [-W %h:%p] <target>
    i = len(parts) - 1
    target = parts[i]

    # Skip if it looks like a user@host (already resolved), a flag, or IP/FQDN
    if "@" in target or target.startswith("-"):
        return command

    profile = resolve_profile(target)
    if profile is None:
        return command
    # The profile's host and user name become ssh's destination argument:
    # one starting with "-" would be an option there (-oProxyCommand=...
    # runs a command on this machine). Quoting does not help against that.
    for value, what in ((profile.host, "host name"), (profile.username or "", "user name")):
        if value.startswith("-"):
            _refuse_shell_syntax(value, what)

    # Build the replacement: inject connection details before the target
    host_part = f"{profile.username}@{profile.host}" if profile.username else profile.host
    replacement = [parts[0]]
    if profile.key_file:
        replacement += ["-i", profile.key_file]
    if profile.port != 22:
        replacement += ["-p", str(profile.port)]
    replacement += parts[1:i]  # Keep original flags (-W %h:%p etc.)
    replacement.append(host_part)

    return " ".join(shlex.quote(p) for p in replacement)


_PROXY_JUMP_DEST = re.compile(r"(?:ssh://)?(?:(?P<user>[^@]+)@)?(?P<host>\[[^\]]+\]|[^:]+)(?::(?P<port>\d+))?")


def proxy_jump_command(value: str) -> str:
    """The ProxyCommand that does what ``ProxyJump`` *value* does; "" for
    ``none`` or a value that cannot be one (a hop starting with "-" would
    be an option of ssh, not a host).

    ``ProxyJump a,b,c`` reaches c through a and b: ``ssh -J a,b -W %h:%p c``.
    """
    value = value.strip()
    if not value or value.lower() == "none":
        return ""
    hops = [hop.strip() for hop in value.split(",")]
    if any(not hop or hop.startswith("-") or any(ch.isspace() for ch in hop) for hop in hops):
        log.warning("SSH config: ProxyJump %r not imported", value)
        return ""
    match = _PROXY_JUMP_DEST.fullmatch(hops[-1])
    if match is None:
        log.warning("SSH config: ProxyJump %r not imported", value)
        return ""
    host = match.group("host").strip("[]")
    user = match.group("user")
    if host.startswith("-") or (user or "").startswith("-"):
        return ""
    import shlex

    argv = ["ssh"]
    if len(hops) > 1:
        argv += ["-J", ",".join(hops[:-1])]
    if match.group("port"):
        argv += ["-p", match.group("port")]
    argv += ["-W", "%h:%p", f"{user}@{host}" if user else host]
    # Literal "%" of a hop must survive the %-token expansion.
    return " ".join(
        part if part == "%h:%p" else shlex.quote(part).replace("%", "%%") for part in argv
    )


#: How deep Include may nest, and how many files one import reads.
MAX_INCLUDE_DEPTH = 16
MAX_INCLUDED_FILES = 256


def _expand_hostname(value: str, alias: str) -> str:
    """``HostName`` with OpenSSH's ``%h`` (the alias) and ``%%``."""
    if "%" not in value:
        return value
    return re.sub(r"%[h%]", lambda m: alias if m.group(0) == "%h" else "%", value)


def parse_ssh_config(path: Path | None = None) -> list[SSHHostConfig]:
    """Parse ~/.ssh/config and return a list of host configs.

    As OpenSSH reads it: the first value of a setting wins (a second
    ``Host prod`` block adds only what the first left unset), ``Include``
    reads its files in place (relative to the config's folder - ~/.ssh
    for the user's own - globs sorted, at most MAX_INCLUDE_DEPTH deep),
    and ``HostName`` expands ``%h``. Skips wildcard patterns (* and ?) as
    they're not useful as connection targets.
    """
    import glob
    import shlex

    if path is None:
        path = Path.home() / ".ssh" / "config"

    if not path.exists():
        log.debug("No SSH config found at %s", path)
        return []

    hosts: list[SSHHostConfig] = []
    by_alias: dict[str, SSHHostConfig] = {}
    # Settings each host has already: OpenSSH takes the first value of
    # each (of ProxyCommand / ProxyJump the first of the two, "none" too).
    assigned: dict[int, set[str]] = {}
    base_dir = path.parent
    budget = {"files": 0, "bytes": 0}

    def read(file: Path) -> str | None:
        try:
            size = file.stat().st_size
            if size > MAX_SSH_CONFIG_BYTES or budget["bytes"] + size > 4 * MAX_SSH_CONFIG_BYTES:
                log.warning("SSH config %s exceeds %d bytes; refusing to parse",
                            file, MAX_SSH_CONFIG_BYTES)
                return None
            budget["bytes"] += size
            budget["files"] += 1
            return file.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            log.warning("Cannot read SSH config %s: %s", file, e)
            return None

    def setting(key: str, current_hosts, apply) -> None:
        for current in current_hosts:
            done = assigned.setdefault(id(current), set())
            if key in done:
                continue
            done.add(key)
            apply(current)

    def include(value: str, current_hosts, depth: int) -> None:
        try:
            patterns = shlex.split(value)
        except ValueError:
            patterns = value.split()
        for pattern in patterns:
            pattern = str(Path(pattern).expanduser())
            if not Path(pattern).is_absolute():
                pattern = str(base_dir / pattern)
            for name in sorted(glob.glob(pattern)):
                if budget["files"] >= MAX_INCLUDED_FILES:
                    log.warning("SSH config: more than %d included files; the rest skipped",
                                MAX_INCLUDED_FILES)
                    return
                text = read(Path(name)) if Path(name).is_file() else None
                if text is not None:
                    # The block state comes back after the file, as in
                    # OpenSSH (readconf.c restores it).
                    process(text, list(current_hosts), depth + 1)

    def process(text: str, current_hosts: list[SSHHostConfig], depth: int) -> None:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Split on first whitespace or = ("Port=2222" as well as "Port 2222")
            match = re.match(r"([^\s=]+)(?:\s*=\s*|\s+)(.*)", line)
            if not match:
                continue

            key = match.group(1).lower()
            value = match.group(2).strip()

            if key == "include":
                if depth >= MAX_INCLUDE_DEPTH:
                    log.warning("SSH config: Include %r nested too deep; skipped", value)
                    continue
                include(value, current_hosts, depth)
                continue
            if key == "host":
                # Patterns and negations ("!bastion") name no host to connect to.
                aliases = [
                    alias for alias in value.split()
                    if "*" not in alias and "?" not in alias and not alias.startswith("!")
                ]
                current_hosts = []
                for alias in aliases:
                    if alias not in by_alias:
                        by_alias[alias] = SSHHostConfig(alias=alias)
                        hosts.append(by_alias[alias])
                    current_hosts.append(by_alias[alias])
                continue
            if key == "match":
                # A Match block applies to whatever it matches at connect time,
                # not to the Host block above it.
                current_hosts = []
                continue

            if not current_hosts:
                continue
            if key == "hostname":
                def apply(current, value=value):
                    current.hostname = _expand_hostname(value, current.alias)
                setting("hostname", current_hosts, apply)
            elif key == "port":
                try:
                    port = int(value)
                except ValueError:
                    continue
                if not 0 < port < 65536:
                    continue
                setting("port", current_hosts, lambda c, port=port: setattr(c, "port", port))
            elif key == "user":
                setting("user", current_hosts, lambda c, v=value: setattr(c, "user", v))
            elif key == "identityfile":
                # Expand ~ in path
                identity_file = str(Path(value.strip('"')).expanduser())
                setting("identityfile", current_hosts,
                        lambda c, v=identity_file: setattr(c, "identity_file", v))
            elif key in ("proxycommand", "proxyjump"):
                command = value if key == "proxycommand" else proxy_jump_command(value)
                if key == "proxycommand" and value.lower() == "none":
                    command = ""
                setting("proxy", current_hosts,
                        lambda c, v=command: setattr(c, "proxy_command", v))
            elif key == "addressfamily":
                val = value.lower()
                address_family = "auto"
                if val == "inet":
                    address_family = "ipv4"
                elif val == "inet6":
                    address_family = "ipv6"
                setting("addressfamily", current_hosts,
                        lambda c, v=address_family: setattr(c, "address_family", v))

    text = read(path)
    if text is None:
        return []
    process(text, [], 0)

    log.info("Parsed %d hosts from SSH config %s", len(hosts), path)
    return hosts
