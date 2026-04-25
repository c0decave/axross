"""Parse ~/.ssh/config and extract host definitions."""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)


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


def parse_ssh_config(path: Path | None = None) -> list[SSHHostConfig]:
    """Parse ~/.ssh/config and return a list of host configs.

    Skips wildcard patterns (* and ?) as they're not useful as connection targets.
    """
    if path is None:
        path = Path.home() / ".ssh" / "config"

    if not path.exists():
        log.debug("No SSH config found at %s", path)
        return []

    hosts: list[SSHHostConfig] = []
    current_hosts: list[SSHHostConfig] = []

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        log.warning("Cannot read SSH config %s: %s", path, e)
        return []

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Split on first whitespace or =
        match = re.match(r"(\S+)\s*=?\s*(.*)", line)
        if not match:
            continue

        key = match.group(1).lower()
        value = match.group(2).strip()

        if key == "host":
            aliases = [
                alias
                for alias in value.split()
                if "*" not in alias and "?" not in alias
            ]
            current_hosts = [SSHHostConfig(alias=alias) for alias in aliases]
            hosts.extend(current_hosts)
            continue

        if current_hosts:
            if key == "hostname":
                for current in current_hosts:
                    current.hostname = value
            elif key == "port":
                try:
                    port = int(value)
                except ValueError:
                    continue
                for current in current_hosts:
                    current.port = port
            elif key == "user":
                for current in current_hosts:
                    current.user = value
            elif key == "identityfile":
                # Expand ~ in path
                identity_file = str(Path(value.strip('"')).expanduser())
                for current in current_hosts:
                    current.identity_file = identity_file
            elif key == "proxycommand":
                for current in current_hosts:
                    current.proxy_command = value
            elif key == "addressfamily":
                val = value.lower()
                address_family = "auto"
                if val == "inet":
                    address_family = "ipv4"
                elif val == "inet6":
                    address_family = "ipv6"
                for current in current_hosts:
                    current.address_family = address_family

    log.info("Parsed %d hosts from SSH config %s", len(hosts), path)
    return hosts
