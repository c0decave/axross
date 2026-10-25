"""MCP servers already on this machine, found without typing a command.

Agent Settings > MCP Servers > *Detected on this machine* and the Tools
list of an Agent tab offer each server found here with one checkbox; a
tick adds it to the agent's settings (switched on) like a configured one
(core.mcp_client: the same McpClient, the same confirm modes).

What runs where (operator rule: servers that are downloaded always run in
a container, under restricted rules):

* a command that **downloads code** at start (npx, uvx, ``docker run`` …,
  core.mcp_runner) never runs on this machine: a tick installs it the
  contained way (core.mcp_install.install_plan - the npm or pypi package
  built in its runtime container, an image run with axross's hardened
  podman line; no network). Its own ``docker run`` flags are not taken
  over, and the details say which were dropped. What cannot be converted
  (a git URL, an unknown option, ``uv run`` …) is shown, not tickable.
* a **program already on disk** runs as it is, in the sandbox profile of
  the place where it was ticked - not in a container, as the details say.
  One that is not found is shown, not tickable.
* an http server becomes an http server; podman images axross installed
  run with its podman line.

Where servers are found:

=====================  ======================================================
podman (axross)        images axross built (label ``io.axross.mcp.package``)
                       and images of Docker's curated ``docker.io/mcp/`` and
                       of ``ghcr.io/c0decave/``, also when the settings lost
                       the server; they run with core.mcp_install's podman
                       line (no network)
Claude Desktop         ``claude_desktop_config.json`` (``mcpServers``)
Claude Code            ``~/.claude.json`` (``mcpServers`` and those of each
                       project) and ``.mcp.json`` of the given folders
VS Code                ``User/settings.json`` (``mcp.servers``, JSON with
                       comments), ``User/mcp.json`` and ``.vscode/mcp.json``
                       of the folders (``servers``)
Cursor                 ``~/.cursor/mcp.json`` and ``.cursor/mcp.json`` of the
                       folders (``mcpServers``)
=====================  ======================================================

Programs on PATH are **not** detected: nothing identifies an MCP server
there except running it or guessing from its name, and neither is safe.

Every file is **untrusted data**: read only, a regular file, bounded
(:data:`MAX_CONFIG_BYTES`), parsed as JSON or TOML (nothing is executed),
and each server is validated (a command and arguments on one line, an
http(s) URL, environment names of letters, digits and ``_``). A value of
an environment variable that looks like a secret (by its name or its
shape) is kept apart: it never reaches a log, a ``repr`` or the settings
file - it goes to the keyring when the user switches the server on.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import stat
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from pathlib import Path
from urllib.parse import urlsplit

from core import mcp_catalog as M
from core import mcp_client as C
from core.mcp_runner import downloading_runner

log = logging.getLogger(__name__)
#: The PATH programs are looked up in during a scan (detect's *env*).
_PATH: ContextVar = ContextVar("mcp_detect_path", default=None)

#: A configuration file larger than this is not read.
MAX_CONFIG_BYTES = 8 << 20
#: Servers read of one file.
MAX_SERVERS_PER_FILE = 200
MAX_ARGS = 64
MAX_ENV = 64
MAX_TEXT = 4000
#: Image names whose images are MCP servers by where they come from.
MCP_IMAGE_PREFIXES = ("docker.io/mcp/", M.HUB_IMAGE_PREFIX)
PACKAGE_LABEL = "io.axross.mcp.package"
PODMAN_CLIENT = "podman (axross)"

_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_PLACEHOLDER = re.compile(r"\$\{[^}]{0,200}\}")
_SECRET_NAME = re.compile(
    r"token|secret|passw|pwd|api_?key|apikey|access_?key|private|credential|auth|bearer"
    r"|cookie|session|(?:^|_)key$|(?:^|_)pat$", re.IGNORECASE)
_SECRET_VALUE = re.compile(
    r"^(?:gh[pousr]_|github_pat_|glpat-|sk-|sk_|xox[abpr]-|AKIA|ASIA|AIza|hf_|npm_|pypi-"
    r"|ya29\.|eyJ)[A-Za-z0-9._\-]{8,}")


def looks_secret(name: str, value: str) -> bool:
    """Whether the environment variable *name* = *value* looks like a secret:
    by its name (TOKEN, PASSWORD, API_KEY …), a known token shape, or a
    long random-looking value."""
    if not value:
        return False
    if _SECRET_NAME.search(name) or _SECRET_VALUE.match(value):
        return True
    if len(value) >= 24 and not re.search(r"[\s/:@.]", value):
        classes = sum(bool(re.search(p, value)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]"))
        return classes >= 3
    return False


_SECRET_OPTION = re.compile(r"^(--?[A-Za-z0-9_.-]*(?:token|secret|passw|key|auth)[A-Za-z0-9_.-]*=)"
                            r"(.+)$", re.IGNORECASE)


def masked(argv) -> list[str]:
    """*argv* to show: the value of an option like ``--api-key=…`` and an
    argument shaped like a token replaced by dots (the command itself is
    kept as it is - it has to run)."""
    out = []
    for arg in argv:
        option = _SECRET_OPTION.match(arg)
        if option:
            out.append(option.group(1) + "•••")
        elif _SECRET_VALUE.match(arg):
            out.append("•••")
        else:
            out.append(arg)
    return out


class _Refused(ValueError):
    pass


@dataclass(frozen=True)
class DetectedServer:
    #: Stable over scans: what the server runs, hashed.
    key: str
    #: A valid server name (core.mcp_client), made free when it is added.
    name: str
    clients: tuple[str, ...] = ()
    #: Where it was found (a file, a project, a podman image).
    origins: tuple[str, ...] = ()
    transport: str = "stdio"
    command: tuple[str, ...] = ()
    env: dict = field(default_factory=dict, repr=False)
    #: Values that look like secrets: to the keyring, never logged.
    secrets: dict = field(default_factory=dict, repr=False)
    #: Variables whose value is a placeholder of the other client.
    missing: tuple[str, ...] = ()
    url: str = ""
    token: str = field(default="", repr=False)
    #: A command that downloads code (core.mcp_runner): installed in a
    #: container by :meth:`install`, never run on this machine.
    plan: object = field(default=None, repr=False)
    #: A program already on disk (it runs on this machine, not in a container).
    local: bool = False
    #: A podman image axross runs with its own podman line.
    image_id: str = ""
    image_ref: str = ""
    package_kind: str = ""
    notes: str = ""
    why_not: str = ""
    #: The name of a configured server that runs the same ("" = none).
    configured: str = ""

    @property
    def usable(self) -> bool:
        return not self.why_not

    @property
    def needs_install(self) -> bool:
        """A tick installs it into a container (it downloads code)."""
        return self.plan is not None and not self.image_id

    def describe(self) -> str:
        """What the server is, as plain text, without a secret value."""
        lines = [self.name, ""]
        lines.append("Found in: " + ", ".join(self.clients))
        lines += [f"  {o}" for o in self.origins[:5]]
        if self.image_id:
            lines.append(f"Image: {self.image_ref or self.image_id}")
            lines.append("Runs with axross's podman line (no network, no folders).")
        elif self.transport == "stdio":
            shown = masked(self.command)
            lines.append("Command: " + " ".join(shown))
            if self.plan is not None and self.plan.convertible:
                lines.append(f"It downloads {self.plan.spec} when it starts ({self.plan.runner}): "
                             f"a tick installs it into a container (podman, no network) - it "
                             f"never runs on this machine.")
                if self.plan.dropped:
                    lines.append(f"Not taken over from its {self.plan.runner} line: "
                                 + ", ".join(masked(self.plan.dropped)))
            elif self.local:
                lines.append("Runs on this machine, not in a container (in the sandbox profile "
                             "of the place where it is ticked, if that has one).")
        else:
            lines.append(f"URL: {self.url}" + (" (with a token)" if self.token else ""))
        if self.env:
            lines.append("Environment: " + ", ".join(sorted(self.env)))
        if self.secrets:
            lines.append("Secrets (to the keyring when it is switched on): "
                         + ", ".join(sorted(self.secrets)))
        if self.notes:
            lines += ["", self.notes]
        if self.why_not:
            lines += ["", f"Cannot be used: {self.why_not}"]
        if self.configured:
            lines += ["", f"Already in the settings as {self.configured}."]
        return "\n".join(lines)

    def config(self, *, name: str, sandbox: str = "") -> C.McpServerConfig:
        """The server as a configuration (switched on). *sandbox* is the
        profile a program runs in; a container and an http server get none.
        A server that downloads code has no such config: :meth:`install`."""
        if self.needs_install:
            raise ValueError("it downloads code: it is installed into a container (install)")
        package = {"source": "detected", "entry": self.key,
                   "kind": self.package_kind or ("remote" if self.transport == "http"
                                                 else "program")}
        if self.image_id:
            from core.mcp_install import run_command

            package.update(image=self.image_id, identifier=self.image_ref[:300])
            return C.McpServerConfig(
                name=name, command=tuple(run_command(name, self.image_ref or self.image_id)),
                enabled=True, container=True, package=package)
        if self.transport == "http":
            return C.McpServerConfig(name=name, transport="http", url=self.url,
                                     bearer=bool(self.token), enabled=True, package=package)
        return C.McpServerConfig(
            name=name, command=self.command, env=dict(self.env), enabled=True, sandbox=sandbox,
            secret_env=tuple(dict.fromkeys([*self.secrets, *self.missing])), package=package)

    def install(self, *, name: str, podman=None, opener=None, on_line=None, cancel=None,
                taken=()) -> C.McpServerConfig:
        """Install a server that downloads code into a container
        (core.mcp_install.install_plan) and return its config, switched on;
        core.mcp_install.InstallError says why not."""
        from core.mcp_install import install_plan

        return install_plan(self.plan, name=name, env=self.env, secrets=self.secrets,
                            missing=self.missing, podman=podman, opener=opener,
                            on_line=on_line, cancel=cancel, taken=taken, source="detected",
                            entry_key=self.key)


@dataclass
class DetectResult:
    servers: list[DetectedServer] = field(default_factory=list)
    #: One line per file or entry that could not be read (no secret in it).
    warnings: list[str] = field(default_factory=list)


# -- reading files ---------------------------------------------------------------------------


def _read(path: Path, warnings: list[str]) -> str | None:
    """The text of *path* if it is a regular file within the bound."""
    try:
        info = os.stat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        warnings.append(f"{path}: cannot be read ({exc.strerror or exc})")
        return None
    if not stat.S_ISREG(info.st_mode):
        warnings.append(f"{path}: not a regular file - skipped")
        return None
    if info.st_size > MAX_CONFIG_BYTES:
        warnings.append(f"{path}: larger than {MAX_CONFIG_BYTES >> 20} MiB - not read")
        return None
    try:
        # Opened without blocking and checked again: a file swapped for a
        # FIFO after the stat must not hang the scan.
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
                     | getattr(os, "O_CLOEXEC", 0))
        with os.fdopen(fd, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                warnings.append(f"{path}: not a regular file - skipped")
                return None
            raw = handle.read(MAX_CONFIG_BYTES + 1)
    except OSError as exc:
        warnings.append(f"{path}: cannot be read ({exc.strerror or exc})")
        return None
    if len(raw) > MAX_CONFIG_BYTES:
        warnings.append(f"{path}: larger than {MAX_CONFIG_BYTES >> 20} MiB - not read")
        return None
    return raw.decode("utf-8", errors="replace")


def strip_jsonc(text: str) -> str:
    """JSON with comments (VS Code's settings) as JSON: ``//`` and ``/* */``
    comments outside strings removed, commas before ``}`` or ``]`` too."""
    out: list[str] = []
    i, n = 0, len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end < 0 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
        else:
            out.append(ch)
            i += 1
    return _drop_trailing_commas("".join(out))


def _drop_trailing_commas(text: str) -> str:
    """Commas before ``}`` or ``]`` removed, outside strings only."""
    out: list[str] = []
    in_string = False
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            in_string = ch != '"'
        elif ch == '"':
            in_string = True
            out.append(ch)
        elif ch == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j >= n or text[j] not in "}]":
                out.append(ch)
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def _load_json(path: Path, warnings: list[str], *, jsonc: bool = False):
    text = _read(path, warnings)
    if text is None:
        return None
    try:
        return json.loads(strip_jsonc(text) if jsonc else text)
    except RecursionError:
        warnings.append(f"{path}: nested too deep - not read")
    except ValueError:
        warnings.append(f"{path}: not valid JSON - not read")
    return None


# -- one server ------------------------------------------------------------------------------


def _line(value, what: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_TEXT \
            or any(c in value for c in "\n\r\x00"):
        raise _Refused(f"{what}: a text on one line")
    return value


def _on_disk(program: str, path: str | None) -> bool:
    """Whether *program* is a file on disk (absolute) or on *path* (PATH)."""
    import shutil

    if os.path.isabs(program):
        return os.path.isfile(program) and os.access(program, os.X_OK)
    if os.sep in program or (os.altsep and os.altsep in program):
        return False  # relative to a folder nobody knows here
    return shutil.which(program, path=path) is not None


def _server(raw, *, name: str, client: str, origin: str,
            path: str | None = None) -> DetectedServer:
    """One server of a client's configuration; _Refused says why not (never
    with a value in it)."""
    if not isinstance(raw, dict):
        raise _Refused("a server is an object")
    kind = raw.get("type", raw.get("transport"))
    kind = kind.lower() if isinstance(kind, str) else ""
    notes: list[str] = []
    env: dict[str, str] = {}
    secrets: dict[str, str] = {}
    missing: list[str] = []
    raw_env = raw.get("env")
    if raw_env is not None:
        if not isinstance(raw_env, dict) or len(raw_env) > MAX_ENV:
            raise _Refused(f"env: an object of at most {MAX_ENV} variables")
        for var, value in raw_env.items():
            if not isinstance(var, str) or not _ENV_NAME.match(var):
                raise _Refused("env: names of letters, digits and _")
            if not isinstance(value, str) or len(value) > MAX_TEXT \
                    or any(c in value for c in "\n\r\x00"):
                raise _Refused(f"env: {var} needs a text on one line")
            if _PLACEHOLDER.search(value):
                missing.append(var)
            elif looks_secret(var, value):
                secrets[var] = value
            else:
                env[var] = value
    if missing:
        notes.append(f"{', '.join(missing)} need a value ({client} fills them in itself): "
                     f"set it with Set Secret… after switching the server on.")
    values = dict(name=M.server_name(name), clients=(client,), origins=(origin,), env=env,
                  secrets=secrets, missing=tuple(missing))
    command = raw.get("command")
    url = raw.get("url", raw.get("serverUrl"))
    if command is not None:
        program = _line(command, "command")
        args = raw.get("args", [])
        if not isinstance(args, list) or len(args) > MAX_ARGS:
            raise _Refused(f"args: a list of at most {MAX_ARGS} texts")
        argv = [program]
        for arg in args:
            if not isinstance(arg, str) or len(arg) > MAX_TEXT \
                    or any(c in arg for c in "\n\r\x00"):
                raise _Refused("args: each one a text on one line")
            argv.append(arg)
        placeholders = sorted({p for a in argv for p in _PLACEHOLDER.findall(a)})
        if placeholders:
            notes.append(f"The command holds {', '.join(placeholders)} of {client}: it is "
                         f"passed as it is - edit the program line if it needs a value.")
        values.update(transport="stdio", command=tuple(argv))
        plan = downloading_runner(argv)
        if plan is not None:
            values["plan"] = plan
            if not plan.convertible:
                values["why_not"] = (f"{plan.why_not} - and a command that downloads code never "
                                     f"runs on this machine")
            else:
                for var, value in plan.env.items():
                    if looks_secret(var, value):
                        secrets.setdefault(var, value)
                    else:
                        env.setdefault(var, value)
                missing.extend(v for v in plan.env_names if v not in missing)
                values["missing"] = tuple(missing)
        elif not _on_disk(program, path):
            values["why_not"] = f"the program {M.clean_text(program, 80)} is not on this machine"
        else:
            values["local"] = True
        if raw.get("envFile"):
            notes.append("Its envFile is not read: set what it holds after switching it on.")
    elif url is not None:
        url = _line(url, "url")
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise _Refused("url: an http:// or https:// URL")
        values.update(transport="http", url=url)
        if kind == "sse":
            values["why_not"] = ("an SSE server (the old transport) is not supported - "
                                 "stdio and Streamable HTTP are")
        headers = raw.get("headers") if isinstance(raw.get("headers"), dict) else {}
        for header, value in headers.items():
            if not isinstance(header, str) or not isinstance(value, str):
                continue
            if header.lower() == "authorization" and value.lower().startswith("bearer "):
                token = value[7:].strip()
                if _PLACEHOLDER.search(token):
                    notes.append("Its token is filled in by the other client: enter it under "
                                 "Token after switching it on.")
                elif token:
                    values["token"] = token
            elif not values.get("why_not"):
                values["why_not"] = (f"it needs the header {M.clean_text(header, 60)} "
                                     f"(axross sends a Bearer token only)")
        if raw.get("bearer_token_env_var"):
            notes.append(f"Its token is read from an environment variable by {client}: enter "
                         f"it under Token after switching it on.")
    else:
        raise _Refused("a server needs a command or a url")
    values["notes"] = " ".join(notes)
    values["key"] = _key(values)
    return DetectedServer(**values)


def _key(values: dict) -> str:
    """What the server runs, hashed - its secrets by name only: the key is
    kept in the settings file, and a hash of a weak password could be
    guessed back."""
    what = json.dumps([values.get("transport"), list(values.get("command") or ()),
                       values.get("url", ""), sorted(values.get("env", {}).items()),
                       sorted(values.get("secrets", {})), bool(values.get("token")),
                       values.get("image_id", "")])
    return "detected:" + hashlib.sha256(what.encode()).hexdigest()[:20]


def _servers_of(mapping, *, client: str, origin: str, out: list, warnings: list) -> None:
    path = _PATH.get()
    if mapping is None:
        return
    if not isinstance(mapping, dict):
        warnings.append(f"{origin}: the servers are not an object - skipped")
        return
    for index, (name, raw) in enumerate(mapping.items()):
        if index >= MAX_SERVERS_PER_FILE:
            warnings.append(f"{origin}: at most {MAX_SERVERS_PER_FILE} servers are read")
            break
        label = M.clean_text(name, 40) or "?"
        try:
            out.append(_server(raw, name=str(name), client=client, origin=origin, path=path))
        except _Refused as exc:
            warnings.append(f"{origin}: {label} skipped - {exc}")


# -- the clients -----------------------------------------------------------------------------


def _config_home(home: Path, env) -> Path:
    base = env.get("XDG_CONFIG_HOME", "")
    return Path(base) if base and os.path.isabs(base) else home / ".config"


def _claude_desktop(home, env, folders, out, warnings) -> None:
    for path in (_config_home(home, env) / "Claude" / "claude_desktop_config.json",
                 home / "Library" / "Application Support" / "Claude"
                 / "claude_desktop_config.json",
                 Path(env.get("APPDATA") or home / "AppData" / "Roaming") / "Claude"
                 / "claude_desktop_config.json"):
        data = _load_json(path, warnings)
        if isinstance(data, dict):
            _servers_of(data.get("mcpServers"), client="Claude Desktop", origin=str(path),
                        out=out, warnings=warnings)
        elif data is not None:
            warnings.append(f"{path}: not an object - skipped")


def _claude_code(home, env, folders, out, warnings) -> None:
    path = home / ".claude.json"
    data = _load_json(path, warnings)
    if isinstance(data, dict):
        _servers_of(data.get("mcpServers"), client="Claude Code", origin=str(path), out=out,
                    warnings=warnings)
        projects = data.get("projects")
        if isinstance(projects, dict):
            for project, settings in list(projects.items())[:1000]:
                if isinstance(settings, dict) and settings.get("mcpServers"):
                    _servers_of(settings["mcpServers"], client="Claude Code",
                                origin=f"{path} (project {M.clean_text(project, 200)})",
                                out=out, warnings=warnings)
    elif data is not None:
        warnings.append(f"{path}: not an object - skipped")
    for folder in folders:
        _project_file(Path(folder) / ".mcp.json", "mcpServers", "Claude Code", out, warnings)


def _project_file(path: Path, key: str, client: str, out, warnings, *, jsonc=False) -> None:
    data = _load_json(path, warnings, jsonc=jsonc)
    if isinstance(data, dict):
        _servers_of(data.get(key), client=client, origin=str(path), out=out, warnings=warnings)
    elif data is not None:
        warnings.append(f"{path}: not an object - skipped")


def _vscode(home, env, folders, out, warnings) -> None:
    for user in (_config_home(home, env) / "Code" / "User",
                 home / "Library" / "Application Support" / "Code" / "User",
                 Path(env.get("APPDATA") or home / "AppData" / "Roaming") / "Code" / "User"):
        settings = _load_json(user / "settings.json", warnings, jsonc=True)
        if isinstance(settings, dict) and isinstance(settings.get("mcp"), dict):
            _servers_of(settings["mcp"].get("servers"), client="VS Code",
                        origin=str(user / "settings.json"), out=out, warnings=warnings)
        _project_file(user / "mcp.json", "servers", "VS Code", out, warnings, jsonc=True)
    for folder in folders:
        _project_file(Path(folder) / ".vscode" / "mcp.json", "servers", "VS Code", out,
                      warnings, jsonc=True)


def _cursor(home, env, folders, out, warnings) -> None:
    _project_file(home / ".cursor" / "mcp.json", "mcpServers", "Cursor", out, warnings)
    for folder in folders:
        _project_file(Path(folder) / ".cursor" / "mcp.json", "mcpServers", "Cursor", out,
                      warnings)


CLIENTS = (_claude_desktop, _claude_code, _vscode, _cursor)


def _podman_servers(podman, out: list, warnings: list) -> None:
    """Images axross installed (its label) or of the MCP namespaces."""
    from core.mcp_install import InstallError

    try:
        images = podman.images()
    except InstallError as exc:
        warnings.append(f"podman: {exc}")
        return
    builtin = {e.identifier: e for e in M.load_builtin()[0]}
    for image in images[:2000]:
        if not isinstance(image, dict) or not isinstance(image.get("Id"), str):
            continue
        ident = image["Id"]
        if not re.match(r"^[a-f0-9]{64}$", ident):
            continue
        labels = image.get("Labels") if isinstance(image.get("Labels"), dict) else {}
        names = [n for n in image.get("Names") or () if isinstance(n, str)]
        digests = [d for d in image.get("RepoDigests") or () if isinstance(d, str)]
        package = labels.get(PACKAGE_LABEL)
        mcp_name = next((n for n in names + digests
                         if n.startswith(MCP_IMAGE_PREFIXES)), "")
        if not (isinstance(package, str) and package) and not mcp_name:
            continue
        values: dict = dict(transport="stdio", clients=(PODMAN_CLIENT,), image_id=ident)
        if isinstance(package, str) and package:
            kind, _, spec = package.partition(":")
            spec = M.clean_text(spec, 200)
            match = re.match(r"^(.*?)(?:==|@(?=[0-9]))(.*)$", spec)
            base, version = (match.group(1), match.group(2)) if match else (spec, "")
            # core.mcp_install tags a build localhost/axross-mcp:<server name>-<version>.
            tag = next((n.split(":", 1)[1] for n in names
                        if n.startswith("localhost/axross-mcp:")), "")
            suffix = f"-{version}" if version else ""
            label = tag[: -len(suffix)] if suffix and tag.endswith(suffix) else base
            values.update(name=M.server_name(label or base), package_kind=M.clean_text(kind, 20),
                          image_ref=ident, origins=(f"podman image {ident[:12]} ({spec})",))
        else:
            repo = mcp_name.split("@", 1)[0]
            repo = repo.rsplit(":", 1)[0] if ":" in repo.rsplit("/", 1)[-1] else repo
            pinned = next((d for d in digests if d.startswith(repo + "@sha256:")), "")
            values.update(name=M.server_name(repo), package_kind="oci",
                          image_ref=pinned or ident, origins=(f"podman image {mcp_name}",))
            entry = builtin.get(repo)
            if entry is not None and (any(m.required for m in entry.mounts)
                                      or any(e.required for e in entry.env)):
                values["why_not"] = ("it needs a folder or a value: install it with Add from "
                                     "Catalog… to choose them")
            elif entry is not None and entry.args:
                values["notes"] = "Its catalog arguments are not added: no folders are given."
        values["key"] = _key(values)
        out.append(DetectedServer(**values))


# -- all of it -------------------------------------------------------------------------------


def configured_as(detected: DetectedServer, servers) -> C.McpServerConfig | None:
    """The server of *servers* (configurations) that runs *detected*: the
    one added from it, the one of its podman image, or one with the same
    command or URL."""
    for server in servers:
        package = server.package if isinstance(server.package, dict) else {}
        if package.get("entry") == detected.key:
            return server
        if detected.image_id:
            if package.get("image") == detected.image_id:
                return server
        elif _signature(server.transport, server.command, server.url) == _signature(
                detected.transport, detected.command, detected.url):
            return server
    return None


def _signature(transport: str, command, url: str) -> tuple:
    return (transport, tuple(command or ()), url or "")


def detect(*, home: Path | None = None, folders=(), podman=None, configured=(),
           env=None) -> DetectResult:
    """Every MCP server found (see the module), each once - the clients
    that name it merged - and marked when *configured* has it already.
    *podman* (core.mcp_install.Podman) None skips the images."""
    home = Path(home) if home is not None else Path.home()
    env = os.environ if env is None else env
    found: list[DetectedServer] = []
    warnings: list[str] = []
    token = _PATH.set(env.get("PATH") or None)
    try:
        _scan_clients(home, env, folders, found, warnings)
    finally:
        _PATH.reset(token)
    if podman is not None and getattr(podman, "available", False):
        _podman_servers(podman, found, warnings)
    return _merge(found, warnings, configured)


def _scan_clients(home, env, folders, found, warnings) -> None:
    for client in CLIENTS:
        try:
            client(home, env, list(folders), found, warnings)
        except Exception as exc:  # noqa: BLE001 - one client's odd file must not cost the rest
            log.warning("mcp detect: %s failed: %s", client.__name__, type(exc).__name__)
            warnings.append(f"{client.__name__.strip('_')}: could not be read")


def _merge(found, warnings, configured) -> DetectResult:
    merged: dict[str, DetectedServer] = {}
    for server in found:
        first = merged.get(server.key)
        if first is None:
            merged[server.key] = server
            continue
        merged[server.key] = replace(
            first, clients=tuple(dict.fromkeys(first.clients + server.clients)),
            origins=tuple(dict.fromkeys(first.origins + server.origins)))
    configured = list(configured)
    out = []
    for server in merged.values():
        mine = configured_as(server, configured)
        if mine is not None:
            server = replace(server, configured=mine.name)
        out.append(server)
    return DetectResult(out, warnings)
