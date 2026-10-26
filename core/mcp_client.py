"""A client for further MCP servers, whose tools the agent may use.

axross's agent offers its own tools (core.mcp_server) and, configured in
Agent Settings > MCP Servers, the tools of other MCP servers: a program
spoken to over stdin/stdout (``stdio``) or a server reached over
Streamable HTTP (``http``). Their tools are named ``<server>__<tool>``.

The servers run with axross, never inside the agent's sandbox: their
credentials (an HTTP token in the keyring) stay here, and a sandboxed
agent reaches their tools as host tools (core.agent_sandbox), under the
sandbox's level and allowed hosts. A stdio server may itself run in a
sandbox profile (``sandbox``).

Bounded: at most :data:`MAX_TOOLS` tools per server, descriptions cut at
:data:`MAX_DESCRIPTION`, input schemas larger than :data:`MAX_SCHEMA_BYTES`
replaced by a plain object schema, answers larger than
:data:`MAX_MESSAGE_BYTES` refused, every request under the server's
timeout. A server's schema is never validated here (that is the server's
job, and validating a foreign schema could fetch remote references).

A **container** server (``container``: installed from a catalog by
core.mcp_install) is a ``podman run`` line axross made. Its environment and
the secrets of ``secret_env`` (keyring: ``axross-mcp-server/<name>``, user
``env:<NAME>``) reach the container through an environment file on a pipe
(``--env-file=/dev/fd/N``): never on the command line, never on disk, never
in podman's own environment. :data:`TOKEN_ENV_FD`, :data:`TOKEN_EGRESS`
(the port of its allowlist proxy, core.mcp_egress, for ``egress``) and
:data:`TOKEN_RUN` (unique per start, in the container's name) are filled in
at each start; a container whose podman had to be killed is removed by name.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import subprocess
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlsplit

from core import process_launcher

log = logging.getLogger(__name__)

PROTOCOL_VERSION = "2024-11-05"
SEPARATOR = "__"
MAX_TOOLS = 128
MAX_DESCRIPTION = 2000
MAX_SCHEMA_BYTES = 64 * 1024
MAX_MESSAGE_BYTES = 16 * 1024 * 1024
MAX_NAME = 64
TRANSPORTS = ("stdio", "http")
CONFIRMS = ("always", "writes")
_NAME = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
#: Filled in at each start of a container server (core.mcp_install).
TOKEN_ENV_FD = "AXROSS_ENV_FD"
TOKEN_EGRESS = "AXROSS_EGRESS_PORT"
TOKEN_RUN = "AXROSS_RUN_ID"
#: Bytes of environment a container server may be given: the file is written
#: into the pipe before podman starts, so it must fit a pipe's buffer (16 KiB
#: is the smallest of Linux and macOS).
MAX_ENV_FILE = 16000
#: Keys of a container server's install record, and how long each may be.
PACKAGE_KEYS = {"source": 300, "entry": 300, "kind": 20, "identifier": 300, "tag": 128,
                "version": 64, "digest": 71, "image": 64, "base": 300, "network": 20,
                "installed": 40, "preexisting": 5}
_TOOL_CHARS = re.compile(r"[^A-Za-z0-9_-]")


#: Longest catalog category kept (core.mcp_catalog keeps as many).
MAX_CATEGORY = 60


def clean_category(value) -> str:
    """*value* as a server's category: one line of text without control or
    bidi characters, at most MAX_CATEGORY long; anything else is ""."""
    from core.mcp_catalog import exact_text

    return exact_text(value, MAX_CATEGORY)


class McpClientError(RuntimeError):
    """The server could not be started, reached or understood."""


@dataclass
class McpServerConfig:
    name: str
    transport: str = "stdio"
    #: stdio: the program and its arguments.
    command: tuple[str, ...] = ()
    #: stdio: extra environment variables (no secrets: the file is plain JSON).
    env: dict = field(default_factory=dict)
    #: http: the endpoint, e.g. ``http://127.0.0.1:7331/messages``.
    url: str = ""
    #: http: send the keyring's token as ``Authorization: Bearer``.
    bearer: bool = False
    enabled: bool = True
    #: "always": every call asks (even in auto mode); "writes": a tool the
    #: server marks read-only (``readOnlyHint``) runs without asking.
    confirm: str = "always"
    timeout: float = 120.0
    #: stdio: run the program in this sandbox profile ("" = not).
    sandbox: str = ""
    #: A ``podman run`` line axross made (core.mcp_install): see the module.
    container: bool = False
    #: Environment variables whose values are in the keyring.
    secret_env: tuple[str, ...] = ()
    #: The allowed ``host:port`` of a container on the allowlist network.
    egress: tuple[str, ...] = ()
    #: A container's install record (core.mcp_install), PACKAGE_KEYS.
    package: dict = field(default_factory=dict)
    #: The catalog category it was installed from, or one set by hand
    #: (Agent profiles choose servers by it: core.agent_profiles).
    category: str = ""

    def problems(self) -> list[str]:
        out = []
        if not _NAME.match(self.name or ""):
            out.append("a name of 1-32 letters, digits, '-' or '_'")
        if self.transport not in TRANSPORTS:
            out.append("transport stdio or http")
        elif self.transport == "stdio" and not self.command:
            out.append("a program to start")
        elif self.transport == "http":
            parts = urlsplit(self.url or "")
            if parts.scheme not in ("http", "https") or not parts.hostname:
                out.append("an http:// or https:// URL")
        if self.confirm not in CONFIRMS:
            out.append("confirm always or writes")
        if not (0 < self.timeout <= 3600):
            out.append("a timeout of 1-3600 seconds")
        if self.container and self.transport != "stdio":
            out.append("a container server runs as a program (stdio)")
        if self.container and self.sandbox:
            out.append("no sandbox profile for a container (it is its own sandbox)")
        out.extend(self.containment_problems())
        return out

    def containment_problems(self) -> list[str]:
        """Operator rule: what is downloaded runs in a container, never on
        the host - a command that downloads code at start (core.mcp_runner)
        is refused, and so is a container line with widening flags; also
        when a settings file was edited by hand."""
        if self.transport != "stdio" or not self.command:
            return []
        from core.mcp_runner import container_flag_problems, downloading_runner

        if self.container:
            return container_flag_problems(self.command)
        plan = downloading_runner(self.command)
        if plan is None:
            return []
        return [f"{plan.runner} downloads code when it starts: it runs only in a container "
                f"(Install in a Container)"]

    def files_risk(self) -> str:
        """Why the server may change the user's files ("" = it cannot): only
        a container server on axross's own podman line with no network and
        read-only folders cannot (core.mcp_install.contained_files_problem).
        Files read-only keeps such a server's tools; its confirm mode still
        asks at every call."""
        if self.transport != "stdio":
            return "it is an HTTP server"
        if not self.container:
            return "it runs outside a container"
        from core.mcp_install import contained_files_problem

        return contained_files_problem(self.command)

    def files_safe(self) -> bool:
        return not self.files_risk()

    def host_port(self) -> tuple[str, int] | None:
        """Where an http server is reached; None for stdio."""
        if self.transport != "http":
            return None
        parts = urlsplit(self.url)
        try:
            port = parts.port
        except ValueError:
            return None
        return (parts.hostname or "", port or (443 if parts.scheme == "https" else 80))

    def signature(self) -> tuple:
        return (self.transport, tuple(self.command), tuple(sorted(self.env.items())), self.url,
                self.bearer, self.timeout, self.sandbox, self.confirm, self.container,
                tuple(self.secret_env), tuple(self.egress))

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "transport": self.transport,
            "command": list(self.command),
            "env": dict(self.env),
            "url": self.url,
            "bearer": self.bearer,
            "enabled": self.enabled,
            "confirm": self.confirm,
            "timeout": self.timeout,
            "sandbox": self.sandbox,
            "container": self.container,
            "secret_env": list(self.secret_env),
            "egress": list(self.egress),
            "package": dict(self.package),
            "category": self.category,
        }

    @classmethod
    def from_dict(cls, data) -> McpServerConfig | None:
        if not isinstance(data, dict) or not isinstance(data.get("name"), str):
            return None
        out = cls(name=data["name"])
        if data.get("transport") in TRANSPORTS:
            out.transport = data["transport"]
        command = data.get("command")
        if isinstance(command, list) and all(isinstance(c, str) for c in command):
            out.command = tuple(command)
        env = data.get("env")
        if isinstance(env, dict):
            out.env = {k: v for k, v in env.items() if isinstance(k, str) and isinstance(v, str)}
        for key in ("url", "sandbox"):
            if isinstance(data.get(key), str):
                setattr(out, key, data[key])
        for key in ("bearer", "enabled"):
            if isinstance(data.get(key), bool):
                setattr(out, key, data[key])
        if data.get("confirm") in CONFIRMS:
            out.confirm = data["confirm"]
        timeout = data.get("timeout")
        if (
            isinstance(timeout, (int, float))
            and not isinstance(timeout, bool)
            and 0 < timeout <= 3600
        ):
            out.timeout = float(timeout)
        if data.get("container") is True:
            out.container = True
            out.sandbox = ""  # a container is its own sandbox
        secret_env = data.get("secret_env")
        if isinstance(secret_env, list):
            out.secret_env = tuple(dict.fromkeys(
                v for v in secret_env if isinstance(v, str) and _ENV_NAME.match(v)))
        egress = data.get("egress")
        if isinstance(egress, list):
            out.egress = _egress_entries(egress)
        package = data.get("package")
        if isinstance(package, dict):
            out.package = {k: v[:PACKAGE_KEYS[k]] for k, v in package.items()
                           if k in PACKAGE_KEYS and isinstance(v, str)}
        out.category = clean_category(data.get("category"))
        problems = out.problems()
        if problems:
            log.warning("mcp client: the server %r of the settings is left out: %s",
                        out.name[:40], "; ".join(problems))
            return None
        return out


def _egress_entries(entries) -> tuple[str, ...]:
    """The valid ``host:port`` entries of *entries*, normalized."""
    from core.agent_net import parse_host

    out: list[str] = []
    for item in entries:
        try:
            host, port = parse_host(item if isinstance(item, str) else "")
        except ValueError:
            continue
        entry = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        if entry not in out:
            out.append(entry)
    return tuple(out)


def keyring_service(name: str) -> str:
    return f"axross-mcp-server/{name}"


def get_token(name: str) -> str:
    try:
        import keyring

        return keyring.get_password(keyring_service(name), "token") or ""
    except Exception as exc:  # noqa: BLE001 - no keyring: no token
        log.debug("mcp client: no token for %s: %s", name, exc)
        return ""


def set_token(name: str, token: str) -> None:
    import keyring

    if token:
        keyring.set_password(keyring_service(name), "token", token)
    else:
        try:
            keyring.delete_password(keyring_service(name), "token")
        except Exception:  # noqa: BLE001 - nothing stored
            pass


def _secret_user(var: str) -> str:
    return f"env:{var}"


def get_secret(name: str, var: str) -> str:
    """The keyring's value of the environment variable *var* of server *name*."""
    try:
        import keyring

        return keyring.get_password(keyring_service(name), _secret_user(var)) or ""
    except Exception as exc:  # noqa: BLE001 - no keyring: no secret
        log.debug("mcp client: no secret %s for %s: %s", var, name, exc)
        return ""


def set_secret(name: str, var: str, value: str) -> None:
    """Store (or with "" delete) a secret environment value in the keyring."""
    import keyring

    if value:
        keyring.set_password(keyring_service(name), _secret_user(var), value)
    else:
        try:
            keyring.delete_password(keyring_service(name), _secret_user(var))
        except Exception:  # noqa: BLE001 - nothing stored
            pass


def secrets_of(config: McpServerConfig) -> dict:
    """The stored values of *config*'s secret variables (missing ones left out)."""
    out = {}
    for var in config.secret_env:
        value = get_secret(config.name, var)
        if value:
            out[var] = value
    return out


# -- transports ------------------------------------------------------------------


#: What a program server gets of axross's environment (plus its own env).
_BASE_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT", "XDG_RUNTIME_DIR", "USER")
#: What podman of a container server gets besides: where the user's podman
#: keeps its configuration and images, and how it reaches the user's
#: session (cgroups). The container itself gets none of it.
_PODMAN_ENV = ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "DBUS_SESSION_BUS_ADDRESS",
               "CONTAINERS_CONF", "CONTAINERS_STORAGE_CONF", "CONTAINERS_REGISTRIES_CONF",
               "CONTAINER_HOST", "CONTAINER_CONNECTION", "LOGNAME")


def _named_env(names) -> dict:
    return {k: v for k, v in os.environ.items() if k in names}


class _Stdio:
    def __init__(self, argv: list[str], env: dict, timeout: float, *, pass_fds=(),
                 cleanup: Callable[[], None] | None = None, base=_BASE_ENV) -> None:
        self._timeout = timeout
        self._cleanup = cleanup
        try:
            # From the launcher thread: a sandboxed server's --die-with-parent
            # watches the thread that forks it (core.process_launcher).
            self._proc = process_launcher.popen(
                argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={**_named_env(base), **env}, start_new_session=True, pass_fds=tuple(pass_fds),
            )
        except OSError as exc:
            raise McpClientError(f"cannot start {argv[0]}: {exc}") from None
        self._lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._waiting: dict[int, dict] = {}
        self._closed = False
        self.stderr: list[str] = []
        threading.Thread(target=self._read, daemon=True, name="mcp-client-stdio").start()
        threading.Thread(target=self._drain, daemon=True, name="mcp-client-stderr").start()

    def _drain(self) -> None:
        for raw in iter(self._proc.stderr.readline, b""):
            self.stderr = (self.stderr + [raw.decode("utf-8", "replace").rstrip()])[-20:]

    def _write(self, message: dict) -> None:
        data = (json.dumps(message, ensure_ascii=False) + "\n").encode("utf-8")
        with self._write_lock:
            try:
                self._proc.stdin.write(data)
                self._proc.stdin.flush()
            except (BrokenPipeError, OSError, ValueError):
                raise McpClientError("the server closed its input") from None

    def _read(self) -> None:
        while True:
            line = self._proc.stdout.readline(MAX_MESSAGE_BYTES + 1)
            if not line:
                break
            if len(line) > MAX_MESSAGE_BYTES:
                log.warning(
                    "mcp client: an answer over %d bytes - the server is dropped", MAX_MESSAGE_BYTES
                )
                break
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if not isinstance(message, dict):
                continue
            if "method" in message:
                self._answer_server(message)
                continue
            with self._lock:
                slot = self._waiting.get(message.get("id"))
            if slot is not None:
                slot["reply"] = message
                slot["event"].set()
        with self._lock:
            self._closed = True
            waiting = list(self._waiting.values())
        for slot in waiting:
            slot["event"].set()

    def _answer_server(self, message: dict) -> None:
        """A request of the server: ping is answered, anything else refused."""
        if "id" not in message:
            return  # a notification
        if message.get("method") == "ping":
            reply = {"jsonrpc": "2.0", "id": message["id"], "result": {}}
        else:
            reply = {"jsonrpc": "2.0", "id": message["id"],
                     "error": {"code": -32601, "message": "axross offers no client features"}}
        try:
            self._write(reply)
        except McpClientError:
            pass

    def request(self, ident: int, message: dict) -> dict:
        slot = {"event": threading.Event(), "reply": None}
        with self._lock:
            if self._closed:
                raise McpClientError(self._ended())
            self._waiting[ident] = slot
        try:
            self._write(message)
            if not slot["event"].wait(self._timeout):
                raise McpClientError(f"no answer within {self._timeout:g} s")
        finally:
            with self._lock:
                self._waiting.pop(ident, None)
        if slot["reply"] is None:
            raise McpClientError(self._ended())
        return slot["reply"]

    def notify(self, message: dict) -> None:
        self._write(message)

    def _ended(self) -> str:
        tail = " | ".join(line for line in self.stderr if line)[-400:]
        return "the server ended" + (f": {tail}" if tail else "")

    def close(self) -> None:
        """End of input first; then SIGTERM (podman passes it on to the
        container, whose --init hands it to the server); then SIGKILL - and
        the cleanup (a container left behind by a killed podman)."""
        proc = self._proc
        try:
            proc.stdin.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=3)
            return
        except subprocess.TimeoutExpired:
            pass
        proc.terminate()
        try:
            proc.wait(timeout=3)
            return
        except subprocess.TimeoutExpired:
            pass
        proc.kill()
        proc.wait(timeout=3)
        if self._cleanup is not None:
            try:
                self._cleanup()
            except Exception:  # noqa: BLE001 - cleanup is best effort
                log.warning("mcp client: cleanup after a killed server failed", exc_info=True)


class _Http:
    def __init__(self, url: str, token: str, timeout: float) -> None:
        self._url = url
        self._token = token
        self._timeout = timeout
        self._session: str | None = None
        self._version: str | None = None

    def _post(self, message: dict) -> tuple[dict | None, dict]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        if self._session:
            headers["Mcp-Session-Id"] = self._session
        if self._version:
            headers["MCP-Protocol-Version"] = self._version
        request = urllib.request.Request(self._url, data=json.dumps(message).encode("utf-8"),
                                         headers=headers, method="POST")
        from core.agent_net import opener_without_redirects

        host = urlsplit(self._url).hostname
        deadline = time.monotonic() + self._timeout
        try:
            with opener_without_redirects().open(request, timeout=self._timeout) as response:
                session = response.headers.get("Mcp-Session-Id")
                if session:
                    self._session = session
                kind = (response.headers.get("Content-Type") or "").split(";")[0].strip().lower()
                if response.status == 202 or "id" not in message:
                    return None, dict(response.headers)
                body = b""
                while len(body) <= MAX_MESSAGE_BYTES:
                    # The whole answer within the timeout, not each read: a
                    # server that drips would hold the agent forever.
                    if time.monotonic() > deadline:
                        raise McpClientError(f"no answer within {self._timeout:g} s")
                    chunk = response.read1(65536)
                    if not chunk:
                        break
                    body += chunk
                    if kind == "text/event-stream" and _from_events(body.decode("utf-8", "replace"),
                                                                    message.get("id")) is not None:
                        break  # a stream may stay open after the answer
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                raise McpClientError(
                    f"{host} answered a redirect (HTTP {exc.code}), which is not followed"
                ) from None
            raise McpClientError(f"{host} answered HTTP {exc.code}") from None
        except (urllib.error.URLError, OSError) as exc:
            raise McpClientError(f"cannot reach {host}: {getattr(exc, 'reason', exc)}") from None
        if len(body) > MAX_MESSAGE_BYTES:
            raise McpClientError(f"an answer over {MAX_MESSAGE_BYTES} bytes")
        if kind == "text/event-stream":
            return _from_events(body.decode("utf-8", "replace"), message.get("id")), {}
        try:
            reply = json.loads(body)
        except ValueError:
            raise McpClientError(f"{host} did not answer JSON") from None
        return (reply if isinstance(reply, dict) else None), {}

    def request(self, ident: int, message: dict) -> dict:
        reply, _ = self._post(message)
        if reply is None:
            raise McpClientError("the server sent no answer")
        return reply

    def notify(self, message: dict) -> None:
        self._post(message)

    def set_version(self, version: str) -> None:
        self._version = version

    def close(self) -> None:
        if not self._session:
            return
        headers = {"Mcp-Session-Id": self._session}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        from core.agent_net import opener_without_redirects

        try:
            opener_without_redirects().open(
                urllib.request.Request(self._url, headers=headers, method="DELETE"), timeout=5
            ).close()
        except Exception:  # noqa: BLE001 - ending a session is best effort
            pass


def _from_events(text: str, ident) -> dict | None:
    """The JSON-RPC answer with *ident* in a server-sent event stream."""
    data: list[str] = []
    for line in text.splitlines() + [""]:
        if line.startswith("data:"):
            data.append(line[5:].lstrip(" "))
        elif not line and data:
            try:
                message = json.loads("\n".join(data))
            except ValueError:
                message = None
            data = []
            if isinstance(message, dict) and message.get("id") == ident and "method" not in message:
                return message
    return None


# -- the client ------------------------------------------------------------------------


@dataclass
class ExternalTool:
    """A tool of another MCP server, as the agent offers it. Not run by
    core.mcp_server's dispatcher: :meth:`call` asks the server."""

    name: str
    description: str
    schema: dict
    write: bool
    client: "McpClient"
    remote_name: str
    always_ask: bool
    group: str = "mcp"
    accepts_backend: bool = False
    external: bool = True
    #: Its server cannot change the user's files (McpServerConfig.files_safe):
    #: Files read-only keeps the tool; *write* still makes each call ask.
    files_safe: bool = False

    def call(self, args: dict) -> tuple[str, str]:
        """``(outcome, text)``: "ok" or "error"."""
        try:
            result = self.client.call_tool(self.remote_name, args)
        except McpClientError as exc:
            return "error", f"error: {self.client.config.name}: {exc}"
        parts = []
        for item in result.get("content") or []:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(str(item.get("text", "")))
            elif isinstance(item, dict):
                parts.append(f"[{item.get('type', 'binary')} result, not shown]")
        if not parts and result.get("structuredContent") is not None:
            parts.append(json.dumps(result["structuredContent"], ensure_ascii=False))
        text = "\n".join(parts)
        if result.get("isError") is True:
            return "error", f"error: {text}" if text else "error: the tool failed"
        return "ok", text


def tool_name(server: str, tool: str) -> str:
    return (server + SEPARATOR + _TOOL_CHARS.sub("_", tool))[:MAX_NAME]


def is_external(name: str) -> bool:
    return SEPARATOR in name


def _schema(raw) -> dict:
    """A foreign input schema as the agent offers it: an object schema
    whose properties map names to schemas, within MAX_SCHEMA_BYTES."""
    empty = {"type": "object", "properties": {}}
    if not isinstance(raw, dict) or raw.get("type") != "object":
        return empty
    try:
        size = len(json.dumps(raw))
    except (TypeError, ValueError):
        return empty
    if size > MAX_SCHEMA_BYTES:
        return empty
    out = dict(raw)
    props = raw.get("properties")
    out["properties"] = (
        {k: v for k, v in props.items() if isinstance(k, str) and isinstance(v, dict)}
        if isinstance(props, dict)
        else {}
    )
    required = raw.get("required")
    if isinstance(required, list) and all(isinstance(r, str) for r in required):
        out["required"] = [r for r in required if r in out["properties"]]
    else:
        out.pop("required", None)
    return out


def _env_file(config: McpServerConfig, secrets: dict, proxy_port: int | None) -> bytes:
    """The ``NAME=value`` lines podman reads from the pipe."""
    values = dict(config.env)
    values.update(secrets)
    if proxy_port is not None:
        proxy = f"http://127.0.0.1:{proxy_port}"
        for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
            values[name] = proxy
        values["NO_PROXY"] = values["no_proxy"] = ""
    lines = []
    for name, value in values.items():
        if not _ENV_NAME.match(str(name)):
            raise McpClientError(f"{name!r} is not an environment variable name")
        if not isinstance(value, str) or any(c in value for c in "\n\r\x00"):
            raise McpClientError(f"the value of {name} must be a single line")
        lines.append(f"{name}={value}\n")
    data = "".join(lines).encode("utf-8")
    if len(data) > MAX_ENV_FILE:
        raise McpClientError(f"the environment is larger than {MAX_ENV_FILE} bytes")
    return data


def _start_container(config: McpServerConfig, secrets: dict) -> _Stdio:
    """Start a container server: fill in the tokens, hand the environment
    over on a pipe, remember the container's name for a cleanup."""
    if os.name != "posix":
        raise McpClientError("container servers need Linux or macOS (an inherited pipe)")
    argv = list(config.command)
    needs_proxy = any(TOKEN_EGRESS in a for a in argv)
    port = None
    if needs_proxy:
        if not config.egress:
            raise McpClientError("its network is an allowlist, but no allowed host is set")
        from core.mcp_egress import shared_proxy

        port = shared_proxy(config.egress).port
    data = _env_file(config, secrets, port)
    run_id = os.urandom(6).hex()
    read_end, write_end = os.pipe()
    try:
        os.write(write_end, data)
    finally:
        os.close(write_end)
    try:
        filled = [a.replace(TOKEN_ENV_FD, str(read_end)).replace(TOKEN_RUN, run_id)
                  .replace(TOKEN_EGRESS, str(port or "")) for a in argv]
        name = next((a.split("=", 1)[1] for a in filled if a.startswith("--name=")), "")
        program = filled[0] if filled else "podman"

        def cleanup() -> None:
            if name:
                subprocess.run([program, "rm", "-f", "-t", "0", name], capture_output=True,
                               timeout=60, env=_named_env(_BASE_ENV + _PODMAN_ENV))

        return _Stdio(filled, {}, config.timeout, pass_fds=(read_end,), cleanup=cleanup,
                      base=_BASE_ENV + _PODMAN_ENV)
    finally:
        os.close(read_end)  # the child has its own copy


class McpClient:
    """One connected server."""

    def __init__(self, config: McpServerConfig, *, token: str = "",
                 wrap: Callable[[list[str]], list[str]] | None = None,
                 secrets: dict | None = None) -> None:
        """*wrap* turns a stdio argv into the sandboxed one; *secrets* are the
        values of ``secret_env`` (default: the keyring's)."""
        self.config = config
        self._lock = threading.Lock()
        self._next = 0
        if config.transport == "stdio":
            refused = config.containment_problems()
            if refused:
                raise McpClientError("; ".join(refused))
            values = secrets_of(config) if secrets is None else {
                k: v for k, v in secrets.items() if k in config.secret_env and v}
            if config.container:
                self._transport = _start_container(config, values)
            else:
                argv = list(config.command)
                self._transport = _Stdio(wrap(argv) if wrap else argv,
                                         {**config.env, **values}, config.timeout)
        else:
            self._transport = _Http(config.url, token, config.timeout)
        try:
            self.server_info = self._initialize()
        except Exception:
            self.close()
            raise

    def _call(self, method: str, params: dict) -> dict:
        with self._lock:
            self._next += 1
            ident = self._next
        reply = self._transport.request(ident, {"jsonrpc": "2.0", "id": ident, "method": method,
                                                "params": params})
        if "error" in reply:
            error = reply["error"] if isinstance(reply["error"], dict) else {}
            raise McpClientError(str(error.get("message") or "the server refused")[:500])
        result = reply.get("result")
        if not isinstance(result, dict):
            raise McpClientError("the server's answer has no result")
        return result

    def _initialize(self) -> dict:
        from axross._version import __version__

        result = self._call(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "axross", "version": __version__},
            },
        )
        version = result.get("protocolVersion")
        if isinstance(version, str) and isinstance(self._transport, _Http):
            self._transport.set_version(version)
        self._transport.notify({"jsonrpc": "2.0", "method": "notifications/initialized"})
        info = result.get("serverInfo")
        return info if isinstance(info, dict) else {}

    def tools(self) -> list[ExternalTool]:
        out: list[ExternalTool] = []
        safe = self.config.files_safe()
        cursor = None
        seen: set = set()
        for _page in range(20):
            result = self._call("tools/list", {"cursor": cursor} if cursor else {})
            for raw in result.get("tools") or []:
                if len(out) >= MAX_TOOLS:
                    break
                if (
                    not isinstance(raw, dict)
                    or not isinstance(raw.get("name"), str)
                    or not raw["name"]
                ):
                    continue
                name = tool_name(self.config.name, raw["name"])
                if name in seen:
                    continue
                seen.add(name)
                annotations = (
                    raw.get("annotations") if isinstance(raw.get("annotations"), dict) else {}
                )
                read_only = annotations.get("readOnlyHint") is True
                always = self.config.confirm == "always"
                description = str(raw.get("description") or "")[:MAX_DESCRIPTION]
                out.append(ExternalTool(
                    name=name,
                    description=f"[{self.config.name}] {description}".strip(),
                    schema=_schema(raw.get("inputSchema")),
                    write=always or not read_only,
                    client=self,
                    remote_name=raw["name"],
                    always_ask=always,
                    files_safe=safe,
                ))
            cursor = result.get("nextCursor")
            if not isinstance(cursor, str) or not cursor or len(out) >= MAX_TOOLS:
                break
        return out

    def call_tool(self, name: str, args: dict) -> dict:
        return self._call("tools/call", {"name": name, "arguments": args})

    def close(self) -> None:
        try:
            self._transport.close()
        except Exception:  # noqa: BLE001 - closing is best effort
            log.debug("mcp client: closing %s failed", self.config.name, exc_info=True)


def _credentials_digest(token: str, secrets: dict) -> str:
    """What a client was connected with, as a digest (the pool keeps no
    secret text of its own)."""
    text = json.dumps([token, sorted(secrets.items())])
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class McpClientPool:
    """The connected servers of the GUI, shared by every Agent tab:
    connected on first use, reconnected when their config changes - or the
    token or secret values (keyring) they would connect with now."""

    def __init__(self, *, token_lookup: Callable[[str], str] | None = None,
                 wrap_for: Callable[[McpServerConfig], Callable | None] | None = None) -> None:
        self._token_lookup = token_lookup or get_token
        self._wrap_for = wrap_for or (lambda config: None)
        self._lock = threading.Lock()
        self._clients: dict[str, tuple[tuple, McpClient, list]] = {}
        self._always: set = set()

    def tools(self, configs, *, wrap_for=None) -> tuple[list[ExternalTool], list[str]]:
        """The tools of *configs* (connecting what is not yet) and one
        error line per server that failed. *wrap_for* replaces the pool's
        own for this call."""
        tools: list[ExternalTool] = []
        errors: list[str] = []
        for config in configs:
            try:
                tools.extend(self._tools_of(config, wrap_for or self._wrap_for))
            except McpClientError as exc:
                errors.append(f"{config.name}: {exc}")
        return tools, errors

    def _tools_of(self, config: McpServerConfig, wrap_for) -> list[ExternalTool]:
        # The token and the secret values live in the keyring, not in the
        # signature: a client connected with other ones is connected again.
        token = self._token_lookup(config.name) if config.bearer else ""
        secrets = secrets_of(config) if config.transport == "stdio" else {}
        digest = _credentials_digest(token, secrets)
        with self._lock:
            held = self._clients.get(config.name)
            if held is not None and held[0] == config.signature() and held[3] == digest:
                return list(held[2])
        if held is not None:
            self.drop(config.name)
        client = McpClient(config, token=token, wrap=wrap_for(config), secrets=secrets)
        try:
            found = client.tools()
        except Exception:
            client.close()
            raise
        with self._lock:
            old = self._clients.get(config.name)
            self._clients[config.name] = (config.signature(), client, found, digest)
            self._always |= {t.name for t in found if t.always_ask}
        if old is not None:
            old[1].close()
        return list(found)

    def always_ask(self, name: str) -> bool:
        with self._lock:
            return name in self._always

    def drop(self, name: str) -> None:
        with self._lock:
            held = self._clients.pop(name, None)
            if held is not None:
                self._always -= {t.name for t in held[2]}
        if held is not None:
            held[1].close()

    def keep_only(self, configs) -> None:
        """Close what is no longer configured as it is."""
        wanted = {c.name: c.signature() for c in configs}
        with self._lock:
            stale = [n for n, held in self._clients.items() if wanted.get(n) != held[0]]
        for name in stale:
            self.drop(name)

    def close_all(self) -> None:
        with self._lock:
            names = list(self._clients)
        for name in names:
            self.drop(name)
